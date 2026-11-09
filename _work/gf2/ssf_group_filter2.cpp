// SSF_GroupFilter2.dll - L4D2 Steam-group-server list insert filter (diagnostic + filter modes)
// Installs a 9-byte detour over the FoundGames/FoundGroupGames/FoundPublicGames insert virtual at
// gameui.dll RVA 0x49070, but only after strict identity checks (file SHA-256, PE timestamp, size,
// prologue bytes, FoundGroupGames RTTI/vtable). Diagnostic mode is pure pass-through + logging;
// filter mode drops insertion of rows whose display name matches a config regex, ONLY for the
// FoundGroupGames panel object (self->vtable == FoundGroupGames vtable); all other classes pass
// through untouched. The hook calls no game code and allocates nothing on the hot path.
// Rollback: set Stop event (restores original bytes) or simply restart the game.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sddl.h>
#include "safe_regex.h"

static const DWORD_PTR EXPECTED_TARGET_RVA = 0x00049070;
static const BYTE      EXPECTED_PROLOGUE[9] = {0x55,0x8B,0xEC,0x81,0xEC,0x84,0x01,0x00,0x00};
static const int       PROLOGUE_LEN = 9;
static const DWORD_PTR PANEL_VTABLE_RVA = 0x00170A14;
static const DWORD_PTR PANEL_COL_RVA    = 0x001F0EBC;
static const DWORD_PTR INSERT_SLOT_OFF  = 0x00000480;
// IPC objects are named after a per-session random token written into the ini by
// the managed host. Without a valid token this DLL refuses to install the hook,
// so another process in the same session cannot forge stop/reload/passthrough.
static const wchar_t*  EVENT_PREFIX   = L"Local\\SSF_GroupFilter2_";
static const wchar_t*  EV_KIND_PASS   = L"PassThrough";
static const wchar_t*  EV_KIND_RELOAD = L"Reload";
static const wchar_t*  EV_KIND_STOP   = L"Stop";
static const int       SESSION_TOKEN_LEN = 32;

static HMODULE g_hSelf = NULL;
static BYTE*   g_base = NULL;
static BYTE*   g_target = NULL;
static BYTE*   g_tramp = NULL;
static void*   g_panelVt = NULL;
static volatile LONG g_ready = 0;
static volatile LONG g_modeFilter = 0;
static volatile LONG g_stopRequested = 0;
static volatile LONG g_callsTotal = 0;
static volatile LONG g_callsGroup = 0;
static volatile LONG g_skipped = 0;
static volatile LONG g_passthrough = 0;
static volatile LONG g_otherVtLogged = 0;
static volatile LONG g_burstCount = 0;
static volatile LONG g_lastTick = 0;
static int g_maxLog = 2000;
static int g_logLines = 0;
static CRITICAL_SECTION g_cs;
static bool g_csInit = false;
static FILE* g_log = NULL;
static HANDLE g_evPass = NULL, g_evReload = NULL, g_evStop = NULL;
static wchar_t g_evPassName[160] = {0}, g_evReloadName[160] = {0}, g_evStopName[160] = {0};
static char g_sessionToken[SESSION_TOKEN_LEN + 1] = {0};
static SECURITY_ATTRIBUTES g_saShared;
static PSECURITY_DESCRIPTOR g_sdShared = NULL;
static HANDLE g_hWatch = NULL;
static wchar_t g_logPath[MAX_PATH] = {0};
static wchar_t g_statusPath[MAX_PATH] = {0};
static wchar_t g_iniPath[MAX_PATH] = {0};
static char g_gameuiPathA[MAX_PATH * 2] = {0};
static BYTE g_origBytes[PROLOGUE_LEN];
static DWORD g_gameuiSize = 0;
static DWORD g_gameuiTimeStamp = 0;
static bool g_hashOk = false, g_peOk = false, g_prologueOk = false, g_vtableOk = false;
static bool g_hookInstalled = false;
static char g_expectedSha[65] = "321EC9B5865582330AF61E81EB347DA31CC213CC6C95B80D6D98170B8A5FBB40";
static DWORD g_expectedTimestamp = 0x6A440E8A;
static DWORD g_expectedSize = 2325296;
static CRITICAL_SECTION g_progCs;
static bool g_progCsInit = false;
static ssfsafe::Program* g_prog = NULL;
static bool g_reOk = false;
static char g_regexText[4096] = {0};

// ---------------------------------------------------------------- duplicate-name filter
// The game inserts one call per server row; a single refresh can contain many
// servers that share the exact same display name. Dedupe keeps the first name
// in each refresh burst and drops later rows with the same name. The table is
// a fixed-size open-addressing hash set (no allocation on the UI thread); the
// epoch counter makes a reset O(1). The burst is delimited by the same
// 1.5-second idle gap the diagnostic refresh marker uses.
static const int DEDUPE_SLOT_COUNT = 8192;   // power of two
static const int DEDUPE_NAME_MAX = 64;       // same size as the game's char[64] name
struct DedupeEntry {
    DWORD epoch;
    DWORD hash;
    char name[DEDUPE_NAME_MAX];
};
static DedupeEntry g_dedupeSlots[DEDUPE_SLOT_COUNT];
static DWORD g_dedupeEpoch = 1;
static CRITICAL_SECTION g_dedupeCs;
static bool g_dedupeCsInit = false;
static volatile LONG g_dedupeEnabled = 0;
static volatile LONG g_dedupeSkipped = 0;
static volatile LONG g_dedupeTableFullLogged = 0;

// The game can rebuild the same list several times in one burst (same first
// two inserts in the same order). It clears the visible list between those
// passes, so keeping one global seen-set for the whole burst would skip every
// row of the second/third pass and leave the page empty. Track the first two
// raw names of the current pass; when that exact two-name prefix repeats, the
// table is cleared and the new pass starts fresh. One lost first row is safe:
// the same name normally appears again in the pass and is then kept.
static char g_passFirst[DEDUPE_NAME_MAX], g_passSecond[DEDUPE_NAME_MAX];
static int g_passFirstLen = 0, g_passSecondLen = 0;
static int g_passCalls = 0;
static int g_passLength = 0;       // calls in the last completed pass, 0 until known
static bool g_passLastWasFirst = false;

static void Log(const char* fmt, ...);   // defined below; dedupe logs a table-full warning

static DWORD DedupeHash(const char* s, int len)
{
    DWORD h = 2166136261u;                  // FNV-1a
    for (int i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 16777619u;
    }
    return h;
}
static void DedupeTableClearLocked()
{
    g_dedupeEpoch++;
    if (g_dedupeEpoch == 0) {
        memset(g_dedupeSlots, 0, sizeof(g_dedupeSlots));
        g_dedupeEpoch = 1;
    }
    InterlockedExchange(&g_dedupeTableFullLogged, 0);
}
static void DedupePassClearLocked()
{
    g_passFirstLen = g_passSecondLen = 0;
    g_passCalls = 0;
    g_passLength = 0;
    g_passLastWasFirst = false;
}
static void DedupeReset()
{
    if (!g_dedupeCsInit) return;
    EnterCriticalSection(&g_dedupeCs);
    DedupeTableClearLocked();
    DedupePassClearLocked();
    LeaveCriticalSection(&g_dedupeCs);
}
// The same physical server can be advertised with a trailing " #123" suffix
// (and some names carry an invisible UTF-8 BOM). Dedupe compares a normalized
// key: skip a leading BOM and ignore a trailing "#<digits>" (spaces allowed).
// The displayed/raw name is never modified; only the table key is normalized.
static int DedupeKeyStart(const char* name, int len)
{
    if (len >= 3 && (unsigned char)name[0] == 0xEF &&
        (unsigned char)name[1] == 0xBB && (unsigned char)name[2] == 0xBF) return 3;
    return 0;
}
static int DedupeKeyEnd(const char* name, int start, int len)
{
    int e = len;
    while (e > start && (name[e - 1] == ' ' || name[e - 1] == '\t')) e--;
    const int digitsEnd = e;
    while (e > start && name[e - 1] >= '0' && name[e - 1] <= '9') e--;
    if (e == digitsEnd) return len;                 // no numeric suffix
    while (e > start && (name[e - 1] == ' ' || name[e - 1] == '\t')) e--;
    if (e <= start || name[e - 1] != '#') return len;
    int base = e - 1;
    while (base > start && (name[base - 1] == ' ' || name[base - 1] == '\t')) base--;
    if (base <= start) return len;                  // "#123" alone is not a suffix
    return base;
}

// Returns true when this normalized name was already seen in the current burst.
// Empty names are never treated as duplicates (many servers have no name).
static bool DedupeSeen(const char* name, int len)
{
    if (!g_dedupeCsInit || !name || len <= 0) return false;
    if (len >= DEDUPE_NAME_MAX) len = DEDUPE_NAME_MAX - 1;
    const int start = DedupeKeyStart(name, len);
    const int end = DedupeKeyEnd(name, start, len);
    const int n = end - start;
    if (n <= 0) return false;
    const char* key = name + start;
    const DWORD h = DedupeHash(key, n);
    EnterCriticalSection(&g_dedupeCs);

    // The game sometimes rebuilds the same list several times in one burst and
    // clears the displayed rows before each pass. Detect the next pass from the
    // known length when possible (this keeps the first row too), with the
    // same-first-two-names rule as a fallback for the first repeat or a changed
    // pass length. Either way the table is cleared before the new pass is judged.
    if (g_passLength > 0 && g_passCalls == g_passLength &&
        g_passFirstLen == len && memcmp(name, g_passFirst, (size_t)len) == 0) {
        DedupeTableClearLocked();
        memcpy(g_passFirst, name, (size_t)len);
        g_passFirst[len] = 0;
        g_passFirstLen = len;
        g_passSecondLen = 0;
        g_passCalls = 1;
        g_passLastWasFirst = true;
    } else if (g_passCalls > 1 && g_passLastWasFirst &&
               g_passSecondLen == len && memcmp(name, g_passSecond, (size_t)len) == 0) {
        g_passLength = g_passCalls - 1;
        DedupeTableClearLocked();
        g_passCalls = 2;
        g_passLastWasFirst = false;
    } else {
        if (g_passCalls == 0) {
            memcpy(g_passFirst, name, (size_t)len);
            g_passFirst[len] = 0;
            g_passFirstLen = len;
        } else if (g_passCalls == 1) {
            memcpy(g_passSecond, name, (size_t)len);
            g_passSecond[len] = 0;
            g_passSecondLen = len;
        }
        g_passCalls++;
        g_passLastWasFirst = (g_passFirstLen == len && memcmp(name, g_passFirst, (size_t)len) == 0);
    }

    const DWORD epoch = g_dedupeEpoch;
    int idx = (int)(h & (DEDUPE_SLOT_COUNT - 1));
    for (int probe = 0; probe < DEDUPE_SLOT_COUNT; probe++) {
        DedupeEntry* e = &g_dedupeSlots[idx];
        if (e->epoch != epoch) {
            e->epoch = epoch;
            e->hash = h;
            memset(e->name, 0, DEDUPE_NAME_MAX);
            memcpy(e->name, key, (size_t)n);
            LeaveCriticalSection(&g_dedupeCs);
            return false;
        }
        if (e->hash == h && e->name[n] == 0 && memcmp(e->name, key, (size_t)n) == 0) {
            LeaveCriticalSection(&g_dedupeCs);
            return true;
        }
        idx = (idx + 1) & (DEDUPE_SLOT_COUNT - 1);
    }
    LeaveCriticalSection(&g_dedupeCs);
    if (InterlockedIncrement(&g_dedupeTableFullLogged) <= 3)
        Log("dedupe: table full (%d names), failing open for this burst", DEDUPE_SLOT_COUNT);
    return false;
}

// The compiled pattern is only ever touched through these helpers. Compiling
// happens on the reload/start thread; the game UI thread only holds the
// critical section for the duration of one bounded NFA match. Reload swaps
// the program under the lock and frees the old program after leaving it.
static bool RegexMatchName(const char* name, int nameLen)
{
    bool match = false;
    if (!g_progCsInit) return false;
    EnterCriticalSection(&g_progCs);
    if (g_prog) match = ssfsafe::Match(g_prog, (const unsigned char*)name, nameLen);
    LeaveCriticalSection(&g_progCs);
    return match;
}
static void CopyRegexText(char* out, int outCch)
{
    if (!out || outCch <= 0) return;
    out[0] = 0;
    if (!g_progCsInit) return;
    EnterCriticalSection(&g_progCs);
    lstrcpynA(out, g_regexText, outCch);
    LeaveCriticalSection(&g_progCs);
}
static int RegexStateCount()
{
    int n = 0;
    if (!g_progCsInit) return 0;
    EnterCriticalSection(&g_progCs);
    if (g_prog) n = g_prog->count;
    LeaveCriticalSection(&g_progCs);
    return n;
}

static void W2A(const wchar_t* w, char* a, int aSize)
{
    if (!w || !a || aSize <= 0) return;
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, a, aSize - 1, NULL, NULL);
    if (n <= 0) a[0] = 0; else a[aSize - 1] = 0;
}

// Shared DACL for the signal events and the status file: only SYSTEM,
// Administrators and the object owner get full access. The managed host runs
// elevated, the game usually runs as the same interactive user, so this is the
// narrowest descriptor both sides can rely on.
static void InitSecurity()
{
    if (g_sdShared) return;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)",
            SDDL_REVISION_1, &g_sdShared, NULL)) {
        g_saShared.nLength = sizeof(g_saShared);
        g_saShared.lpSecurityDescriptor = g_sdShared;
        g_saShared.bInheritHandle = FALSE;
    }
}
static SECURITY_ATTRIBUTES* SharedSa()
{
    return g_sdShared ? &g_saShared : NULL;
}
static bool TokenValid()
{
    if (strlen(g_sessionToken) != (size_t)SESSION_TOKEN_LEN) return false;
    for (int i = 0; i < SESSION_TOKEN_LEN; i++) {
        char c = g_sessionToken[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}
static void BuildEventNames()
{
    g_evPassName[0] = g_evReloadName[0] = g_evStopName[0] = 0;
    if (!TokenValid()) return;
    wchar_t tok[64] = {0};
    MultiByteToWideChar(CP_ACP, 0, g_sessionToken, -1, tok, 64);
    wsprintfW(g_evPassName, L"%s%s_%s", EVENT_PREFIX, tok, EV_KIND_PASS);
    wsprintfW(g_evReloadName, L"%s%s_%s", EVENT_PREFIX, tok, EV_KIND_RELOAD);
    wsprintfW(g_evStopName, L"%s%s_%s", EVENT_PREFIX, tok, EV_KIND_STOP);
}

static void LogV(const char* fmt, va_list ap, bool capped)
{
    if (!g_csInit) return;
    EnterCriticalSection(&g_cs);
    if (g_log && (!capped || g_logLines < g_maxLog))
    {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(g_log, "%02u:%02u:%02u.%03u ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        vfprintf(g_log, fmt, ap);
        fputc('\n', g_log);
        fflush(g_log);
        g_logLines++;
    }
    LeaveCriticalSection(&g_cs);
}
static void Log(const char* fmt, ...) { va_list ap; va_start(ap, fmt); LogV(fmt, ap, false); va_end(ap); }
static void LogCapped(const char* fmt, ...) { va_list ap; va_start(ap, fmt); LogV(fmt, ap, true); va_end(ap); }

static void WriteStatus(const char* result, const char* err)
{
    char body[8192];
    char regexText[4096];
    CopyRegexText(regexText, sizeof(regexText));
    int n = _snprintf(body, sizeof(body),
        "RESULT=%s\r\nERROR=%s\r\nPID=%lu\r\nMODE=%s\r\nTOKEN=%s\r\n"
        "GAMEUI_BASE=0x%08lX\r\nGAMEUI_SIZE=%lu\r\nGAMEUI_TIMESTAMP=0x%08lX\r\nGAMEUI_PATH=%s\r\n"
        "SHA256_OK=%d\r\nPE_OK=%d\r\nPROLOGUE_OK=%d\r\nVTABLE_OK=%d\r\nHOOK=%s\r\n"
        "TARGET_ADDR=0x%08lX\r\nTRAMPOLINE=0x%08lX\r\nHOOK_PATCH_RVA=0x%08lX\r\n"
        "REGEX_OK=%d\r\nREGEX_ENGINE=safe-nfa-1\r\nREGEX_STATES=%d\r\nREGEX=%s\r\n"
        "DEDUPE=%d\r\nDEDUPE_SKIPPED=%ld\r\n",
        result ? result : "UNKNOWN", err ? err : "",
        (unsigned long)GetCurrentProcessId(), g_modeFilter ? "filter" : "diag",
        TokenValid() ? g_sessionToken : "",
        (unsigned long)(DWORD_PTR)g_base, (unsigned long)g_gameuiSize,
        (unsigned long)g_gameuiTimeStamp, g_gameuiPathA,
        g_hashOk ? 1 : 0, g_peOk ? 1 : 0, g_prologueOk ? 1 : 0, g_vtableOk ? 1 : 0,
        g_hookInstalled ? "installed" : "not-installed",
        (unsigned long)(DWORD_PTR)g_target, (unsigned long)(DWORD_PTR)g_tramp,
        (unsigned long)(DWORD_PTR)(g_hookInstalled ? ((BYTE*)g_target - g_base) : 0),
        g_reOk ? 1 : 0, RegexStateCount(), regexText,
        g_dedupeEnabled ? 1 : 0, (long)g_dedupeSkipped);
    if (n < 0) body[0] = 0;
    // append log path (unicode) converted
    char logA[MAX_PATH * 2] = {0};
    W2A(g_logPath, logA, sizeof(logA));
    int len = (int)strlen(body);
    _snprintf(body + len, sizeof(body) - len, "LOG=%s\r\n", logA);

    // Publish atomically: readers never observe a half-written status file, and
    // the DACL keeps other same-session users from forging it.
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    wchar_t full[MAX_PATH * 2];
    wchar_t fullTmp[MAX_PATH * 2 + 8];
    wsprintfW(full, L"%sssf-gf2-%lu.status", tmp, (unsigned long)GetCurrentProcessId());
    wsprintfW(fullTmp, L"%s.tmp", full);
    InitSecurity();
    HANDLE h = CreateFileW(fullTmp, GENERIC_WRITE, 0, SharedSa(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!h) return;
    DWORD wr = 0;
    BOOL wrote = WriteFile(h, body, (DWORD)strlen(body), &wr, NULL);
    CloseHandle(h);
    if (!wrote || !MoveFileExW(fullTmp, full, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(fullTmp);
    }
}

static bool Sha256Hex(const wchar_t* path, char outHex[65])
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = false;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE* obj = NULL;
    BYTE digest[64];
    DWORD hashLen = 0, objLen = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0) == 0 &&
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) == 0 &&
        objLen > 0 && hashLen <= sizeof(digest))
    {
        obj = (BYTE*)malloc(objLen);
        if (obj && BCryptCreateHash(alg, &hash, obj, objLen, NULL, 0, 0) == 0)
        {
            BYTE* buf = (BYTE*)malloc(65536);
            if (buf) {
                DWORD got = 0; bool readOk = true;
                for (;;) {
                    if (!ReadFile(h, buf, 65536, &got, NULL)) { readOk = false; break; }
                    if (got == 0) break;
                    if (BCryptHashData(hash, buf, got, 0) != 0) { readOk = false; break; }
                }
                if (readOk && BCryptFinishHash(hash, digest, hashLen, 0) == 0) {
                    for (DWORD i = 0; i < hashLen; i++) sprintf(outHex + i * 2, "%02X", digest[i]);
                    outHex[hashLen * 2] = 0;
                    ok = true;
                }
                free(buf);
            }
        }
    }
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (obj) free(obj);
    CloseHandle(h);
    return ok;
}

static DWORD CfgIntW(const wchar_t* key, int def)
{
    wchar_t wdef[32], wout[64];
    wsprintfW(wdef, L"%d", def);
    GetPrivateProfileStringW(L"groupfilter", key, wdef, wout, 64, g_iniPath);
    return (DWORD)wcstol(wout, NULL, 0);
}
static void CfgStrA(const wchar_t* key, const char* def, char* out, DWORD outCch)
{
    // Large enough for a full MAX_PATTERN_BYTES (2048 byte) regex plus margin.
    wchar_t wout[8192];
    wchar_t wdef[512];
    if (!out || outCch == 0) return;
    out[0] = 0;
    MultiByteToWideChar(CP_ACP, 0, def, -1, wdef, 512);
    GetPrivateProfileStringW(L"groupfilter", key, wdef, wout, 8192, g_iniPath);
    int n = WideCharToMultiByte(CP_ACP, 0, wout, -1, out, outCch, NULL, NULL);
    if (n <= 0) out[0] = 0; else out[outCch - 1] = 0;
}
static DWORD CfgHexW(const wchar_t* key, DWORD def)
{
    wchar_t wdef[32], wout[64];
    wsprintfW(wdef, L"0x%lX", (unsigned long)def);
    GetPrivateProfileStringW(L"groupfilter", key, wdef, wout, 64, g_iniPath);
    return (DWORD)wcstoul(wout, NULL, 0);
}

static void InitConfig()
{
    g_modeFilter = (CfgIntW(L"filter", 0) != 0) ? 1 : 0;
    g_maxLog = (int)CfgIntW(L"max_log", 2000);
    if (g_maxLog < 10) g_maxLog = 10;
    if (g_maxLog > 200000) g_maxLog = 200000;

    // Duplicate-name filter: 1 = keep only the first row per exact display name
    // in each refresh burst. Missing key = off for old ini files; the managed
    // host always writes the key. A setting change starts a fresh table.
    LONG dedupe = (CfgIntW(L"dedupe_names", 0) != 0) ? 1 : 0;
    if (dedupe != g_dedupeEnabled) {
        g_dedupeEnabled = dedupe;
        DedupeReset();
    }

    // Session token: exactly 32 hex characters, written by the managed host.
    // Anything else clears the token so that SSF_Start fails closed instead of
    // falling back to predictable, forgeable object names.
    char tok[128] = "";
    CfgStrA(L"session_token", "", tok, sizeof(tok));
    if (strlen(tok) == (size_t)SESSION_TOKEN_LEN) lstrcpynA(g_sessionToken, tok, sizeof(g_sessionToken));
    else g_sessionToken[0] = 0;
    BuildEventNames();

    // Compile with the bounded NFA engine, never std::regex. A pattern that is
    // too long or uses rejected constructs is refused; the previous program
    // stays active on reload so a broken rules file cannot silently disable or
    // hang the filter.
    char reStr[4096] = "";
    CfgStrA(L"regex", "", reStr, sizeof(reStr));
    ssfsafe::Program* np = NULL;
    char perr[200] = "";
    if (reStr[0]) np = ssfsafe::Compile(reStr, perr, sizeof(perr));

    ssfsafe::Program* old = NULL;
    bool swapped = false;
    if (g_progCsInit) {
        EnterCriticalSection(&g_progCs);
        old = g_prog;
        if (!reStr[0]) {
            g_prog = NULL;
            g_reOk = false;
            swapped = true;
        } else if (np) {
            g_prog = np;
            g_reOk = true;
            swapped = true;
            np = NULL;
        } else if (!old) {
            g_prog = NULL;
            g_reOk = false;
            swapped = true;
        }
        if (swapped) lstrcpynA(g_regexText, reStr, sizeof(g_regexText));
        LeaveCriticalSection(&g_progCs);
    }
    if (old) ssfsafe::Free(old);
    if (np) ssfsafe::Free(np);
    if (perr[0] && g_csInit) Log("config: regex rejected by safe engine: %s", perr);
    if (reStr[0] && !g_reOk && g_csInit) Log("config: WARNING filter requested but regex is not active -> failing closed (no filtering)");

    char sha[80] = "";
    CfgStrA(L"expected_sha256", "", sha, sizeof(sha));
    if (sha[0]) lstrcpynA(g_expectedSha, sha, sizeof(g_expectedSha));
    g_expectedTimestamp = CfgHexW(L"expected_timestamp", g_expectedTimestamp);
    g_expectedSize = CfgHexW(L"expected_size", g_expectedSize);
}

static int EnumerateSuspendThreads(DWORD pid, HANDLE* out, int maxOut)
{
    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == GetCurrentThreadId()) continue;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (th) {
                // Never suspend a thread we cannot remember: a handle dropped on
                // the floor while suspended would freeze the game permanently.
                if (n >= maxOut) { CloseHandle(th); continue; }
                if (SuspendThread(th) == (DWORD)-1) CloseHandle(th);
                else out[n++] = th;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}
static void ResumeAll(HANDLE* hs, int n)
{
    for (int i = 0; i < n; i++) { ResumeThread(hs[i]); CloseHandle(hs[i]); }
}
static void FreeTramp()
{
    if (g_tramp) { VirtualFree(g_tramp, 0, MEM_RELEASE); g_tramp = NULL; }
}

extern "C" void HookNaked(void);

static bool InstallHook(char* err, DWORD errCch)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { sprintf(err, "bad dos magic"); return false; }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(g_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { sprintf(err, "bad nt signature"); return false; }
    if (memcmp(g_origBytes, EXPECTED_PROLOGUE, PROLOGUE_LEN) != 0) { sprintf(err, "prologue mismatch"); return false; }
    g_prologueOk = true;
    DWORD_PTR vt = (DWORD_PTR)g_panelVt;
    if (*(DWORD_PTR*)(vt + INSERT_SLOT_OFF) != (DWORD_PTR)g_target) {
        sprintf(err, "vtable[0x480]=0x%08lX expected 0x%08lX", (unsigned long)*(DWORD_PTR*)(vt + INSERT_SLOT_OFF), (unsigned long)(DWORD_PTR)g_target);
        return false;
    }
    if (*(DWORD_PTR*)(vt - 4) != (DWORD_PTR)(g_base + PANEL_COL_RVA)) {
        sprintf(err, "vtable[-1] COL mismatch"); return false;
    }
    g_vtableOk = true;

    g_tramp = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_tramp) { sprintf(err, "VirtualAlloc tramp failed %lu", GetLastError()); return false; }
    memcpy(g_tramp, g_target, PROLOGUE_LEN);
    BYTE* jb = g_tramp + PROLOGUE_LEN;
    jb[0] = 0xE9;
    *(INT32*)(jb + 1) = (INT32)((g_target + PROLOGUE_LEN) - (jb + 5));
    FlushInstructionCache(GetCurrentProcess(), g_tramp, 64);

    INT32 rel = (INT32)((BYTE*)&HookNaked - (g_target + 5));
    if (rel < -0x7FFF0000 || rel > 0x7FFF0000) { sprintf(err, "hook too far"); FreeTramp(); return false; }
    BYTE patch[PROLOGUE_LEN];
    patch[0] = 0xE9;
    *(INT32*)(patch + 1) = rel;
    for (int i = 5; i < PROLOGUE_LEN; i++) patch[i] = 0x90;

    HANDLE ths[1024]; int nths = EnumerateSuspendThreads(GetCurrentProcessId(), ths, 1024);
    DWORD old = 0;
    bool ok = false;
    if (VirtualProtect(g_target, PROLOGUE_LEN, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(g_target, patch, PROLOGUE_LEN);
        FlushInstructionCache(GetCurrentProcess(), g_target, PROLOGUE_LEN);
        DWORD tmp;
        VirtualProtect(g_target, PROLOGUE_LEN, old, &tmp);
        ok = true;
    } else {
        sprintf(err, "VirtualProtect failed %lu", GetLastError());
    }
    ResumeAll(ths, nths);
    if (!ok) { FreeTramp(); return false; }
    g_hookInstalled = true;
    return true;
}

static void UninstallHook()
{
    if (!g_hookInstalled) return;
    HANDLE ths[1024]; int nths = EnumerateSuspendThreads(GetCurrentProcessId(), ths, 1024);
    DWORD old = 0;
    if (VirtualProtect(g_target, PROLOGUE_LEN, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(g_target, g_origBytes, PROLOGUE_LEN);
        FlushInstructionCache(GetCurrentProcess(), g_target, PROLOGUE_LEN);
        DWORD tmp;
        VirtualProtect(g_target, PROLOGUE_LEN, old, &tmp);
        g_hookInstalled = false;
    }
    ResumeAll(ths, nths);
}

// Give already-running hook invocations time to return before the trampoline
// memory is released. Bounded: 2s max, returns early after 300ms of quiet.
static void WaitForCallsToSettle()
{
    LONG last = g_callsTotal;
    DWORD begin = GetTickCount();
    DWORD stableSince = begin;
    while (GetTickCount() - begin < 2000) {
        Sleep(50);
        LONG now = g_callsTotal;
        if (now != last) { last = now; stableSince = GetTickCount(); }
        else if (GetTickCount() - stableSince >= 300) break;
    }
}

// Full stop: restore the original bytes, wait for in-flight calls, release the
// trampoline and close every IPC/log handle. Critical sections are kept alive:
// a hook invocation may still be inside one when we get here, and deleting a
// critical section in use is undefined behaviour.
static void ReleaseHookResources()
{
    UninstallHook();
    WaitForCallsToSettle();
    FreeTramp();
    if (g_evPass) { CloseHandle(g_evPass); g_evPass = NULL; }
    if (g_evReload) { CloseHandle(g_evReload); g_evReload = NULL; }
    if (g_evStop) { CloseHandle(g_evStop); g_evStop = NULL; }
    if (g_log) { fclose(g_log); g_log = NULL; }
}

// ---------------------------------------------------------------- hook decision
static void SanitizeName(const char* raw, char* out, int outCch)
{
    int i = 0, o = 0;
    for (; i < 63 && o < outCch - 5; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (c == 0) break;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c >= 0x20 && c < 0x7F) out[o++] = (char)c;
        else { out[o++] = '\\'; out[o++] = 'x'; out[o++] = "0123456789ABCDEF"[c >> 4]; out[o++] = "0123456789ABCDEF"[c & 15]; }
    }
    out[o] = 0;
}

extern "C" int __cdecl DecideFilter(void* self, void* details, void* retAddr)
{
    if (!g_ready) return 1;
    if (!self || !details) return 1;
    InterlockedIncrement(&g_callsTotal);
    void* vt = *(void**)self;
    if (vt != g_panelVt) {
        LONG n = InterlockedIncrement(&g_otherVtLogged);
        if (n <= 20) LogCapped("PASS_OTHER self=0x%08lX vt=0x%08lX ret=0x%08lX n=%ld",
            (unsigned long)(DWORD_PTR)self, (unsigned long)(DWORD_PTR)vt, (unsigned long)(DWORD_PTR)retAddr, (long)n);
        return 1;
    }
    LONG gseq = InterlockedIncrement(&g_callsGroup);
    DWORD now = GetTickCount();
    LONG prevTick = (LONG)InterlockedExchange(&g_lastTick, (LONG)now);
    // One refresh burst inserts every row in a tight sequence. The same idle
    // gap that marks a new diagnostic burst also starts a fresh duplicate-name
    // table, so a later refresh is not mistaken for a duplicate of the old one.
    bool newBurst = (prevTick == 0) || ((DWORD)(now - (DWORD)prevTick) > 1500);
    if (newBurst) {
        if (prevTick != 0) {
            Log("---- REFRESH new burst; previous burst had %ld group insert calls, duplicate-name skips total %ld ----",
                (long)InterlockedExchange(&g_burstCount, 0), (long)g_dedupeSkipped);
        } else {
            InterlockedExchange(&g_burstCount, 0);
        }
        DedupeReset();
    }
    InterlockedIncrement(&g_burstCount);

    const DWORD* d = (const DWORD*)details;
    const char* rawName = (const char*)details + 4;
    int rawLen = 0;
    while (rawLen < 63 && rawName[rawLen]) rawLen++;
    char name[80];
    SanitizeName(rawName, name, sizeof(name));
    const BYTE* db = (const BYTE*)details;
    DWORD kv = d[0x54 / 4], idLo = d[0x58 / 4], idHi = d[0x5C / 4], ping = d[0x60 / 4], tail = d[0x64 / 4];
    bool passThrough = false;
    if (g_evPass && WaitForSingleObject(g_evPass, 0) == WAIT_OBJECT_0) {
        passThrough = true;
        InterlockedIncrement(&g_passthrough);
    }
    bool duplicate = false;
    if (g_dedupeEnabled && rawLen > 0) duplicate = DedupeSeen(rawName, rawLen);
    bool match = RegexMatchName(rawName, rawLen);
    if (g_modeFilter) {
        if (match || duplicate) {
            if (duplicate) InterlockedIncrement(&g_dedupeSkipped);
            InterlockedIncrement(&g_skipped);
            LogCapped("SKIP name=\"%s\" type=%lu id=%08lX%08lX ping=%lu reason=%s skipped_total=%ld%s",
                name, (unsigned long)d[0], (unsigned long)idHi, (unsigned long)idLo, (unsigned long)ping,
                duplicate ? (match ? "regex+dedupe" : "dedupe") : "regex",
                (long)g_skipped, passThrough ? " (passthrough-override)" : "");
            if (passThrough) return 1;
            return 0;
        }
        LogCapped("KEEP name=\"%s\" type=%lu ping=%lu", name, (unsigned long)d[0], (unsigned long)ping);
        return 1;
    }
    LogCapped("CALL seq=%ld self=0x%08lX ret=0x%08lX type=%lu name=\"%s\" flag44=%lu flag4C=%lu state50=%lu kv=0x%08lX id=%08lX%08lX ping=%lu tail=%lu match=%d dup=%d",
        (long)gseq, (unsigned long)(DWORD_PTR)self, (unsigned long)(DWORD_PTR)retAddr, (unsigned long)d[0],
        name, (unsigned long)db[0x44], (unsigned long)db[0x4C], (unsigned long)d[0x50 / 4],
        (unsigned long)kv, (unsigned long)idHi, (unsigned long)idLo, (unsigned long)ping,
        (unsigned long)tail, match ? 1 : 0, duplicate ? 1 : 0);
    return 1;
}

// ---------------------------------------------------------------- naked hook
extern "C" __declspec(naked) void HookNaked(void)
{
    __asm {
        pushad
        pushfd
        // cdecl DecideFilter(self, details, retAddr): push args right-to-left.
        // After pushad+pushfd: [esp+36]=retaddr, [esp+40]=details, [esp+28]=ECX(self).
        push dword ptr [esp+36]     // retAddr (still at +36 before any other push)
        push dword ptr [esp+44]     // details (shifted +4 by the push above)
        push ecx                    // self (thiscall ECX at entry)
        call DecideFilter
        add  esp, 12
        test eax, eax
        je   skip_insert
        popfd
        popad
        jmp  dword ptr [g_tramp]
    skip_insert:
        popfd
        popad
        xor  eax, eax
        ret  4
    }
}

// ---------------------------------------------------------------- worker
static DWORD WINAPI WatchThread(LPVOID)
{
    HANDLE h[2];
    h[0] = g_evStop;
    h[1] = g_evReload;
    for (;;) {
        DWORD w = WaitForMultipleObjects(2, h, FALSE, 1000);
        if (w == WAIT_OBJECT_0) {
            ResetEvent(g_evStop);
            Log("STOP event received: disabling filter and restoring original bytes");
            InterlockedExchange(&g_ready, 0);
            ReleaseHookResources();
            g_stopRequested = 1;
            WriteStatus("STOPPED", "");
            if (g_hWatch) { CloseHandle(g_hWatch); g_hWatch = NULL; }
            return 0;
        } else if (w == WAIT_OBJECT_0 + 1) {
            ResetEvent(g_evReload);
            char before[32]; strcpy(before, g_modeFilter ? "filter" : "diag");
            LONG oldMode = g_modeFilter;
            InitConfig();
            Log("RELOAD config: mode %s -> %s regex_ok=%d dedupe=%d max_log=%d regex_states=%d",
                before, g_modeFilter ? "filter" : "diag", g_reOk ? 1 : 0, g_dedupeEnabled ? 1 : 0,
                g_maxLog, RegexStateCount());
            if (oldMode != g_modeFilter) {
                WriteStatus(g_modeFilter ? "OK_FILTER" : "OK_DIAG", "");
            }
        }
    }
}

extern "C" __declspec(dllexport) DWORD WINAPI SSF_Start(LPVOID)
{
    if (InterlockedCompareExchange(&g_ready, 1, 1) == 1) {
        Log("SSF_Start called again while active; ignoring duplicate request");
        return 0;
    }
    // Re-injection after a clean stop re-enters this function, so create the
    // critical sections once and recreate the IPC objects the stop closed.
    if (!g_csInit) { InitializeCriticalSection(&g_cs); g_csInit = true; }
    if (!g_progCsInit) { InitializeCriticalSection(&g_progCs); g_progCsInit = true; }
    g_stopRequested = 0;
    g_hookInstalled = false;
    InitSecurity();

    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    wsprintfW(g_logPath, L"%sssf-gf2-%lu.log", tmp, (unsigned long)GetCurrentProcessId());

    // module dir + ini path
    wchar_t selfPath[MAX_PATH]; GetModuleFileNameW(g_hSelf, selfPath, MAX_PATH);
    wchar_t* slash = wcsrchr(selfPath, L'\\');
    if (slash) { *slash = 0; lstrcpynW(g_iniPath, selfPath, MAX_PATH); lstrcatW(g_iniPath, L"\\SSF_GroupFilter2.ini"); }

    char logA[MAX_PATH * 2] = {0}; W2A(g_logPath, logA, sizeof(logA));
    if (!g_log) { g_log = fopen(logA, "a"); g_logLines = 0; }
    Log("=== SSF_GroupFilter2 starting pid=%lu ===", (unsigned long)GetCurrentProcessId());
    Log("dll=%ls", selfPath);
    Log("ini=%ls", g_iniPath);
    InitConfig();
    Log("config: mode=%s regex_ok=%d dedupe=%d max_log=%d regex_engine=safe-nfa-1 regex_states=%d",
        g_modeFilter ? "filter" : "diag", g_reOk ? 1 : 0, g_dedupeEnabled ? 1 : 0, g_maxLog, RegexStateCount());
    if (g_modeFilter && !g_reOk) Log("config: WARNING filter requested but regex failed to compile -> failing closed (no filtering)");

    // Fail closed before touching any IPC object or game memory: without a
    // per-session token the signal names would be predictable, and the managed
    // host would reject our status anyway.
    if (!TokenValid()) {
        Log("FATAL missing/invalid session_token in ini; refusing to install the hook");
        WriteStatus("FAIL", "missing or invalid session_token in ini (refusing to install without a per-session token)");
        return 1;
    }
    Log("ipc: session token accepted (len=%d)", SESSION_TOKEN_LEN);

    if (g_evPass) { CloseHandle(g_evPass); g_evPass = NULL; }
    if (g_evReload) { CloseHandle(g_evReload); g_evReload = NULL; }
    if (g_evStop) { CloseHandle(g_evStop); g_evStop = NULL; }
    g_evPass = CreateEventW(SharedSa(), TRUE, FALSE, g_evPassName);
    g_evReload = CreateEventW(SharedSa(), TRUE, FALSE, g_evReloadName);
    g_evStop = CreateEventW(SharedSa(), TRUE, FALSE, g_evStopName);
    Log("events: pass=0x%lX reload=0x%lX stop=0x%lX", (unsigned long)(DWORD_PTR)g_evPass,
        (unsigned long)(DWORD_PTR)g_evReload, (unsigned long)(DWORD_PTR)g_evStop);
    if (!g_evPass || !g_evReload || !g_evStop) {
        Log("FATAL CreateEvent failed (%lu)", (unsigned long)GetLastError());
        WriteStatus("FAIL", "CreateEvent failed for token-bound IPC objects");
        return 1;
    }

    g_base = (BYTE*)GetModuleHandleW(L"gameui.dll");
    if (!g_base) { Log("FATAL gameui.dll not loaded"); WriteStatus("FAIL", "gameui.dll not loaded"); return 1; }
    HMODULE hGameui = (HMODULE)g_base;
    wchar_t gameuiPath[MAX_PATH] = {0};
    GetModuleFileNameW(hGameui, gameuiPath, MAX_PATH);
    W2A(gameuiPath, g_gameuiPathA, sizeof(g_gameuiPathA));
    g_target = g_base + EXPECTED_TARGET_RVA;
    g_panelVt = g_base + PANEL_VTABLE_RVA;
    memcpy(g_origBytes, g_target, PROLOGUE_LEN);
    Log("gameui base=0x%08lX target=0x%08lX panelVt=0x%08lX", (unsigned long)(DWORD_PTR)g_base,
        (unsigned long)(DWORD_PTR)g_target, (unsigned long)(DWORD_PTR)g_panelVt);
    Log("gameui path=%s", g_gameuiPathA);

    // PE identity
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(g_base + dos->e_lfanew);
    g_gameuiTimeStamp = nt->FileHeader.TimeDateStamp;
    g_gameuiSize = (DWORD)(((BYTE*)g_base) + nt->OptionalHeader.SizeOfImage - g_base);
    // actual file size via mapping? use module file size
    HANDLE hf = CreateFileW(gameuiPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) { LARGE_INTEGER li; if (GetFileSizeEx(hf, &li)) g_gameuiSize = (DWORD)li.QuadPart; CloseHandle(hf); }
    Log("gameui timestamp=0x%08lX size=%lu", (unsigned long)g_gameuiTimeStamp, (unsigned long)g_gameuiSize);
    g_peOk = (g_gameuiTimeStamp == g_expectedTimestamp && g_gameuiSize == g_expectedSize);
    char sha[128] = {0};
    bool hashComputed = Sha256Hex(gameuiPath, sha);
    g_hashOk = hashComputed && (_stricmp(sha, g_expectedSha) == 0);
    Log("sha256=%s expected=%s match=%d", hashComputed ? sha : "(failed)", g_expectedSha, g_hashOk ? 1 : 0);
    if (!g_peOk) { Log("FATAL PE timestamp/size mismatch"); WriteStatus("FAIL", "PE timestamp/size mismatch"); return 1; }
    if (!g_hashOk) { Log("FATAL sha256 mismatch"); WriteStatus("FAIL", "sha256 mismatch"); return 1; }

    char err[256] = {0};
    if (!InstallHook(err, sizeof(err))) {
        Log("FATAL hook install failed: %s", err);
        WriteStatus("FAIL", err);
        return 1;
    }
    InterlockedExchange(&g_ready, 1);
    DWORD tid = 0;
    g_hWatch = CreateThread(NULL, 0, WatchThread, NULL, 0, &tid);
    Log("hook installed at 0x%08lX trampoline=0x%08lX rva=0x%08lX watch_tid=%lu",
        (unsigned long)(DWORD_PTR)g_target, (unsigned long)(DWORD_PTR)g_tramp,
        (unsigned long)(DWORD_PTR)(g_target - g_base), (unsigned long)tid);
    Log("=== READY mode=%s ===", g_modeFilter ? "filter" : "diag");
    WriteStatus(g_modeFilter ? "OK_FILTER" : "OK_DIAG", "");
    return 0;
}

// ---------------------------------------------------------------- test exports
// Used by the managed host (GroupServerFilter.NativeValidate / SelfTest) and by
// offline tests. Both run the same bounded engine the hook uses, so a pattern
// accepted here is exactly a pattern the game thread can execute safely.
extern "C" __declspec(dllexport) int __cdecl SSF_ValidatePattern(const char* pattern, char* err, int errCch)
{
    char local[200] = {0};
    ssfsafe::Program* p = ssfsafe::Compile(
        pattern ? pattern : "",
        (err && errCch > 0) ? err : local,
        (err && errCch > 0) ? errCch : (int)sizeof(local));
    if (!p) return 0;
    ssfsafe::Free(p);
    return 1;
}

// Offline hooks for the managed self-test: the same fixed hash table the game
// thread uses. SSF_DedupeCheck returns 1 when the name is a duplicate in the
// current burst, 0 for a new name (or an empty name), -1 for a null pointer.
extern "C" __declspec(dllexport) void __cdecl SSF_DedupeReset(void)
{
    DedupeReset();
}

extern "C" __declspec(dllexport) int __cdecl SSF_DedupeCheck(const char* name)
{
    if (!name) return -1;
    int len = 0;
    while (len < 63 && name[len]) len++;
    if (len == 0) return 0;
    return DedupeSeen(name, len) ? 1 : 0;
}

extern "C" __declspec(dllexport) int __cdecl SSF_TestMatch(const char* pattern, const char* text)
{
    char err[200] = {0};
    ssfsafe::Program* p = ssfsafe::Compile(pattern ? pattern : "", err, sizeof(err));
    if (!p) return -1;
    int len = 0;
    if (text) { while (text[len] && len < 4096) len++; }
    bool m = false;
    if (g_progCsInit) {
        EnterCriticalSection(&g_progCs);
        m = ssfsafe::Match(p, (const unsigned char*)(text ? text : ""), len);
        LeaveCriticalSection(&g_progCs);
    } else {
        m = ssfsafe::Match(p, (const unsigned char*)(text ? text : ""), len);
    }
    ssfsafe::Free(p);
    return m ? 1 : 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hSelf = hModule;
        DisableThreadLibraryCalls(hModule);
        // The dedupe table is touched by the game UI thread, the reload thread
        // and the offline test exports; one small critical section serializes it.
        InitializeCriticalSection(&g_dedupeCs);
        g_dedupeCsInit = true;
    }
    return TRUE;
}
