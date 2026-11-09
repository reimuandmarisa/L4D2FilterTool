// ssf-group-injector.exe - strict, auditable injector for SSF_GroupFilter2.dll
// Usage:
//   ssf-group-injector.exe --ack [--pid N | --process left4dead2.exe] [--dll PATH]         inject
//   ssf-group-injector.exe --passthrough on|off [--dll PATH]                               toggle filter pass-through
//   ssf-group-injector.exe --reload [--dll PATH]                                           re-read ini (mode/regex)
//   ssf-group-injector.exe --stop [--dll PATH]                                             restore original gameui bytes
//   ssf-group-injector.exe --status                                                        print last status file
// Signal commands read the per-session token from <DLL dir>\SSF_GroupFilter2.ini.
// Guard rails: target must be left4dead2.exe under steamapps\common\left 4 dead 2; gameui.dll on
// disk must match the expected SHA-256 / PE timestamp / size before anything is injected.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* EXPECTED_SHA = "321EC9B5865582330AF61E81EB347DA31CC213CC6C95B80D6D98170B8A5FBB40";
static const DWORD EXPECTED_TIMESTAMP = 0x6A440E8A;
static const DWORD EXPECTED_SIZE = 2325296;
// Signal objects are bound to a per-session random token stored in the DLL ini;
// a process that cannot read the ini token cannot forge stop/reload/passthrough.
static const wchar_t* EVENT_PREFIX = L"Local\\SSF_GroupFilter2_";
static const wchar_t* EV_KIND_PASS = L"PassThrough";
static const wchar_t* EV_KIND_RELOAD = L"Reload";
static const wchar_t* EV_KIND_STOP = L"Stop";
static const int SESSION_TOKEN_LEN = 32;
static char g_token[SESSION_TOKEN_LEN + 1] = {0};

static void die(const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}
static void info(const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static bool Sha256HexW(const wchar_t* path, char outHex[65])
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = false;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE* obj = NULL; BYTE* buf = NULL;
    BYTE digest[64]; DWORD hashLen = 0, objLen = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0) == 0 &&
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) == 0 &&
        objLen > 0 && hashLen <= sizeof(digest))
    {
        obj = (BYTE*)malloc(objLen);
        buf = (BYTE*)malloc(65536);
        if (obj && buf && BCryptCreateHash(alg, &hash, obj, objLen, NULL, 0, 0) == 0) {
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
        }
    }
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    free(obj); free(buf);
    CloseHandle(h);
    return ok;
}

static DWORD FindPid(const wchar_t* exeName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool ProcessImagePath(DWORD pid, wchar_t* out, DWORD cch)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD n = cch;
    bool ok = QueryFullProcessImageNameW(h, 0, out, &n) != FALSE;
    CloseHandle(h);
    return ok;
}

static DWORD RvaToOff(PIMAGE_NT_HEADERS nt, DWORD rva)
{
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD vs = sec[i].VirtualAddress, sz = sec[i].SizeOfRawData;
        if (rva >= vs && rva < vs + sz) return sec[i].PointerToRawData + (rva - vs);
    }
    return 0;
}

static DWORD RvaOfExport(const BYTE* file, DWORD fileSize, const char* name)
{
    if (fileSize < 0x200) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!expRva) return 0;
    DWORD off = RvaToOff(nt, expRva);
    if (!off || off + expSize > fileSize) return 0;
    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(file + off);
    DWORD nameOff = RvaToOff(nt, ed->AddressOfNames);
    DWORD funcOff = RvaToOff(nt, ed->AddressOfFunctions);
    DWORD ordOff  = RvaToOff(nt, ed->AddressOfNameOrdinals);
    if (!nameOff || !funcOff || !ordOff) return 0;
    DWORD* names = (DWORD*)(file + nameOff);
    WORD* ords = (WORD*)(file + ordOff);
    DWORD* funcs = (DWORD*)(file + funcOff);
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        DWORD nOff = RvaToOff(nt, names[i]);
        if (!nOff) continue;
        const char* en = (const char*)(file + nOff);
        if (strcmp(en, name) == 0 || strncmp(en, "_", 1) == 0) {
            // MSVC emits "_SSF_Start@4" for extern "C" __stdcall; also accept a plain name
            size_t nl = strlen(name);
            const char* a = en + 1;
            if (strncmp(a, name, nl) != 0 || (a[nl] != '@' && a[nl] != 0)) continue;
        } else continue;
        {
            if (ords[i] < ed->NumberOfFunctions) return funcs[ords[i]];
        }
        }
    return 0;
}

static BYTE* ReadFileAll(const wchar_t* path, DWORD* outSize)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER li; GetFileSizeEx(h, &li);
    DWORD sz = (DWORD)li.QuadPart;
    BYTE* p = (BYTE*)malloc(sz);
    if (!p) { CloseHandle(h); return NULL; }
    DWORD got = 0;
    if (!ReadFile(h, p, sz, &got, NULL) || got != sz) { free(p); CloseHandle(h); return NULL; }
    CloseHandle(h);
    *outSize = sz;
    return p;
}

static bool VerifyGameuiIdentity(const wchar_t* gameuiPath)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(gameuiPath, GetFileExInfoStandard, &fad)) {
        info("GAMEUI_CHECK: cannot stat %ls", gameuiPath); return false;
    }
    DWORD size = fad.nFileSizeLow;
    HANDLE h = CreateFileW(gameuiPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { info("GAMEUI_CHECK: cannot open"); return false; }
    BYTE hdr[0x400] = {0}; DWORD got = 0;
    ReadFile(h, hdr, sizeof(hdr), &got, NULL);
    CloseHandle(h);
    DWORD ts = 0;
    if (got > 0x100) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdr;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(hdr + dos->e_lfanew);
        ts = nt->FileHeader.TimeDateStamp;
    }
    char sha[128] = {0};
    bool hashed = Sha256HexW(gameuiPath, sha);
    bool shaOk = hashed && _stricmp(sha, EXPECTED_SHA) == 0;
    info("GAMEUI_CHECK: path=%ls", gameuiPath);
    info("GAMEUI_CHECK: size=%lu (expected %lu) ts=0x%08lX (expected 0x%08lX) sha256=%s match=%s",
         (unsigned long)size, (unsigned long)EXPECTED_SIZE, (unsigned long)ts, (unsigned long)EXPECTED_TIMESTAMP,
         hashed ? sha : "(failed)", (shaOk && size == EXPECTED_SIZE && ts == EXPECTED_TIMESTAMP) ? "YES" : "NO");
    return shaOk && size == EXPECTED_SIZE && ts == EXPECTED_TIMESTAMP;
}

static void PrintStatusFile(DWORD pid, bool wait)
{
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    wchar_t path[MAX_PATH * 2];
    wsprintfW(path, L"%sssf-gf2-%lu.status", tmp, (unsigned long)pid);
    for (int i = 0; i < (wait ? 100 : 1); i++) {
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[8192]; DWORD got = 0;
            ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
            CloseHandle(h);
            buf[got] = 0;
            info("---- %ls ----", path);
            info("%s", buf);
            return;
        }
        Sleep(200);
    }
    info("(no status file yet at %ls)", path);
}

static void WaitFileStatus(DWORD pid, const char* expectKey, const char* expectVal, int timeoutMs)
{
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    wchar_t path[MAX_PATH * 2];
    wsprintfW(path, L"%sssf-gf2-%lu.status", tmp, (unsigned long)pid);
    for (int t = 0; t < timeoutMs; t += 100) {
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[8192]; DWORD got = 0;
            ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
            CloseHandle(h);
            buf[got] = 0;
            char key[128]; wsprintfA(key, "%s=%s", expectKey, expectVal);
            if (strstr(buf, key)) { return; }
        }
        Sleep(100);
    }
}

static bool TokenValid()
{
    if (strlen(g_token) != (size_t)SESSION_TOKEN_LEN) return false;
    for (int i = 0; i < SESSION_TOKEN_LEN; i++) {
        char c = g_token[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

// Locate <dir of --dll>\SSF_GroupFilter2.ini and read its session_token. Signal
// commands therefore require --dll (or --ini) instead of guessing a fixed name.
static bool LoadToken(const char* dllArg, const char* iniArg)
{
    wchar_t path[MAX_PATH * 2] = {0};
    if (iniArg && iniArg[0]) {
        MultiByteToWideChar(CP_ACP, 0, iniArg, -1, path, MAX_PATH * 2);
    } else if (dllArg && dllArg[0]) {
        wchar_t dllPath[MAX_PATH * 2] = {0};
        MultiByteToWideChar(CP_ACP, 0, dllArg, -1, dllPath, MAX_PATH * 2);
        wchar_t* slash = wcsrchr(dllPath, L'\\');
        if (!slash) slash = wcsrchr(dllPath, L'/');
        if (slash) *(slash + 1) = 0; else dllPath[0] = 0;
        if (dllPath[0]) {
            lstrcpynW(path, dllPath, MAX_PATH * 2);
            lstrcatW(path, L"SSF_GroupFilter2.ini");
        }
    }
    if (!path[0] || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return false;
    wchar_t wout[128] = {0};
    GetPrivateProfileStringW(L"groupfilter", L"session_token", L"", wout, 128, path);
    char tok[128] = {0};
    WideCharToMultiByte(CP_ACP, 0, wout, -1, tok, sizeof(tok), NULL, NULL);
    if (strlen(tok) != (size_t)SESSION_TOKEN_LEN) return false;
    lstrcpynA(g_token, tok, sizeof(g_token));
    return TokenValid();
}

static int CmdSignal(const wchar_t* kind, bool set)
{
    if (!TokenValid()) {
        info("FAIL: no valid session token loaded; pass --dll <path to SSF_GroupFilter2.dll> (or --ini) so the ini can be read.");
        return 2;
    }
    wchar_t tok[64] = {0};
    MultiByteToWideChar(CP_ACP, 0, g_token, -1, tok, 64);
    wchar_t evName[160] = {0};
    wsprintfW(evName, L"%s%s_%s", EVENT_PREFIX, tok, kind);
    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, evName);
    if (!h) { info("FAIL: event not found (is the DLL injected?): %ls", evName); return 2; }
    BOOL ok = set ? SetEvent(h) : ResetEvent(h);
    CloseHandle(h);
    info("EVENT %ls %s -> %s", evName, set ? "SET" : "RESET", ok ? "OK" : "FAIL");
    return ok ? 0 : 2;
}

int main(int argc, char** argv)
{
    const char* dllArg = NULL;
    const char* iniArg = NULL;
    const char* procArg = "left4dead2.exe";
    DWORD pidArg = 0;
    bool ack = false, doInject = false, doStop = false, doReload = false, doStatus = false, doVerify = false;
    int passMode = -1; // 0=off 1=on
    for (int i = 1; i < argc; i++) {
        if (!_stricmp(argv[i], "--ack") || !_stricmp(argv[i], "--i-acknowledge-local-menu-test")) ack = true;
        else if (!_stricmp(argv[i], "--inject")) doInject = true;
        else if (!_stricmp(argv[i], "--pid") && i + 1 < argc) pidArg = (DWORD)strtoul(argv[++i], NULL, 0);
        else if (!_stricmp(argv[i], "--process") && i + 1 < argc) procArg = argv[++i];
        else if (!_stricmp(argv[i], "--dll") && i + 1 < argc) dllArg = argv[++i];
        else if (!_stricmp(argv[i], "--ini") && i + 1 < argc) iniArg = argv[++i];

        else if (!_stricmp(argv[i], "--passthrough") && i + 1 < argc) passMode = (!_stricmp(argv[++i], "on") || !_stricmp(argv[i], "1")) ? 1 : 0;
        else if (!_stricmp(argv[i], "--stop")) doStop = true;
        else if (!_stricmp(argv[i], "--reload")) doReload = true;
        else if (!_stricmp(argv[i], "--status")) doStatus = true;
        else if (!_stricmp(argv[i], "--verify")) doVerify = true;
        else if (!_stricmp(argv[i], "--help") || !_stricmp(argv[i], "-h")) {
            info("usage: %s --ack [--pid N | --process name.exe] [--dll path] [--inject]\n"
                 "       %s --passthrough on|off | --reload | --stop | --status\n"
                 "       (signal commands also require --dll <SSF_GroupFilter2.dll> or --ini <ini> to locate the session token)",
                 argv[0], argv[0]);
            return 0;
        }
    }
    if (passMode >= 0) {
        if (!LoadToken(dllArg, iniArg)) return CmdSignal(NULL, true);
        return CmdSignal(EV_KIND_PASS, passMode == 1);
    }
    if (doReload) {
        if (!LoadToken(dllArg, iniArg)) return CmdSignal(NULL, true);
        int r = CmdSignal(EV_KIND_RELOAD, true); Sleep(300); CmdSignal(EV_KIND_RELOAD, false); return r;
    }
    if (doStop) {
        DWORD pid = pidArg ? pidArg : FindPid(L"left4dead2.exe");
        if (!pid) die("FAIL: left4dead2.exe not running");
        if (!LoadToken(dllArg, iniArg)) return CmdSignal(NULL, true);
        int r = CmdSignal(EV_KIND_STOP, true);
        if (r == 0) { WaitFileStatus(pid, "RESULT", "STOPPED", 5000); }
        return r;
    }
    if (doStatus) {
        DWORD pid = pidArg ? pidArg : FindPid(L"left4dead2.exe");
        if (!pid) die("FAIL: left4dead2.exe not running");
        PrintStatusFile(pid, false);
        return 0;
    }

    // inject path
    if (!ack && !doVerify) die("REFUSED: injection requires --ack (acknowledges local/menu-only test of your own game process).");
    DWORD pid = pidArg ? pidArg : FindPid(L"left4dead2.exe");
    if (!pid) die("FAIL: left4dead2.exe not running (use --pid / --process)");
    wchar_t img[MAX_PATH * 2] = {0};
    if (!ProcessImagePath(pid, img, MAX_PATH * 2)) die("FAIL: cannot query image path for pid %lu", (unsigned long)pid);
    info("TARGET: pid=%lu image=%ls", (unsigned long)pid, img);
    const wchar_t* baseName = wcsrchr(img, L'\\'); baseName = baseName ? baseName + 1 : img;
    if (_wcsicmp(baseName, L"left4dead2.exe") != 0) die("REFUSED: target image is not left4dead2.exe");
    wchar_t lower[MAX_PATH * 2]; lstrcpynW(lower, img, MAX_PATH * 2); CharLowerW(lower);
    if (!wcsstr(lower, L"steamapps\\common\\left 4 dead 2\\")) die("REFUSED: game is not under steamapps\\common\\left 4 dead 2");

    wchar_t gameDir[MAX_PATH * 2]; lstrcpynW(gameDir, img, MAX_PATH * 2);
    { wchar_t* s = wcsrchr(gameDir, L'\\'); if (!s) die("REFUSED: bad image path"); *s = 0; } // ...\Left 4 Dead 2
    wchar_t gameui[MAX_PATH * 2];
    wsprintfW(gameui, L"%ls\\bin\\gameui.dll", gameDir);
    if (!VerifyGameuiIdentity(gameui)) die("REFUSED: gameui.dll identity mismatch (unknown build) - fail closed");
    if (doVerify) {
        HANDLE hq = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hq) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me; me.dwSize = sizeof(me);
                if (Module32FirstW(snap, &me)) {
                    do {
                        if (_wcsicmp(me.szModule, L"gameui.dll") == 0) {
                            info("REMOTE_MODULE: gameui.dll base=0x%08lX size=0x%08lX path=%ls",
                                 (unsigned long)(DWORD_PTR)me.modBaseAddr, (unsigned long)me.modBaseSize, me.szExePath);
                        }
                    } while (Module32NextW(snap, &me));
                }
                CloseHandle(snap);
            }
            CloseHandle(hq);
        }
        info("VERIFY: all identity gates passed; no injection performed");
        return 0;
    }

    if (!dllArg) die("FAIL: --dll <path to SSF_GroupFilter2.dll> required");
    wchar_t dllPath[MAX_PATH * 2] = {0};
    wchar_t dllArgW[MAX_PATH * 2] = {0};
    MultiByteToWideChar(CP_ACP, 0, dllArg, -1, dllArgW, MAX_PATH * 2);
    GetFullPathNameW(dllArgW, MAX_PATH * 2, dllPath, NULL);
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) die("FAIL: dll not found: %ls", dllPath);
    DWORD fsz = 0; BYTE* fdata = ReadFileAll(dllPath, &fsz);
    if (!fdata) die("FAIL: cannot read dll");
    DWORD expRva = RvaOfExport(fdata, fsz, "SSF_Start");
    free(fdata);
    if (!expRva) die("FAIL: SSF_Start export not found in dll");

    info("DLL: %ls (SSF_Start RVA=0x%08lX)", dllPath, (unsigned long)expRva);
    HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                            PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid);
    if (!hp) die("FAIL: OpenProcess failed %lu", GetLastError());

    SIZE_T pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* remotePath = VirtualAllocEx(hp, NULL, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) die("FAIL: VirtualAllocEx failed %lu", GetLastError());
    if (!WriteProcessMemory(hp, remotePath, dllPath, pathBytes, NULL)) die("FAIL: WriteProcessMemory failed %lu", GetLastError());

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    info("REMOTE: LoadLibraryW=0x%08lX path buffer=0x%08lX", (unsigned long)(DWORD_PTR)pLoadLibraryW, (unsigned long)(DWORD_PTR)remotePath);
    HANDLE th = CreateRemoteThread(hp, NULL, 0, pLoadLibraryW, remotePath, 0, NULL);
    if (!th) die("FAIL: CreateRemoteThread(LoadLibraryW) failed %lu", GetLastError());
    DWORD wr = WaitForSingleObject(th, 20000);
    DWORD hRemoteDll = 0;
    GetExitCodeThread(th, &hRemoteDll);
    CloseHandle(th);
    if (wr != WAIT_OBJECT_0) die("FAIL: LoadLibraryW remote thread timeout");
    if (!hRemoteDll) die("FAIL: LoadLibraryW returned NULL in target (DllMain/loader failed)");
    info("REMOTE: module loaded at 0x%08lX", (unsigned long)hRemoteDll);

    // verify module is enumerated in target
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        bool found = false;
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me; me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do {
                    if ((DWORD_PTR)me.modBaseAddr == (DWORD_PTR)hRemoteDll) { found = true; break; }
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
        info("REMOTE: module enumerated=%s", found ? "YES" : "NO");
        if (!found) die("FAIL: injected module not enumerated in target");
    }

    LPTHREAD_START_ROUTINE pStart = (LPTHREAD_START_ROUTINE)((BYTE*)(DWORD_PTR)hRemoteDll + expRva);
    info("REMOTE: calling SSF_Start at 0x%08lX", (unsigned long)(DWORD_PTR)pStart);
    HANDLE th2 = CreateRemoteThread(hp, NULL, 0, pStart, NULL, 0, NULL);
    if (!th2) die("FAIL: CreateRemoteThread(SSF_Start) failed %lu", GetLastError());
    DWORD wr2 = WaitForSingleObject(th2, 60000);
    DWORD startRet = 0xFFFFFFFF;
    GetExitCodeThread(th2, &startRet);
    CloseHandle(th2);
    if (wr2 != WAIT_OBJECT_0) die("FAIL: SSF_Start timeout");
    info("REMOTE: SSF_Start returned %lu", (unsigned long)startRet);
    Sleep(200);
    PrintStatusFile(pid, true);
    VirtualFreeEx(hp, remotePath, 0, MEM_RELEASE);
    CloseHandle(hp);
    return startRet == 0 ? 0 : 2;
}
