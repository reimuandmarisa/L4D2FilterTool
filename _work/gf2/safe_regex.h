// safe_regex.h - bounded, backtracking-free regular expression engine.
// Used by SSF_GroupFilter2.dll so that the game UI thread never runs
// std::regex (which can backtrack exponentially). Byte oriented.
//
// Supported (ECMAScript subset, enough for the generated group-filter pattern):
//   ^  $  .  *  +  ?  {m}  {m,}  {m,n}  |  ( )  (?: )  [class]  [^class]
//   escapes: literal punctuation, \xHH, \n \r \t \f \v \0, \cX,
//            \d \D \w \W \s \S, \b \B (outside a class)
// Rejected on purpose: backreferences, lookaround, named/conditional groups,
// \p{...}, \A \Z \z \G \k \Q, and anything that enables unbounded work.
//
// Hard limits: pattern <= 2048 bytes, NFA <= 4096 states, quantifier <= 64.
// Matching is a Thompson/Pike NFA simulation: O(states * text length) time,
// no recursion while matching, no user-controlled loop counts.
//
// The Match() function uses process-wide scratch buffers; callers must
// serialize Match()/Compile() calls (the DLL uses a critical section).

#ifndef SSF_SAFE_REGEX_H
#define SSF_SAFE_REGEX_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

namespace ssfsafe {

enum {
    MAX_PATTERN_BYTES = 2048,
    MAX_STATES        = 4096,
    MAX_QUANT         = 64,
    MAX_DEPTH         = 32,
    MAX_NODES         = 8192,
    MAX_CLASSES       = 256
};

enum InstOp {
    I_CHAR = 1,
    I_ANY,
    I_CLASS,
    I_SPLIT,
    I_JMP,
    I_ASSERT,
    I_MATCH
};

enum AssertKind {
    A_BOL = 1,
    A_EOL,
    A_WORDB,
    A_NWORDB
};

struct Inst {
    int op;
    int x;          // char value, jump target, or assertion kind
    int y;          // continuation instruction
    int cls;        // class index for I_CLASS
};

struct Program {
    Inst* inst;
    int count;
    int start;
    unsigned char (*classes)[32];
    int classCount;
};

// ---- parser/compiler -------------------------------------------------------

enum NodeType {
    N_EMPTY = 1,
    N_CHAR,
    N_ANY,
    N_CLASS,
    N_CONCAT,
    N_ALT,
    N_REPEAT,
    N_BOL,
    N_EOL,
    N_WORDB,
    N_NWORDB
};

struct Node {
    int type;
    int a;
    int b;
    int min;
    int max;
    int cls;
};

struct Compiler {
    const unsigned char* pat;
    int len;
    int pos;
    int depth;
    bool failed;
    char err[200];
    Node nodes[MAX_NODES];
    int nodeCount;
    unsigned char classes[MAX_CLASSES][32];
    int classCount;
    Inst insts[MAX_STATES];
    int instCount;
};

static void SetErr(Compiler& c, const char* fmt, ...)
{
    if (c.failed) return;
    c.failed = true;
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(c.err, sizeof(c.err), _TRUNCATE, fmt, ap);
    va_end(ap);
}

static int NewNode(Compiler& c, int type)
{
    if (c.nodeCount >= MAX_NODES) {
        SetErr(c, "pattern too complex (AST node limit)");
        return -1;
    }
    Node& n = c.nodes[c.nodeCount];
    memset(&n, 0, sizeof(n));
    n.type = type;
    n.a = -1;
    n.b = -1;
    n.cls = -1;
    return c.nodeCount++;
}

static void BitsAddByte(unsigned char* bits, int b)
{
    bits[(b >> 3) & 31] |= (unsigned char)(1u << (b & 7));
}

static void BitsAddRange(unsigned char* bits, int lo, int hi)
{
    for (int i = lo; i <= hi; ++i) BitsAddByte(bits, i);
}

static void BitsNegate(unsigned char* bits)
{
    for (int i = 0; i < 32; ++i) bits[i] = (unsigned char)(~bits[i]);
}

static void BitsForClass(unsigned char* bits, int kind)
{
    memset(bits, 0, 32);
    if (kind == 'd' || kind == 'D') BitsAddRange(bits, '0', '9');
    if (kind == 'w' || kind == 'W') {
        BitsAddRange(bits, '0', '9');
        BitsAddRange(bits, 'A', 'Z');
        BitsAddRange(bits, 'a', 'z');
        BitsAddByte(bits, '_');
    }
    if (kind == 's' || kind == 'S') {
        BitsAddByte(bits, ' ');
        BitsAddByte(bits, '\t');
        BitsAddByte(bits, '\r');
        BitsAddByte(bits, '\n');
        BitsAddByte(bits, '\f');
        BitsAddByte(bits, '\v');
    }
    if (kind == 'D' || kind == 'W' || kind == 'S') BitsNegate(bits);
}

static int HexVal(int ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

enum EscKind {
    ESC_BAD = 0,
    ESC_BYTE,
    ESC_CLASS,
    ESC_WORDB,
    ESC_NWORDB
};

// Parses one escape sequence; c.pos points at the backslash on entry.
static EscKind ParseEscape(Compiler& c, unsigned* outByte, unsigned char* outBits, bool inClass)
{
    c.pos++; // backslash
    if (c.pos >= c.len) {
        SetErr(c, "trailing backslash");
        return ESC_BAD;
    }
    int ch = c.pat[c.pos++];
    if (ch == 'x') {
        if (c.pos + 2 > c.len) { SetErr(c, "incomplete \\xHH escape"); return ESC_BAD; }
        int h1 = HexVal(c.pat[c.pos]);
        int h2 = HexVal(c.pat[c.pos + 1]);
        if (h1 < 0 || h2 < 0) { SetErr(c, "invalid \\xHH escape"); return ESC_BAD; }
        c.pos += 2;
        *outByte = (unsigned)((h1 << 4) | h2);
        return ESC_BYTE;
    }
    if (ch == 'u') { SetErr(c, "\\u escapes are not supported; use UTF-8 \\xHH bytes"); return ESC_BAD; }
    if (ch >= '1' && ch <= '9') { SetErr(c, "backreference is not supported"); return ESC_BAD; }
    if (ch == 'p' || ch == 'P' || ch == 'A' || ch == 'Z' || ch == 'z' ||
        ch == 'G' || ch == 'k' || ch == 'Q') {
        SetErr(c, "unsupported escape \\%c", ch);
        return ESC_BAD;
    }
    if (ch == 'd' || ch == 'D' || ch == 'w' || ch == 'W' || ch == 's' || ch == 'S') {
        if (outBits) BitsForClass(outBits, ch);
        return ESC_CLASS;
    }
    if (ch == 'b') {
        if (inClass) { *outByte = 8; return ESC_BYTE; }
        return ESC_WORDB;
    }
    if (ch == 'B') {
        if (inClass) { SetErr(c, "\\B is not valid inside a character class"); return ESC_BAD; }
        return ESC_NWORDB;
    }
    if (ch == '0') {
        if (c.pos < c.len && c.pat[c.pos] >= '0' && c.pat[c.pos] <= '9') {
            SetErr(c, "octal escapes are not supported");
            return ESC_BAD;
        }
        *outByte = 0;
        return ESC_BYTE;
    }
    if (ch == 'n') { *outByte = '\n'; return ESC_BYTE; }
    if (ch == 'r') { *outByte = '\r'; return ESC_BYTE; }
    if (ch == 't') { *outByte = '\t'; return ESC_BYTE; }
    if (ch == 'f') { *outByte = '\f'; return ESC_BYTE; }
    if (ch == 'v') { *outByte = '\v'; return ESC_BYTE; }
    if (ch == 'c') {
        if (c.pos >= c.len) { SetErr(c, "incomplete \\cX escape"); return ESC_BAD; }
        int letter = c.pat[c.pos++];
        if (!((letter >= 'a' && letter <= 'z') || (letter >= 'A' && letter <= 'Z'))) {
            SetErr(c, "\\cX escape requires an ASCII letter");
            return ESC_BAD;
        }
        *outByte = (unsigned)(letter & 0x1F);
        return ESC_BYTE;
    }
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
        SetErr(c, "unsupported escape \\%c", ch);
        return ESC_BAD;
    }
    // Escaped punctuation is the literal byte (ECMAScript identity escape).
    *outByte = (unsigned)ch;
    return ESC_BYTE;
}

static int StoreClass(Compiler& c, const unsigned char* bits)
{
    if (c.classCount >= MAX_CLASSES) {
        SetErr(c, "too many character classes");
        return -1;
    }
    memcpy(c.classes[c.classCount], bits, 32);
    return c.classCount++;
}

static int ParseClass(Compiler& c)
{
    int node = NewNode(c, N_CLASS);
    if (node < 0) return -1;
    c.pos++; // '['
    bool neg = false;
    if (c.pos < c.len && c.pat[c.pos] == '^') {
        neg = true;
        c.pos++;
    }
    unsigned char bits[32];
    memset(bits, 0, sizeof(bits));
    bool first = true;
    for (;;) {
        if (c.pos >= c.len) {
            SetErr(c, "unterminated character class");
            return -1;
        }
        unsigned char ch = c.pat[c.pos];
        if (ch == ']' && !first) {
            c.pos++;
            break;
        }
        first = false;
        int lo = -1;
        unsigned char setBits[32];
        memset(setBits, 0, sizeof(setBits));
        bool isSet = false;
        if (ch == '\\') {
            unsigned b = 0;
            EscKind k = ParseEscape(c, &b, setBits, true);
            if (k == ESC_BAD) return -1;
            if (k == ESC_BYTE) lo = (int)b;
            else if (k == ESC_CLASS) isSet = true;
            else { SetErr(c, "\\b/\\B is not valid here"); return -1; }
        } else {
            lo = ch;
            c.pos++;
        }
        if (isSet) {
            for (int i = 0; i < 32; ++i) bits[i] |= setBits[i];
            continue;
        }
        // Range?
        if (c.pos + 1 < c.len && c.pat[c.pos] == '-' && c.pat[c.pos + 1] != ']') {
            int save = c.pos;
            c.pos++; // '-'
            int hi = -1;
            if (c.pos < c.len && c.pat[c.pos] == '\\') {
                unsigned b = 0;
                EscKind k = ParseEscape(c, &b, NULL, true);
                if (k == ESC_BAD) return -1;
                if (k != ESC_BYTE) { SetErr(c, "invalid character class range"); return -1; }
                hi = (int)b;
            } else if (c.pos < c.len && c.pat[c.pos] != ']') {
                hi = c.pat[c.pos];
                c.pos++;
            } else {
                c.pos = save;
            }
            if (hi < 0) {
                BitsAddByte(bits, lo);
                BitsAddByte(bits, '-');
            } else {
                if (hi < lo) { SetErr(c, "invalid character class range"); return -1; }
                BitsAddRange(bits, lo, hi);
            }
        } else {
            BitsAddByte(bits, lo);
        }
    }
    if (neg) BitsNegate(bits);
    int cls = StoreClass(c, bits);
    if (cls < 0) return -1;
    c.nodes[node].cls = cls;
    return node;
}

static int ParseAlt(Compiler& c);

static int ParseAtom(Compiler& c)
{
    if (c.pos >= c.len) {
        SetErr(c, "unexpected end of pattern");
        return -1;
    }
    unsigned char ch = c.pat[c.pos];
    switch (ch) {
    case '^': {
        c.pos++;
        return NewNode(c, N_BOL);
    }
    case '$': {
        c.pos++;
        return NewNode(c, N_EOL);
    }
    case '.': {
        c.pos++;
        return NewNode(c, N_ANY);
    }
    case '[':
        return ParseClass(c);
    case '(': {
        c.pos++;
        if (c.pos < c.len && c.pat[c.pos] == '?') {
            if (c.pos + 1 < c.len && c.pat[c.pos + 1] == ':') {
                c.pos += 2;
            } else {
                SetErr(c, "lookaround, named groups and conditionals are not supported");
                return -1;
            }
        }
        if (++c.depth > MAX_DEPTH) {
            SetErr(c, "group nesting too deep (max %d)", MAX_DEPTH);
            return -1;
        }
        int inner = ParseAlt(c);
        c.depth--;
        if (inner < 0) return -1;
        if (c.pos >= c.len || c.pat[c.pos] != ')') {
            SetErr(c, "missing closing parenthesis");
            return -1;
        }
        c.pos++;
        return inner;
    }
    case ')':
        SetErr(c, "unexpected ')'");
        return -1;
    case '|':
        SetErr(c, "empty alternative is not allowed here");
        return -1;
    case '*':
    case '+':
    case '?':
        SetErr(c, "quantifier without a preceding atom");
        return -1;
    case '\\': {
        unsigned b = 0;
        unsigned char bits[32];
        memset(bits, 0, sizeof(bits));
        EscKind k = ParseEscape(c, &b, bits, false);
        if (k == ESC_BAD) return -1;
        if (k == ESC_BYTE) {
            int n = NewNode(c, N_CHAR);
            if (n >= 0) c.nodes[n].a = (int)b;
            return n;
        }
        if (k == ESC_CLASS) {
            int n = NewNode(c, N_CLASS);
            if (n < 0) return -1;
            int cls = StoreClass(c, bits);
            if (cls < 0) return -1;
            c.nodes[n].cls = cls;
            return n;
        }
        if (k == ESC_WORDB) return NewNode(c, N_WORDB);
        return NewNode(c, N_NWORDB);
    }
    case ']':
        // A ']' outside a class is a literal byte in ECMAScript.
        c.pos++;
        {
            int n = NewNode(c, N_CHAR);
            if (n >= 0) c.nodes[n].a = ']';
            return n;
        }
    default: {
        c.pos++;
        int n = NewNode(c, N_CHAR);
        if (n >= 0) c.nodes[n].a = (int)ch;
        return n;
    }
    }
}

static bool LooksLikeBraceQuantifier(const Compiler& c)
{
    // c.pos points at '{'
    int p = c.pos + 1;
    if (p >= c.len || c.pat[p] < '0' || c.pat[p] > '9') return false;
    while (p < c.len && c.pat[p] >= '0' && c.pat[p] <= '9') p++;
    if (p < c.len && c.pat[p] == ',') {
        p++;
        while (p < c.len && c.pat[p] >= '0' && c.pat[p] <= '9') p++;
    }
    return p < c.len && c.pat[p] == '}';
}

static int ParseRepeat(Compiler& c)
{
    int atom = ParseAtom(c);
    if (atom < 0) return -1;
    if (c.pos >= c.len) return atom;
    int min = -1, max = -1;
    unsigned char ch = c.pat[c.pos];
    if (ch == '*') { c.pos++; min = 0; max = -1; }
    else if (ch == '+') { c.pos++; min = 1; max = -1; }
    else if (ch == '?') { c.pos++; min = 0; max = 1; }
    else if (ch == '{' && LooksLikeBraceQuantifier(c)) {
        int save = c.pos;
        c.pos++;
        int m = 0;
        while (c.pos < c.len && c.pat[c.pos] >= '0' && c.pat[c.pos] <= '9') {
            m = m * 10 + (c.pat[c.pos] - '0');
            if (m > 100000) { SetErr(c, "quantifier is too large"); return -1; }
            c.pos++;
        }
        int n = m;
        if (c.pos < c.len && c.pat[c.pos] == ',') {
            c.pos++;
            if (c.pos < c.len && c.pat[c.pos] == '}') {
                n = -1;
            } else {
                n = 0;
                while (c.pos < c.len && c.pat[c.pos] >= '0' && c.pat[c.pos] <= '9') {
                    n = n * 10 + (c.pat[c.pos] - '0');
                    if (n > 100000) { SetErr(c, "quantifier is too large"); return -1; }
                    c.pos++;
                }
            }
        }
        if (c.pos >= c.len || c.pat[c.pos] != '}') {
            c.pos = save;
            return atom;
        }
        c.pos++;
        min = m;
        max = n;
        if (min > MAX_QUANT || (max >= 0 && max > MAX_QUANT)) {
            SetErr(c, "quantifier out of range (max %d)", MAX_QUANT);
            return -1;
        }
        if (max >= 0 && max < min) {
            SetErr(c, "quantifier range is inverted");
            return -1;
        }
    } else {
        return atom;
    }
    // A single trailing '?' marks the quantifier lazy. For a boolean match that
    // is equivalent to greedy, so it is accepted and ignored.
    if (c.pos < c.len && c.pat[c.pos] == '?') c.pos++;
    // Any further quantifier directly after the first is a syntax error.
    if (c.pos < c.len) {
        unsigned char q = c.pat[c.pos];
        if (q == '*' || q == '+' || q == '?') {
            SetErr(c, "nested quantifier is not supported");
            return -1;
        }
        if (q == '{' && LooksLikeBraceQuantifier(c)) {
            SetErr(c, "nested quantifier is not supported");
            return -1;
        }
    }
    int rep = NewNode(c, N_REPEAT);
    if (rep < 0) return -1;
    c.nodes[rep].a = atom;
    c.nodes[rep].min = min;
    c.nodes[rep].max = max;
    return rep;
}

static int ParseConcat(Compiler& c)
{
    int result = -1;
    for (;;) {
        if (c.pos >= c.len) break;
        unsigned char ch = c.pat[c.pos];
        if (ch == ')' || ch == '|') break;
        int n = ParseRepeat(c);
        if (n < 0) return -1;
        if (result < 0) {
            result = n;
        } else {
            int cat = NewNode(c, N_CONCAT);
            if (cat < 0) return -1;
            c.nodes[cat].a = result;
            c.nodes[cat].b = n;
            result = cat;
        }
    }
    if (result < 0) return NewNode(c, N_EMPTY);
    return result;
}

static int ParseAlt(Compiler& c)
{
    int left = ParseConcat(c);
    if (left < 0) return -1;
    while (c.pos < c.len && c.pat[c.pos] == '|') {
        c.pos++;
        int right = ParseConcat(c);
        if (right < 0) return -1;
        int alt = NewNode(c, N_ALT);
        if (alt < 0) return -1;
        c.nodes[alt].a = left;
        c.nodes[alt].b = right;
        left = alt;
    }
    return left;
}

// ---- NFA emission (CPS style, continuation-passing) -----------------------

static int AddInst(Compiler& c, int op)
{
    if (c.instCount >= MAX_STATES) {
        SetErr(c, "pattern too complex (NFA state limit)");
        return -1;
    }
    Inst& in = c.insts[c.instCount];
    memset(&in, 0, sizeof(in));
    in.op = op;
    in.x = -1;
    in.y = -1;
    in.cls = -1;
    return c.instCount++;
}

static int Emit(Compiler& c, int node, int next)
{
    if (node < 0 || c.failed) return -1;
    const Node& n = c.nodes[node];
    switch (n.type) {
    case N_EMPTY:
        return next;
    case N_CHAR: {
        int i = AddInst(c, I_CHAR);
        if (i < 0) return -1;
        c.insts[i].x = n.a;
        c.insts[i].y = next;
        return i;
    }
    case N_ANY: {
        int i = AddInst(c, I_ANY);
        if (i < 0) return -1;
        c.insts[i].y = next;
        return i;
    }
    case N_CLASS: {
        int i = AddInst(c, I_CLASS);
        if (i < 0) return -1;
        c.insts[i].cls = n.cls;
        c.insts[i].y = next;
        return i;
    }
    case N_BOL:
    case N_EOL:
    case N_WORDB:
    case N_NWORDB: {
        int i = AddInst(c, I_ASSERT);
        if (i < 0) return -1;
        c.insts[i].x = (n.type == N_BOL) ? A_BOL :
                       (n.type == N_EOL) ? A_EOL :
                       (n.type == N_WORDB) ? A_WORDB : A_NWORDB;
        c.insts[i].y = next;
        return i;
    }
    case N_CONCAT: {
        int cont = Emit(c, n.b, next);
        if (cont < 0) return -1;
        return Emit(c, n.a, cont);
    }
    case N_ALT: {
        int split = AddInst(c, I_SPLIT);
        if (split < 0) return -1;
        int x = Emit(c, n.a, next);
        if (x < 0) return -1;
        int y = Emit(c, n.b, next);
        if (y < 0) return -1;
        c.insts[split].x = x;
        c.insts[split].y = y;
        return split;
    }
    case N_REPEAT: {
        int child = n.a;
        int min = n.min;
        int max = n.max;
        int cont = next;
        if (max < 0) {
            int split = AddInst(c, I_SPLIT);
            if (split < 0) return -1;
            int body = Emit(c, child, split);
            if (body < 0) return -1;
            c.insts[split].x = body;
            c.insts[split].y = cont;
            cont = split;
            for (int i = 0; i < min; ++i) {
                cont = Emit(c, child, cont);
                if (cont < 0) return -1;
            }
        } else {
            for (int i = 0; i < max - min; ++i) {
                int split = AddInst(c, I_SPLIT);
                if (split < 0) return -1;
                int body = Emit(c, child, cont);
                if (body < 0) return -1;
                c.insts[split].x = body;
                c.insts[split].y = cont;
                cont = split;
            }
            for (int i = 0; i < min; ++i) {
                cont = Emit(c, child, cont);
                if (cont < 0) return -1;
            }
        }
        return cont;
    }
    default:
        SetErr(c, "internal compiler error");
        return -1;
    }
}

// ---- matching -------------------------------------------------------------

struct Scratch {
    int* list1;
    int* list2;
    int* stack;
    int* seen;
    int capacity;
    int gen;
};

static Scratch g_scratch;

static bool EnsureScratch()
{
    if (g_scratch.capacity >= MAX_STATES) return true;
    if (g_scratch.list1) free(g_scratch.list1);
    if (g_scratch.list2) free(g_scratch.list2);
    if (g_scratch.stack) free(g_scratch.stack);
    if (g_scratch.seen) free(g_scratch.seen);
    memset(&g_scratch, 0, sizeof(g_scratch));
    int cap = MAX_STATES;
    g_scratch.list1 = (int*)malloc(sizeof(int) * cap);
    g_scratch.list2 = (int*)malloc(sizeof(int) * cap);
    g_scratch.stack = (int*)malloc(sizeof(int) * cap);
    g_scratch.seen = (int*)malloc(sizeof(int) * cap);
    if (!g_scratch.list1 || !g_scratch.list2 || !g_scratch.stack || !g_scratch.seen) return false;
    memset(g_scratch.seen, 0, sizeof(int) * cap);
    g_scratch.capacity = cap;
    return true;
}

static bool IsWordAt(const unsigned char* text, int idx, int len)
{
    if (idx < 0 || idx >= len) return false;
    unsigned char c = text[idx];
    if (c >= 0x80) return false;
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') return true;
    return false;
}

static void AddThread(const Program* p, int* list, int& listN, int pc,
                      int pos, int len, const unsigned char* text)
{
    Scratch& s = g_scratch;
    if (pc < 0) return;
    int sp = 0;
    s.stack[sp++] = pc;
    while (sp > 0) {
        pc = s.stack[--sp];
        if (pc < 0 || pc >= p->count) continue;
        if (s.seen[pc] == s.gen) continue;
        s.seen[pc] = s.gen;
        const Inst& in = p->inst[pc];
        switch (in.op) {
        case I_JMP:
            if (in.x >= 0 && sp < s.capacity) s.stack[sp++] = in.x;
            break;
        case I_SPLIT:
            if (in.y >= 0 && sp < s.capacity) s.stack[sp++] = in.y;
            if (in.x >= 0 && sp < s.capacity) s.stack[sp++] = in.x;
            break;
        case I_ASSERT: {
            bool ok = false;
            if (in.x == A_BOL) ok = (pos == 0);
            else if (in.x == A_EOL) ok = (pos == len);
            else if (in.x == A_WORDB) ok = (IsWordAt(text, pos, len) != IsWordAt(text, pos - 1, len));
            else if (in.x == A_NWORDB) ok = (IsWordAt(text, pos, len) == IsWordAt(text, pos - 1, len));
            if (ok && in.y >= 0 && sp < s.capacity) s.stack[sp++] = in.y;
            break;
        }
        default:
            if (listN < s.capacity) list[listN++] = pc;
            break;
        }
    }
}

static bool Match(const Program* p, const unsigned char* text, int len)
{
    if (!p || !p->inst || p->count <= 0 || p->start < 0) return false;
    if (len < 0) return false;
    if (!EnsureScratch()) return false;
    Scratch& s = g_scratch;
    int* clist = s.list1;
    int* nlist = s.list2;
    int cn = 0;
    s.gen++;
    AddThread(p, clist, cn, p->start, 0, len, text);
    for (int pos = 0;; ++pos) {
        for (int i = 0; i < cn; ++i) {
            if (p->inst[clist[i]].op == I_MATCH) return true;
        }
        if (pos >= len) return false;
        s.gen++;
        int nn = 0;
        unsigned char ch = text[pos];
        for (int i = 0; i < cn; ++i) {
            const Inst& in = p->inst[clist[i]];
            bool hit = false;
            if (in.op == I_CHAR) hit = (ch == (unsigned char)in.x);
            else if (in.op == I_ANY) hit = (ch != '\n');
            else if (in.op == I_CLASS && in.cls >= 0 && in.cls < p->classCount) {
                hit = ((p->classes[in.cls][(ch >> 3) & 31] >> (ch & 7)) & 1) != 0;
            }
            if (hit) AddThread(p, nlist, nn, in.y, pos + 1, len, text);
        }
        int* tmp = clist;
        clist = nlist;
        nlist = tmp;
        cn = nn;
        if (cn == 0) return false;
    }
}

static void Free(Program* p)
{
    if (!p) return;
    if (p->inst) free(p->inst);
    if (p->classes) free(p->classes);
    free(p);
}

// Compiles a pattern. Returns NULL on failure and writes a reason into err.
// Caller must Free() the returned program.
static Program* Compile(const char* pattern, char* err, int errCch)
{
    if (err && errCch > 0) err[0] = 0;
    if (!pattern) {
        if (err && errCch > 0) snprintf(err, errCch, "null pattern");
        return NULL;
    }
    size_t plen = strlen(pattern);
    if (plen > MAX_PATTERN_BYTES) {
        if (err && errCch > 0) snprintf(err, errCch, "pattern too long: %u bytes (max %d)", (unsigned)plen, MAX_PATTERN_BYTES);
        return NULL;
    }
    Compiler* c = (Compiler*)malloc(sizeof(Compiler));
    if (!c) {
        if (err && errCch > 0) snprintf(err, errCch, "out of memory");
        return NULL;
    }
    memset(c, 0, sizeof(*c));
    c->pat = (const unsigned char*)pattern;
    c->len = (int)plen;
    int root = (plen == 0) ? NewNode(*c, N_EMPTY) : ParseAlt(*c);
    if (root >= 0 && !c->failed && c->pos != c->len) {
        SetErr(*c, "unexpected character at offset %d", c->pos);
    }
    if (root < 0 || c->failed) {
        if (err && errCch > 0) snprintf(err, errCch, "%s", c->err[0] ? c->err : "invalid pattern");
        free(c);
        return NULL;
    }
    int mat = AddInst(*c, I_MATCH);
    if (mat < 0) {
        if (err && errCch > 0) snprintf(err, errCch, "%s", c->err[0] ? c->err : "pattern too complex");
        free(c);
        return NULL;
    }
    int start = Emit(*c, root, mat);
    if (start < 0 || c->failed) {
        if (err && errCch > 0) snprintf(err, errCch, "%s", c->err[0] ? c->err : "pattern too complex");
        free(c);
        return NULL;
    }
    Program* p = (Program*)malloc(sizeof(Program));
    if (!p) {
        free(c);
        if (err && errCch > 0) snprintf(err, errCch, "out of memory");
        return NULL;
    }
    memset(p, 0, sizeof(*p));
    p->count = c->instCount;
    p->start = start;
    p->classCount = c->classCount;
    p->inst = (Inst*)malloc(sizeof(Inst) * (size_t)p->count);
    p->classes = (unsigned char(*)[32])malloc(32 * (size_t)(p->classCount > 0 ? p->classCount : 1));
    if (!p->inst || !p->classes) {
        if (p->inst) free(p->inst);
        if (p->classes) free(p->classes);
        free(p);
        free(c);
        if (err && errCch > 0) snprintf(err, errCch, "out of memory");
        return NULL;
    }
    memcpy(p->inst, c->insts, sizeof(Inst) * (size_t)p->count);
    if (p->classCount > 0) memcpy(p->classes, c->classes, 32 * (size_t)p->classCount);
    free(c);
    return p;
}

} // namespace ssfsafe

#endif // SSF_SAFE_REGEX_H
