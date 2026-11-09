// test_safe_regex.cpp - offline tests for safe_regex.h (no game, no injection)
#include "safe_regex.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

using namespace ssfsafe;

static int g_pass = 0;
static int g_fail = 0;

static void Expect(const char* pat, const char* text, bool want, const char* label)
{
    char err[200] = {0};
    Program* p = Compile(pat, err, sizeof(err));
    if (!p) {
        printf("FAIL [%s] compile failed: pattern=%s err=%s\n", label, pat, err);
        g_fail++;
        return;
    }
    bool got = Match(p, (const unsigned char*)text, (int)strlen(text));
    Free(p);
    if (got != want) {
        printf("FAIL [%s] pattern=%s text=%s want=%d got=%d\n", label, pat, text, (int)want, (int)got);
        g_fail++;
    } else {
        g_pass++;
    }
}

static void ExpectReject(const char* pat, const char* label)
{
    char err[200] = {0};
    Program* p = Compile(pat, err, sizeof(err));
    if (p) {
        printf("FAIL [%s] should reject: %s\n", label, pat);
        Free(p);
        g_fail++;
    } else {
        g_pass++;
    }
}

int main()
{
    const char* plus = "^([Pp][Ll][Uu][Ss] L4D2 [0-9][0-9] #[0-9]+|[Pp][Uu][Rr][Ee] L4D2 .*)$";
    Expect(plus, "PLUS L4D2 01 #3", true, "plus");
    Expect(plus, "plus L4D2 21 #7", true, "plus-lower");
    Expect(plus, "PURE L4D2 05 #3", true, "pure");
    Expect(plus, "PLUS L4D2 1 #3", false, "plus-one-digit");
    Expect(plus, "PLUS L4D2 01 #", false, "plus-no-num");
    Expect(plus, "PLUS L4D2 01 #3 extra", false, "plus-trailing");
    Expect(plus, "PLUS L4D2 01 #3\n", false, "plus-newline");

    Expect("^(?:a|b)+c$", "ababc", true, "alt-plus");
    Expect("^(?:a|b)+c$", "abab", false, "alt-plus-no-c");
    Expect("^a{2,4}$", "aa", true, "quant");
    Expect("^a{2,4}$", "aaaa", true, "quant4");
    Expect("^a{2,4}$", "a", false, "quant1");
    Expect("^a{2,4}$", "aaaaa", false, "quant5");
    Expect("^a{3}$", "aaa", true, "quant-exact");
    Expect("^a{2,}$", "aaaaaaaa", true, "quant-open");
    Expect("^[^0-9]+$", "abc", true, "class-neg");
    Expect("^[^0-9]+$", "a1c", false, "class-neg-hit");
    Expect("^[a-c-e]+$", "-", true, "class-dash");
    Expect("^[a-c-e]+$", "d", false, "class-range-d");
    Expect("^[a-c-e]+$", "b", true, "class-range-b");
    Expect("^\\xE7\\xBA\\xAF$", "\xE7\xBA\xAF", true, "utf8-escape");
    Expect("^\\d+\\.\\d+$", "12.34", true, "digit-dot");
    Expect("^\\w+$", "abc_09", true, "word");
    Expect("^\\w+$", "a-b", false, "word-dash");
    Expect("^\\s+$", " \t\r\n", true, "space");
    Expect("^$", "", true, "empty");
    Expect("^(?:)$", "", true, "empty-group");
    Expect("^a*$", "", true, "star-empty");
    Expect("^.*$", "PLUS L4D2 01 #3", true, "dotstar");
    Expect("^(?:ab){2,3}$", "abab", true, "group-quant");
    Expect("^(?:ab){2,3}$", "ababab", true, "group-quant3");
    Expect("^(?:ab){2,3}$", "ab", false, "group-quant1");
    Expect("^a+?$", "aaa", true, "lazy-plus");
    Expect("^(?:a*?)*$", "aaa", true, "lazy-star-star");
    Expect("^\\bword\\b$", "word", true, "wordb");
    Expect("^\\bword\\b$", "sword", false, "wordb-prefix");
    Expect("^(?:a|)$", "", true, "empty-branch");
    Expect("^(?:a|)$", "a", true, "empty-branch-a");
    Expect("^[\\d]+$", "0123", true, "class-digit");
    Expect("^[\\-]+$", "--", true, "class-escaped-dash");
    Expect("^[a\\-c]+$", "a-c", true, "class-escaped-dash2");

    // Rejected constructs: no unbounded backtracking / unsupported syntax.
    ExpectReject("(?=x)y", "lookahead");
    ExpectReject("(?<=x)y", "lookbehind");
    ExpectReject("(?!x)y", "neg-lookahead");
    ExpectReject("(a)\\1", "backref");
    ExpectReject("(?<name>a)", "named-group");
    ExpectReject("\\p{L}", "unicode-prop");
    ExpectReject("a**", "double-quant");
    ExpectReject("a{65}", "quant-limit");
    ExpectReject("a{1,1000}", "quant-limit2");
    ExpectReject("a{5,2}", "quant-inverted");
    ExpectReject("[a-", "unterminated-class");
    ExpectReject("[z-a]", "bad-range");
    ExpectReject("(", "unclosed-group");
    ExpectReject(")", "stray-rparen");

    // Length limit.
    {
        char big[2200];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = 0;
        ExpectReject(big, "too-long");
    }

    // Catastrophic-backtracking pattern must finish fast (Pike VM O(n*m)).
    {
        char err[200] = {0};
        Program* p = Compile("^(a+)+$", err, sizeof(err));
        if (!p) {
            printf("FAIL [perf] compile: %s\n", err);
            g_fail++;
        } else {
            char text[141];
            memset(text, 'a', sizeof(text) - 1);
            text[sizeof(text) - 1] = 0;
            text[sizeof(text) - 2] = 'b';
            ULONGLONG t0 = GetTickCount64();
            bool got = Match(p, (const unsigned char*)text, (int)strlen(text));
            ULONGLONG dt = GetTickCount64() - t0;
            Free(p);
            if (got) { printf("FAIL [perf] expected no match\n"); g_fail++; }
            else if (dt > 200) { printf("FAIL [perf] too slow: %llu ms\n", (unsigned long long)dt); g_fail++; }
            else { printf("perf: (a+)+$ on %d chars -> %llu ms\n", (int)strlen(text), (unsigned long long)dt); g_pass++; }
        }
    }

    // Size limit: match text length > 63 is still bounded by caller, but the
    // engine itself handles arbitrary byte lengths without backtracking.
    Expect("^a+$", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, "long-match");

    printf("RESULT: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
