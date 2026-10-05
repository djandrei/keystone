/* Integration-test fixture for Keystone's ghidra-headless-mcp client.
 *
 * Small and deterministic on purpose: check_key is called from main and
 * compares against a known string, so the tests can assert a function, a
 * cross-reference and a string without depending on the compiler's choices.
 * Never executed by the tests — only imported into Ghidra. */
#include <stdio.h>
#include <string.h>

static const char *EXPECTED = "KEYSTONE-FIXTURE-KEY";

int check_key(const char *candidate) {
    return strcmp(candidate, EXPECTED) == 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        puts("usage: keycheck <key>");
        return 2;
    }
    if (check_key(argv[1])) {
        puts("ACCESS GRANTED");
        return 0;
    }
    puts("ACCESS DENIED");
    return 1;
}
