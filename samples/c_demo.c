#include <windows.h>
#include <string.h>

void c_demo(void) {
    char buf[16];
    EnterCriticalSection(NULL);
    strcpy(buf, "this is too long");
    if (buf[0] == 'x') {
        return;
    }
    LeaveCriticalSection(NULL);
    TerminateThread(NULL, 0);
}