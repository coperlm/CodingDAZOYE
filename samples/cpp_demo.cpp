#include <windows.h>
#include <cstring>

class Demo {
public:
    void run() {
        char buf[16];
        EnterCriticalSection(NULL);
        strcpy(buf, "cpp sample payload");
        if (buf[0] == '\0') {
            return;
        }
        LeaveCriticalSection(NULL);
        TerminateThread(NULL, 0);
    }
};