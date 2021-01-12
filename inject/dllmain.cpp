
#include <Windows.h>
#include <stdio.h>
//
// some data will be shared across all
// instances of the DLL
//
#pragma comment(linker, "/SECTION:.SHARED,RWS")
#pragma data_seg(".SHARED")

int iKeyCount = 0;
HHOOK hMsgHook = 0;

//
// instance specific data
//
HMODULE hInstance = 0;

//
// DLL load/unload entry point
//
BOOL APIENTRY DllMain(HANDLE hModule,
    DWORD  dwReason,
    LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        hInstance = (HINSTANCE)hModule;
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport)
LRESULT CALLBACK MsgProc(int code,
    WPARAM wParam,
    LPARAM lParam)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    MSG* ptr = (MSG*)lParam;
    FILE* fp;
    fopen_s(&fp, "log.log", "a+");
    if (fp != nullptr) {
        fprintf(fp, "[%d-%02d-%02d %02d:%02d:%02d]call hook\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fclose(fp);
    }
    return CallNextHookEx(hMsgHook, code, wParam, lParam);
}

//
// install hooks
//
extern "C" __declspec(dllexport)
void InstallHooks()
{
    //hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, hInstance, 0);
    hMsgHook = SetWindowsHookEx(WH_MSGFILTER, MsgProc, hInstance, 0);
}

//
// remov hooks
//
extern "C" __declspec(dllexport)
void RemoveHooks()
{
    //UnhookWindowsHookEx(hKeyboardHook);
    UnhookWindowsHookEx(hMsgHook);
    hMsgHook = 0;
}

