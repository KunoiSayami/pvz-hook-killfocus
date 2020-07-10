#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

HHOOK _hook;

DWORD GuessProcessMainThread(DWORD dwProcID)
{
	DWORD dwMainThreadID = 0;
	ULONGLONG ullMinCreateTime = MAXULONGLONG;

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 th32;
		th32.dwSize = sizeof(THREADENTRY32);
		BOOL bOK = TRUE;
		for (bOK = Thread32First(hThreadSnap, &th32); bOK;
			bOK = Thread32Next(hThreadSnap, &th32)) {
			if (th32.th32OwnerProcessID == dwProcID) {
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
					TRUE, th32.th32ThreadID);
				if (hThread) {
					FILETIME afTimes[4] = { 0 };
					if (GetThreadTimes(hThread,
						&afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
						ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime,
							afTimes[0].dwHighDateTime);
						if (ullTest && ullTest < ullMinCreateTime) {
							ullMinCreateTime = ullTest;
							dwMainThreadID = th32.th32ThreadID; // let it be main... :)
						}
					}
					CloseHandle(hThread);
				}
			}
		}
		CloseHandle(hThreadSnap);
	}

	//if (dwMainThreadID) {
	//	//PostThreadMessage(dwMainThreadID, WM_QUIT, 0, 0); // close your eyes...
	//}

	return dwMainThreadID;
}

LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
	MSG* ptr = (MSG*)lParam;
	if (nCode >= 0)
	{
		printf("%d", ptr->message == WM_KILLFOCUS);
	}

	// call the next hook in the hook chain. This is nessecary or your hook chain will break and the hook stops
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}
INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {
	/* open file */
	FILE* file;
	fopen_s(&file, "temp.txt", "a+");

	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		fprintf(file, "DLL attach function called.\n");
		break;
	case DLL_PROCESS_DETACH:
		fprintf(file, "DLL detach function called.\n");
		break;
	case DLL_THREAD_ATTACH:
		fprintf(file, "DLL thread attach function called.\n");
		break;
	case DLL_THREAD_DETACH:
		fprintf(file, "DLL thread detach function called.\n");
		break;
	}
	/* close file */
	SYSTEMTIME st;
	GetLocalTime(&st);
	//SetWindowsHookEx(WH_MSGFILTER, HookCallback, NULL, GuessProcessMainThread(GetProcessId(GetCurrentProcess())));
	fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d %ld.\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetLastError());
	fclose(file);
	return TRUE;
}

extern "C" __declspec(dllexport) int meconnect(int code, WPARAM wParam, LPARAM lParam) {
	FILE* file;
	SYSTEMTIME st;
	GetLocalTime(&st);
	MSG* ptr = (MSG*)lParam;
	fopen_s(&file, "function.txt", "a+");
	fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d %d.\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, ptr->message == WM_KILLFOCUS);
	fclose(file);
	return(CallNextHookEx(NULL, code, wParam, lParam));
}
