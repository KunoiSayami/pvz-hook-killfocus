#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include "file_location.h"
#include <string>


#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

#ifndef DLL_LOGDIR
constexpr auto DLL_FUNCTION_FILE = "function.log";
constexpr auto DLL_LOG_FILE = "log.log";
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

//extern "C" __declspec(dllexport)
LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
	FILE* file;
	SYSTEMTIME st;
	GetLocalTime(&st);
	MSG* ptr = (MSG*)lParam;
	fopen_s(&file, DLL_FUNCTION_FILE, "a+");
	fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d %d.\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, ptr->message == WM_KILLFOCUS);
	//printf("%d", ptr->message == WM_KILLFOCUS);
	fclose(file);
	if (nCode >= 0)
	{

	}

	// call the next hook in the hook chain. This is nessecary or your hook chain will break and the hook stops
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}

#if 0
#ifdef UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

std::vector<DWORD>& get_thread_id(std::vector<DWORD>& tids) {
	HANDLE hdSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);
	if (Thread32First(hdSnap, &te32)) {
		do {
			if (tstring(te32.))
		}
	}
	return tids;
}
#endif

DWORD WINAPI thread(LPVOID params) {
	FILE* file;
	SYSTEMTIME st;
	GetLocalTime(&st);
	fopen_s(&file, DLL_FUNCTION_FILE, "a+");
	_hook = SetWindowsHookEx(WH_MSGFILTER, HookCallback, NULL, GuessProcessMainThread(GetCurrentProcessId()));
	std::vector<DWORD> threadPids;
	if (_hook == NULL)
		fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d %ld.\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetLastError());
	else
		fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d hook started.\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	fclose(file);
	while (1)
		Sleep(60000);
	return 0;
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {
	/* open file */
	FILE* file;
	SYSTEMTIME st;
	GetLocalTime(&st);
	fopen_s(&file, DLL_LOG_FILE, "a+");

	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		fprintf(file, "DLL attach function called.\n");
		CreateThread(NULL, 0, thread, NULL, 0, NULL);
		break;
	case DLL_PROCESS_DETACH:
		fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		fprintf(file, "DLL detach function called.\n");
		break;
	case DLL_THREAD_ATTACH:
		fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		fprintf(file, "DLL thread attach function called.\n");
		break;
	case DLL_THREAD_DETACH:
		fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		fprintf(file, "DLL thread detach function called.\n");
		break;
	}
	/* close file */
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
