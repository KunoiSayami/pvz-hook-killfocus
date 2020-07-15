#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

#include <stdio.h>
#include <signal.h>

HHOOK _hook;
HANDLE hProcess;
#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif


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
DWORD scan_process(LPCTSTR process_name) {
	HANDLE hdSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	DWORD process_id = 0;
	Process32First(hdSnap, &pe32);
	do {
		if (!_tcscmp(process_name, pe32.szExeFile)) {
			process_id = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hdSnap, &pe32));
	CloseHandle(hdSnap);
	return process_id;
}

LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
	MSG* ptr = (MSG*) lParam;
	if (nCode >= 0)
	{
		printf("%d", ptr->message == WM_KILLFOCUS);
	}

	// call the next hook in the hook chain. This is nessecary or your hook chain will break and the hook stops
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}



void do_hook(DWORD pid) {
	//hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	HMODULE hModule = LoadLibrary(_T("INJECT.dll"));
	_hook = SetWindowsHookEx(WH_MSGFILTER, (HOOKPROC)GetProcAddress(hModule, "meconnect"), hModule, 0);
	printf("%ld\n", GetLastError());
}

// https://www.codeproject.com/Articles/4610/Three-Ways-to-Inject-Your-Code-into-Another-Proces
void inject_and_hook(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	HANDLE hThread;
	void* pLibRemote;
	DWORD hLibModule;
	HMODULE hKernel32 = LoadLibrary(_T("kernel32"));//, hInject = LoadLibrary(TEXT("INJECT.dll"));
	DWORD dWord;
	LPSTR szCurrentPath = new CHAR[260], szLibPath = new CHAR[300];
	GetCurrentDirectoryA(260, szCurrentPath);
	void* addr = (void*)::GetProcAddress(hKernel32, "LoadLibraryA");
	sprintf(szLibPath, "%s\\Release\\INJECT.dll", szCurrentPath);
	pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(szLibPath) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath, strlen(szLibPath), NULL);
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) addr, pLibRemote, 0, &dWord);
	WaitForSingleObject(hThread, INFINITE);
	printf("%ld\n", GetExitCodeThread(hThread, &hLibModule));
	//_hook = SetWindowsHookEx(WH_MSGFILTER, (HOOKPROC)GetProcAddress(hInject, "meconnect"),(HINSTANCE) hLibModule, GuessProcessMainThread(pid));
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);
	delete[] szCurrentPath, delete[] szLibPath;
	CloseHandle(hProcess);
}


void signa(int) {
	UnhookWindowsHookEx(_hook);
	CloseHandle(hProcess);
	exit(0);
}

int main()
{
	DWORD process_id = scan_process(_T("popcapgame1.exe"));
	printf("%ld\n", process_id);
	inject_and_hook(process_id);
	//Sleep(50000);
	//signal(SIGINT, signa);
	//while (1) Sleep(1000);
	return 0;
}
