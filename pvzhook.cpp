#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

#include <stdio.h>
#include <signal.h>

HHOOK _hook;
HMODULE hModule;
FARPROC cleanFunction;

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

void do_hook(DWORD pid) {
	//hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	hModule = LoadLibrary(_T("INJECT.dll"));
	cleanFunction = GetProcAddress(hModule, "RemoveHooks");
	GetProcAddress(hModule, "InstallHooks")();
	//_hook = SetWindowsHookEx(WH_MSGFILTER, (HOOKPROC)GetProcAddress(hModule, "InstallHooks"), hModule, 0);
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
	//UnhookWindowsHookEx(_hook);
	//CloseHandle(hProcess);
	cleanFunction();
	FreeLibrary(hModule);
	exit(0);
}

int main()
{
	DWORD process_id = scan_process(_T("popcapgame1.exe"));
	printf("%ld\n", process_id);
	do_hook(process_id);
	//Sleep(50000);
	//signal(SIGINT, signa);
	while (1) Sleep(1000);
	return 0;
}
