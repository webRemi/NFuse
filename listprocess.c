#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include "C:\Users\attacker\source\hiddenLib-main\info\info.h"
#define MAX_SIZE 1024

DWORD ListProcess(CHAR* cProcessNeeded) {
	DWORD dwPids[MAX_SIZE];
	DWORD dwNumberOfPids = 0;
	DWORD dwPidsSize = sizeof(dwPids);
	HANDLE hProcess = NULL;
	HMODULE lphModule = NULL;
	DWORD dwCb = sizeof(lphModule);
	DWORD dwCbNeeded = 0;
	CHAR cProcessName[MAX_SIZE];
	SIZE_T nSize = sizeof(cProcessName);

	printf("%s Injecting in: %s\n", INFO, cProcessNeeded);

	if (!EnumProcesses(&dwPids, dwPidsSize, &dwNumberOfPids)) {
		printf("%s EnumProcesses failed with error: 0x%x\n", ERROR, GetLastError());
		return 1;
	}

	for (int i = 0; i < dwNumberOfPids; i++) {
		if (dwPids[i] != 0) {
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, dwPids[i]);
			if (hProcess == NULL) {
				continue;
			}
			//printf("%s Get handle for process %d at address: 0x%p\n", SUCCESS, dwPids[i], hProcess);

			if (!EnumProcessModules(hProcess, &lphModule, dwCb, &dwCbNeeded)) {
				continue;
			}

			GetModuleBaseNameA(hProcess, lphModule, &cProcessName, nSize);
			//printf("%s Get name of process %d: %s\n", SUCCESS, dwPids[i], cProcessName);

			if (strstr(cProcessName, cProcessNeeded)) {
				printf("%s Process %s active with pid %d\n", SUCCESS, cProcessName, dwPids[i]);
				return dwPids[i];
			}
		}
	}
	printf("%s Injection error\n", ERROR);
	printf("%s Possible failures:\n"
		"\t- Process does not exist\n"
		"\t- Access denied\n"
		"\t- Process locked\n", INFO);
	printf("%s Try running as Administrator\n", ERROR);
	exit(1);
}