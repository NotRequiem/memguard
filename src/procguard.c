#include "struct.h"

static void InspectHandle(HANDLE hProcessHandle, DWORD accessMask, DWORD protectedProcessPID, DWORD currentProcessId) {
    bool hasOneUnallowed = false;
    for (int i = 0; i < sizeof(unallowedAccess) / sizeof(unallowedAccess[0]); i++) {
        DWORD flag = unallowedAccess[i];
        if (accessMask & flag) {
            hasOneUnallowed = true;
            break;
        }
    }

    if (!hasOneUnallowed) {
        return;
    }

    PROCESS_BASIC_INFORMATION processInfo;
    ULONG returnedLength;
    NTSTATUS status;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        wprintf(L"Failed to get module handle for ntdll.dll.\n");
        return;
    }

    pfnNtQueryInformationProcess pNtQueryInformationProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (pNtQueryInformationProcess == NULL) {
        wprintf(L"Failed to get address for NtQueryInformationProcess.\n");
        return;
    }

    status = pNtQueryInformationProcess(hProcessHandle, ProcessBasicInformation, &processInfo, sizeof(processInfo), &returnedLength);

    if (NT_SUCCESS(status)) {
        DWORD_PTR processId = (DWORD_PTR)processInfo.UniqueProcessId;
        if (processId == protectedProcessPID) {
            wprintf(L"Injection detected from process with PID %lu.\n", currentProcessId);
        }
    }
}

static void EnumerateProcesses(DWORD protectedProcessPID) {
    DWORD processIds[1024];
    DWORD bytesReturned;
    DWORD currentProcessId = GetCurrentProcessId();

    if (EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        DWORD numProcesses = bytesReturned / sizeof(DWORD);

        for (DWORD i = 0; i < numProcesses; ++i) {
            if (processIds[i] != 0 && processIds[i] != 4 && processIds[i] != protectedProcessPID && processIds[i] != currentProcessId) {

                HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, processIds[i]);
                if (hProcess != NULL) {
                    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
                    ULONG handleInfoSize = 0x10000;
                    NTSTATUS status;

                    do {
                        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(sizeof(ULONG) + handleInfoSize);
                        if (pHandleInfo == NULL) {
                            break;
                        }

                        status = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, handleInfoSize, NULL);

                        if (status == STATUS_INFO_LENGTH_MISMATCH) {
                            free(pHandleInfo);
                            handleInfoSize *= 2;
                        }
                        else if (NT_SUCCESS(status)) {
                            for (ULONG j = 0; j < pHandleInfo->HandleCount; ++j) {
                                HANDLE hDuplicate;
                                if (DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)pHandleInfo->Handles[j].HandleValue, GetCurrentProcess(), &hDuplicate, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, 0)) {
                                    InspectHandle(hDuplicate, pHandleInfo->Handles[j].AccessMask, protectedProcessPID, processIds[i]);
                                    CloseHandle(hDuplicate);
                                }
                            }
                        }

                    } while (status == STATUS_INFO_LENGTH_MISMATCH);

                    free(pHandleInfo);
                    CloseHandle(hProcess);
                }
            }
        }
    }
}

static int wcscasecmp(const wchar_t* s1, const wchar_t* s2) {
    while (*s1 != L'\0' && towlower(*s1) == towlower(*s2)) {
        s1++;
        s2++;
    }
    return towlower(*s1) - towlower(*s2);
}

static DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processIds[1024];
    DWORD bytesReturned;

    if (EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        DWORD numProcesses = bytesReturned / sizeof(DWORD);

        for (DWORD i = 0; i < numProcesses; ++i) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processIds[i]);

            if (hProcess) {
                wchar_t exeFileName[MAX_PATH] = { 0 };
                if (GetProcessImageFileName(hProcess, exeFileName, MAX_PATH) > 0) {
                    wchar_t* fileName = wcsrchr(exeFileName, L'\\');

                    if (fileName != NULL) {
                        ++fileName;
                        if (wcscasecmp(fileName, processName) == 0) {
                            CloseHandle(hProcess);
                            return processIds[i];
                        }
                    }
                }

                CloseHandle(hProcess);
            }
        }
    }

    return 0;
}

int main() {
    wchar_t targetProcessName[MAX_PATH];
    wprintf(L"Enter the process name to protect (e.g., Discord.exe): ");
    if (wscanf_s(L"%s", targetProcessName, (unsigned)_countof(targetProcessName)) != 1) {
        wprintf(L"Error reading input.\n");
        return 1;
    }

    DWORD protectedProcessPID = GetProcessIdByName(targetProcessName);
    bool ProtectedProcessPID = false;
    while (1) {
        if (protectedProcessPID != 0) {
            if (!ProtectedProcessPID) {
                wprintf(L"Protecting process with PID: %lu\n", protectedProcessPID);
                ProtectedProcessPID = true;
            }
            EnumerateProcesses(protectedProcessPID);
        }
        else {
            wprintf(L"Process %s not found.\n", targetProcessName);
        }

        Sleep(100);
    }
    return 0;
}