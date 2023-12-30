#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <Psapi.h>
#include <ntstatus.h>
#include <stdbool.h>
#include <wctype.h>

#pragma comment(lib, "ntdll.lib")

#define SystemHandleInformation 16

    typedef NTSTATUS(WINAPI* pfnNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    typedef struct _SYSTEM_HANDLE_ENTRY {
        ULONG       OwnerPid;
        BYTE        ObjectType;
        BYTE        HandleFlags;
        USHORT      HandleValue;
        PVOID       ObjectPointer;
        ULONG       AccessMask;
    } SYSTEM_HANDLE_ENTRY, * PSYSTEM_HANDLE_ENTRY;

    typedef struct _SYSTEM_HANDLE_INFORMATION {
        ULONG               HandleCount;
        SYSTEM_HANDLE_ENTRY Handles[1];
    } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    DWORD unallowedAccess[] = { PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_CREATE_PROCESS, PROCESS_SET_INFORMATION, PROCESS_SET_LIMITED_INFORMATION, PROCESS_SET_QUOTA };

#ifdef __cplusplus
}
#endif

/*

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;
/*
typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved [22];
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;
typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG   Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG   HandleCount;
    ULONG   PointerCount;
    ULONG   PagedPoolCharge;
    ULONG   NonPagedPoolCharge;
    union {
        struct { // For versions 3.10 only
            ULONG   TotalNumberOfObjects;
            ULONG   TotalNumberOfHandles;
            ULONG   UnknownDword;
        } Version310;
        ULONG   Reserved[3];              // For versions 3.51 and higher
    };
    ULONG   NameInfoSize;
    ULONG   TypeInfoSize;
    ULONG   SecurityDescriptorSize;
    LARGE_INTEGER   CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;
typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    // POOL_TYPE PoolType; for Kernel Development
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

__kernel_entry NTSTATUS
NTAPI
NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

static NTSTATUS NtQueryObjectWrapper(
    HANDLE hObject,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
)
{
    HMODULE ntdllModule = GetModuleHandle(L"ntdll.dll");
    if (ntdllModule != NULL) {
        NtQueryObject_t NtQueryObject = (NtQueryObject_t)GetProcAddress(ntdllModule, "NtQueryObject");
        if (NtQueryObject != NULL) {
            return NtQueryObject(hObject, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
        }
        else {
            DWORD lastError = GetLastError();
            printf("Error: Couldn't find NtQueryObject function in ntdll.dll. GetLastError: %u\n", lastError);
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }
    else {
        DWORD lastError = GetLastError();
        printf("Error: Couldn't find ntdll.dll. GetLastError: %u\n", lastError);
        return STATUS_PROCEDURE_NOT_FOUND;
    }
} 
*/