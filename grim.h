#include <Windows.h>
#pragma comment(lib, "ntdll")

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;                                                          //0x0
    VOID* RootDirectory;                                                    //0x8
    struct _UNICODE_STRING* ObjectName;                                     //0x10
    ULONG Attributes;                                                       //0x18
    VOID* SecurityDescriptor;                                               //0x20
    VOID* SecurityQualityOfService;                                         //0x28
} *POBJECT_ATTRIBUTES, OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    VOID* UniqueProcess;                                                    //0x0
    VOID* UniqueThread;                                                     //0x8
} *PCLIENT_ID, CLIENT_ID;

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );