#ifndef CSC_H
#define CSC_H

#include <ntifs.h>
#include <windef.h>

#define CSC_DEVICE_NAME             L"\\Device\\Csc"
#define CSC_DOS_DEVICE_NAME         L"\\DosDevices\\Csc"

#define CSC_DEVICE_TYPE             FILE_DEVICE_NETWORK_FILE_SYSTEM

// GUID: {1C92E1BF-103B-4545-B242-E5A9858EC9C8}
DEFINE_GUID(GUID_DEVCLASS_CSC,
    0x1C92E1BF, 0x103B, 0x4545, 0xB2, 0x42, 0xE5, 0xA9, 0x85, 0x8E, 0xC9, 0xC8);

// FSCTL / IOCTL Definitions
// CVE-2024-26229: FSCTL_CSC_INTERNAL uses METHOD_NEITHER
#ifdef FSCTL_CSC_INTERNAL
#undef FSCTL_CSC_INTERNAL
#endif
#define FSCTL_CSC_INTERNAL              0x001401A3 // CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0x0068, METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_CSC_FINALIZE_CONNECTION   0x001401AC // CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0x006B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CSC_USER_QUERY_ITEM       0x00140180 // CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0x0060, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CSC_USER_QUERY_DATABASE   0x00140184 // CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0x0061, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CSC_USER_SET_PIN          0x00140188 // CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0x0062, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CSC_USER_QUERY_SECURITY   0x0014018C // CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 0x0063, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Sub-operation opcodes for FSCTL_CSC_INTERNAL
#define CSC_FSCTL_OPERATION_QUERY_HANDLE                0
#define CSC_FSCTL_OPERATION_TRANSITION                  1
#define CSC_FSCTL_OPERATION_QUERY_ITEM                  2
#define CSC_FSCTL_OPERATION_SET_ITEM                    3
#define CSC_FSCTL_OPERATION_DELETE                      4
#define CSC_FSCTL_OPERATION_EVICT_ITEM                  5
#define CSC_FSCTL_OPERATION_EVICT                       6
#define CSC_FSCTL_OPERATION_RENAME                      7
#define CSC_FSCTL_OPERATION_QUERY_SECURITY              8
#define CSC_FSCTL_OPERATION_SET_SECURITY                9
#define CSC_FSCTL_OPERATION_QUERY_PIN                   10
#define CSC_FSCTL_OPERATION_QUERY_PIN_ALL               11
#define CSC_FSCTL_OPERATION_SET_PIN                     12
#define CSC_FSCTL_OPERATION_REMOVE_PIN                  13
#define CSC_FSCTL_OPERATION_QUERY_DIRECTORY             14
#define CSC_FSCTL_OPERATION_ENUMERATE_QUEUE             16
#define CSC_FSCTL_OPERATION_QUERY_DATABASE              17
#define CSC_FSCTL_OPERATION_SET_DATABASE                18
#define CSC_FSCTL_OPERATION_QUERY_DATABASE_EVICTION     19
#define CSC_FSCTL_OPERATION_SET_DATABASE_EVICTION       20
#define CSC_FSCTL_OPERATION_PRINCIPAL_ID_TO_SID         23
#define CSC_FSCTL_OPERATION_CONNECT                     24
#define CSC_FSCTL_OPERATION_DISCONNECT                  25
#define CSC_FSCTL_OPERATION_ENABLE                      26
#define CSC_FSCTL_OPERATION_DISABLE                     27
#define CSC_FSCTL_OPERATION_IS_ENABLED                  28
#define CSC_FSCTL_OPERATION_ADD_SID                     37

// Request Structures
#pragma pack(push, 1)

typedef struct _CSC_INTERNAL_REQUEST {
    ULONG OpCode;
    ULONG SubOpCode;
    ULONG Size;
    ULONG Flags;
    PVOID UserBuffer;
    ULONG BufferLength;
} CSC_INTERNAL_REQUEST, *PCSC_INTERNAL_REQUEST;

typedef struct _CSC_STORE_ITEM_INFO {
    ULONG ItemId;
    ULONG ParentId;
    ULONG Attributes;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER LastWriteTime;
    WCHAR FileName[260];
} CSC_STORE_ITEM_INFO, *PCSC_STORE_ITEM_INFO;

typedef struct _CSC_STORE_QUERY_REQ {
    ULONG ItemId;
    ULONG Flags;
    CSC_STORE_ITEM_INFO ItemInfo;
} CSC_STORE_QUERY_REQ, *PCSC_STORE_QUERY_REQ;

typedef struct _CSC_DATABASE_INFO {
    ULONG Version;
    ULONG TotalItems;
    ULONG TotalPinCount;
    ULONG DatabaseFlags;
    ULONGLONG DatabaseSize;
} CSC_DATABASE_INFO, *PCSC_DATABASE_INFO;

typedef struct _CSC_SECURITY_REQ {
    ULONG PrincipalId;
    ULONG SidLength;
    UCHAR SidBuffer[68];
    ULONG SecurityDescriptorLength;
} CSC_SECURITY_REQ, *PCSC_SECURITY_REQ;

typedef struct _CSC_PIN_REQ {
    ULONG ItemId;
    ULONG PinFlags;
} CSC_PIN_REQ, *PCSC_PIN_REQ;

#pragma pack(pop)

// Forward declarations
extern PDEVICE_OBJECT g_CscDeviceObject;

// Prototypes - fsctl.c
NTSTATUS CscProcessFsctl(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
NTSTATUS CscHandleInternalFsctl(PVOID InputBuffer, ULONG InputLength, PVOID OutputBuffer, ULONG OutputLength, ULONG_PTR *BytesReturned);

// Prototypes - store.c
NTSTATUS CscStoreQueryItem(ULONG ItemId, PCSC_STORE_ITEM_INFO ItemInfo);
NTSTATUS CscStoreQueryDatabase(PCSC_DATABASE_INFO DatabaseInfo);
NTSTATUS CscStoreSetPin(ULONG ItemId, ULONG PinFlags);
NTSTATUS CscStoreEvictItem(ULONG ItemId);

// Prototypes - security.c
NTSTATUS CscQuerySecurity(ULONG PrincipalId, PVOID Buffer, ULONG BufferLength, ULONG *RequiredLength);
NTSTATUS CscSetSecurity(ULONG PrincipalId, PVOID Buffer, ULONG BufferLength);
NTSTATUS CscPrincipalIdToSid(ULONG PrincipalId, PSID Sid, ULONG SidLength);
BOOLEAN CscValidateCallerAccess(VOID);

#endif // CSC_H
