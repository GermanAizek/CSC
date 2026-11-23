#include "CSC.h"

NTSTATUS CscHandleInternalFsctl(
    PVOID InputBuffer,
    ULONG InputLength,
    PVOID OutputBuffer,
    ULONG OutputLength,
    ULONG_PTR *BytesReturned
)
{
    PCSC_INTERNAL_REQUEST Req;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputLength);

    if (!InputBuffer || InputLength < sizeof(CSC_INTERNAL_REQUEST)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // Initial vulnerable implementation (CVE-2024-26229):
    // Unvalidated user-mode pointers accessed directly in kernel mode without probing
    Req = (PCSC_INTERNAL_REQUEST)InputBuffer;

    switch (Req->OpCode) {
    case CSC_FSCTL_OPERATION_QUERY_HANDLE:
        if (Req->UserBuffer && Req->BufferLength >= sizeof(ULONG)) {
            *(PULONG)Req->UserBuffer = 0x1000;
            *BytesReturned = sizeof(ULONG);
        }
        break;

    case CSC_FSCTL_OPERATION_QUERY_ITEM:
        if (Req->UserBuffer && Req->BufferLength >= sizeof(CSC_STORE_ITEM_INFO)) {
            Status = CscStoreQueryItem(Req->SubOpCode, (PCSC_STORE_ITEM_INFO)Req->UserBuffer);
            if (NT_SUCCESS(Status)) {
                *BytesReturned = sizeof(CSC_STORE_ITEM_INFO);
            }
        }
        break;

    case CSC_FSCTL_OPERATION_QUERY_DATABASE:
        if (Req->UserBuffer && Req->BufferLength >= sizeof(CSC_DATABASE_INFO)) {
            Status = CscStoreQueryDatabase((PCSC_DATABASE_INFO)Req->UserBuffer);
            if (NT_SUCCESS(Status)) {
                *BytesReturned = sizeof(CSC_DATABASE_INFO);
            }
        }
        break;

    case CSC_FSCTL_OPERATION_SET_PIN:
        Status = CscStoreSetPin(Req->SubOpCode, Req->Flags);
        break;

    case CSC_FSCTL_OPERATION_EVICT_ITEM:
        Status = CscStoreEvictItem(Req->SubOpCode);
        break;

    case CSC_FSCTL_OPERATION_SET_SECURITY:
        Status = CscSetSecurity(Req->SubOpCode, Req->UserBuffer, Req->BufferLength);
        break;

    default:
        Status = STATUS_NOT_SUPPORTED;
        break;
    }

    return Status;
}

NTSTATUS CscProcessFsctl(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp)
{
    ULONG FsControlCode = IrpSp->Parameters.FileSystemControl.FsControlCode;
    ULONG InputBufferLength = IrpSp->Parameters.FileSystemControl.InputBufferLength;
    ULONG OutputBufferLength = IrpSp->Parameters.FileSystemControl.OutputBufferLength;
    PVOID Type3InputBuffer = IrpSp->Parameters.FileSystemControl.Type3InputBuffer;
    PVOID UserBuffer = Irp->UserBuffer;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR Information = 0;

    switch (FsControlCode) {
    case FSCTL_CSC_INTERNAL: // 0x001401A3 (METHOD_NEITHER)
        // VULNERABLE (CVE-2024-26229): Direct access to user-supplied METHOD_NEITHER buffers
        Status = CscHandleInternalFsctl(
            Type3InputBuffer,
            InputBufferLength,
            UserBuffer,
            OutputBufferLength,
            &Information
        );
        break;

    case FSCTL_CSC_FINALIZE_CONNECTION: // 0x001401AC (METHOD_BUFFERED)
        Information = 0;
        Status = STATUS_SUCCESS;
        break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
