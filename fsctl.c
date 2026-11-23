#include "CSC.h"

// FIX: Validate user buffer addresses, boundary constraints, and memory accessibility (CVE-2024-26229 / LOLDrivers: CSC.sys)
NTSTATUS CscValidateUserBuffer(PVOID Buffer, SIZE_T Length, BOOLEAN WriteAccess)
{
    if (!Buffer || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Ensure the address range is entirely within user-mode address space
    if ((ULONG_PTR)Buffer + Length < (ULONG_PTR)Buffer ||
        (ULONG_PTR)Buffer + Length > (ULONG_PTR)MmHighestUserAddress) {
        return STATUS_ACCESS_VIOLATION;
    }

    __try {
        if (WriteAccess) {
            ProbeForWrite(Buffer, Length, sizeof(UCHAR));
        } else {
            ProbeForRead(Buffer, Length, sizeof(UCHAR));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

NTSTATUS CscHandleInternalFsctl(
    PVOID InputBuffer,
    ULONG InputLength,
    PVOID OutputBuffer,
    ULONG OutputLength,
    ULONG_PTR *BytesReturned
)
{
    CSC_INTERNAL_REQUEST SafeReq;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputLength);

    if (!InputBuffer || InputLength < sizeof(CSC_INTERNAL_REQUEST)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // FIX (CVE-2024-26229): Validate METHOD_NEITHER input buffer before accessing
    Status = CscValidateUserBuffer(InputBuffer, sizeof(CSC_INTERNAL_REQUEST), FALSE);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    __try {
        RtlCopyMemory(&SafeReq, InputBuffer, sizeof(CSC_INTERNAL_REQUEST));

        switch (SafeReq.OpCode) {
        case CSC_FSCTL_OPERATION_QUERY_HANDLE:
            if (SafeReq.UserBuffer && SafeReq.BufferLength >= sizeof(ULONG)) {
                Status = CscValidateUserBuffer(SafeReq.UserBuffer, sizeof(ULONG), TRUE);
                if (NT_SUCCESS(Status)) {
                    *(PULONG)SafeReq.UserBuffer = 0x1000;
                    *BytesReturned = sizeof(ULONG);
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case CSC_FSCTL_OPERATION_QUERY_ITEM:
            if (SafeReq.UserBuffer && SafeReq.BufferLength >= sizeof(CSC_STORE_ITEM_INFO)) {
                Status = CscValidateUserBuffer(SafeReq.UserBuffer, sizeof(CSC_STORE_ITEM_INFO), TRUE);
                if (NT_SUCCESS(Status)) {
                    Status = CscStoreQueryItem(SafeReq.SubOpCode, (PCSC_STORE_ITEM_INFO)SafeReq.UserBuffer);
                    if (NT_SUCCESS(Status)) {
                        *BytesReturned = sizeof(CSC_STORE_ITEM_INFO);
                    }
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case CSC_FSCTL_OPERATION_QUERY_DATABASE:
            if (SafeReq.UserBuffer && SafeReq.BufferLength >= sizeof(CSC_DATABASE_INFO)) {
                Status = CscValidateUserBuffer(SafeReq.UserBuffer, sizeof(CSC_DATABASE_INFO), TRUE);
                if (NT_SUCCESS(Status)) {
                    Status = CscStoreQueryDatabase((PCSC_DATABASE_INFO)SafeReq.UserBuffer);
                    if (NT_SUCCESS(Status)) {
                        *BytesReturned = sizeof(CSC_DATABASE_INFO);
                    }
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case CSC_FSCTL_OPERATION_SET_PIN:
            Status = CscStoreSetPin(SafeReq.SubOpCode, SafeReq.Flags);
            break;

        case CSC_FSCTL_OPERATION_EVICT_ITEM:
            Status = CscStoreEvictItem(SafeReq.SubOpCode);
            break;

        case CSC_FSCTL_OPERATION_SET_SECURITY:
            if (SafeReq.UserBuffer && SafeReq.BufferLength > 0) {
                Status = CscValidateUserBuffer(SafeReq.UserBuffer, SafeReq.BufferLength, FALSE);
                if (NT_SUCCESS(Status)) {
                    Status = CscSetSecurity(SafeReq.SubOpCode, SafeReq.UserBuffer, SafeReq.BufferLength);
                }
            } else {
                Status = STATUS_INVALID_PARAMETER;
            }
            break;

        default:
            Status = STATUS_NOT_SUPPORTED;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
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
        // FIX (CVE-2024-26229): Guarded METHOD_NEITHER handler with probe and address validation
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
