#include <ntifs.h>
#include <windef.h>
#include <initguid.h>
#include "CSC.h"

PDEVICE_OBJECT g_CscDeviceObject = NULL;

VOID CscUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymlinkName;
    UNREFERENCED_PARAMETER(DriverObject);

    RtlInitUnicodeString(&SymlinkName, CSC_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&SymlinkName);

    if (g_CscDeviceObject) {
        IoDeleteDevice(g_CscDeviceObject);
        g_CscDeviceObject = NULL;
    }
}

NTSTATUS CscCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS CscDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    ULONG IoControlCode;
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    PVOID Buffer;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!Irp) {
        return STATUS_INVALID_PARAMETER;
    }

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    if (!IrpSp) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    Buffer = Irp->AssociatedIrp.SystemBuffer;

    // FIX: Wrap IOCTL dispatch in SEH to guard against unhandled memory faults and invalid buffers
    __try {
        switch (IoControlCode) {
        case IOCTL_CSC_USER_QUERY_ITEM:
            if (Buffer && InputBufferLength >= sizeof(ULONG) && OutputBufferLength >= sizeof(CSC_STORE_ITEM_INFO)) {
                ULONG ItemId = *(PULONG)Buffer;
                Status = CscStoreQueryItem(ItemId, (PCSC_STORE_ITEM_INFO)Buffer);
                if (NT_SUCCESS(Status)) {
                    Information = sizeof(CSC_STORE_ITEM_INFO);
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_CSC_USER_QUERY_DATABASE:
            if (Buffer && OutputBufferLength >= sizeof(CSC_DATABASE_INFO)) {
                Status = CscStoreQueryDatabase((PCSC_DATABASE_INFO)Buffer);
                if (NT_SUCCESS(Status)) {
                    Information = sizeof(CSC_DATABASE_INFO);
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_CSC_USER_SET_PIN:
            if (Buffer && InputBufferLength >= sizeof(CSC_PIN_REQ)) {
                PCSC_PIN_REQ PinReq = (PCSC_PIN_REQ)Buffer;
                Status = CscStoreSetPin(PinReq->ItemId, PinReq->PinFlags);
                if (NT_SUCCESS(Status)) {
                    Information = sizeof(CSC_PIN_REQ);
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        case IOCTL_CSC_USER_QUERY_SECURITY:
            if (Buffer && InputBufferLength >= sizeof(ULONG)) {
                ULONG PrincipalId = *(PULONG)Buffer;
                ULONG RequiredLength = 0;
                Status = CscQuerySecurity(PrincipalId, Buffer, OutputBufferLength, &RequiredLength);
                if (NT_SUCCESS(Status)) {
                    Information = RequiredLength;
                }
            } else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        Information = 0;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS CscFileSystemControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (!Irp) {
        return STATUS_INVALID_PARAMETER;
    }

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    if (!IrpSp) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Wrap FileSystemControl dispatch in SEH to guard against unhandled exceptions
    __try {
        return CscProcessFsctl(Irp, IrpSp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Irp->IoStatus.Status = GetExceptionCode();
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return GetExceptionCode();
    }
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymlinkName;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = CscUnload;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = CscCreateClose;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]              = CscCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]               = CscCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]      = CscDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = CscFileSystemControl;

    UNICODE_STRING Sddl;

    RtlInitUnicodeString(&DeviceName, CSC_DEVICE_NAME);
    RtlInitUnicodeString(&SymlinkName, CSC_DOS_DEVICE_NAME);

    // FIX: Secure device creation to mitigate unprivileged access (LOLDrivers: CSC.sys, CVE-2024-26229 / 1c92e1bf-103b-4545-b242-e5a9858ec9c8)
    // SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA) - Only SYSTEM and Administrators have access
    RtlInitUnicodeString(&Sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    Status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &DeviceName,
        CSC_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &Sddl,
        &GUID_DEVCLASS_CSC,
        &g_CscDeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        // FIX: Clean up device object on symbolic link creation failure to prevent resource leak
        IoDeleteDevice(g_CscDeviceObject);
        g_CscDeviceObject = NULL;
        return Status;
    }

    g_CscDeviceObject->Flags |= DO_BUFFERED_IO;
    g_CscDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
