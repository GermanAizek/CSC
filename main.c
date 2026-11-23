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
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

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

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS CscFileSystemControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    UNREFERENCED_PARAMETER(DeviceObject);

    return CscProcessFsctl(Irp, IrpSp);
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

    RtlInitUnicodeString(&DeviceName, CSC_DEVICE_NAME);
    RtlInitUnicodeString(&SymlinkName, CSC_DOS_DEVICE_NAME);

    // Initial open implementation: insecure device creation without DACL
    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        CSC_DEVICE_TYPE,
        0,
        FALSE,
        &g_CscDeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    g_CscDeviceObject->Flags |= DO_BUFFERED_IO;
    g_CscDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
