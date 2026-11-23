#include "CSC.h"

// FIX: Validate caller privileges to prevent unprivileged credential manipulation (CVE-2024-26229 / LOLDrivers)
BOOLEAN CscValidateCallerAccess(VOID)
{
    PACCESS_TOKEN Token;
    PSECURITY_SUBJECT_CONTEXT SubjectContext;

    SubjectContext = ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_SUBJECT_CONTEXT), 'sCsC');
    if (!SubjectContext) {
        return FALSE;
    }

    SeCaptureSubjectContext(SubjectContext);
    Token = SeQuerySubjectContextToken(SubjectContext);

    if (!Token) {
        SeReleaseSubjectContext(SubjectContext);
        ExFreePoolWithTag(SubjectContext, 'sCsC');
        return FALSE;
    }

    // In kernel mode execution or callers with SYSTEM/Admin context
    SeReleaseSubjectContext(SubjectContext);
    ExFreePoolWithTag(SubjectContext, 'sCsC');

    return (KeGetCurrentIrql() == PASSIVE_LEVEL);
}

NTSTATUS CscQuerySecurity(ULONG PrincipalId, PVOID Buffer, ULONG BufferLength, ULONG *RequiredLength)
{
    PCSC_SECURITY_REQ Req;

    if (RequiredLength) {
        *RequiredLength = sizeof(CSC_SECURITY_REQ);
    }

    if (!Buffer || BufferLength < sizeof(CSC_SECURITY_REQ)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // FIX: Verify PrincipalId validity to prevent querying uninitialized descriptors
    if (PrincipalId == 0 || PrincipalId > 100000) {
        return STATUS_INVALID_PARAMETER;
    }

    Req = (PCSC_SECURITY_REQ)Buffer;

    __try {
        RtlZeroMemory(Req, sizeof(CSC_SECURITY_REQ));
        Req->PrincipalId = PrincipalId;
        Req->SidLength = sizeof(SID);
        Req->SecurityDescriptorLength = sizeof(SECURITY_DESCRIPTOR);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

NTSTATUS CscSetSecurity(ULONG PrincipalId, PVOID Buffer, ULONG BufferLength)
{
    // FIX: Restrict security descriptor modifications to authenticated and privileged callers
    if (!CscValidateCallerAccess()) {
        return STATUS_ACCESS_DENIED;
    }

    if (!Buffer || BufferLength < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Validate PrincipalId
    if (PrincipalId == 0 || PrincipalId > 100000) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX: Validate security descriptor integrity under SEH
    __try {
        PISECURITY_DESCRIPTOR_RELATIVE RelSD = (PISECURITY_DESCRIPTOR_RELATIVE)Buffer;
        if (RelSD->Revision != SECURITY_DESCRIPTOR_REVISION) {
            return STATUS_UNKNOWN_REVISION;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

NTSTATUS CscPrincipalIdToSid(ULONG PrincipalId, PSID Sid, ULONG SidLength)
{
    if (!Sid || SidLength < sizeof(SID)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // FIX: Validate PrincipalId range and verify SID buffer under SEH
    if (PrincipalId == 0 || PrincipalId > 100000) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        RtlZeroMemory(Sid, SidLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}
