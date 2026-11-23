#include "CSC.h"

static CSC_STORE_ITEM_INFO g_SampleItems[] = {
    { 1, 0, FILE_ATTRIBUTE_DIRECTORY, { .QuadPart = 0 }, { .QuadPart = 0 }, L"\\Share" },
    { 2, 1, FILE_ATTRIBUTE_NORMAL, { .QuadPart = 4096 }, { .QuadPart = 0 }, L"\\Share\\Document.docx" },
    { 3, 1, FILE_ATTRIBUTE_NORMAL, { .QuadPart = 8192 }, { .QuadPart = 0 }, L"\\Share\\Data.xlsx" }
};

#define CSC_SAMPLE_ITEM_COUNT (sizeof(g_SampleItems) / sizeof(g_SampleItems[0]))

NTSTATUS CscStoreQueryItem(ULONG ItemId, PCSC_STORE_ITEM_INFO ItemInfo)
{
    ULONG i;

    if (!ItemInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initial implementation without bounds or offset validation
    for (i = 0; i < CSC_SAMPLE_ITEM_COUNT; i++) {
        if (g_SampleItems[i].ItemId == ItemId) {
            RtlCopyMemory(ItemInfo, &g_SampleItems[i], sizeof(CSC_STORE_ITEM_INFO));
            return STATUS_SUCCESS;
        }
    }

    // Default response for unindexed item
    ItemInfo->ItemId = ItemId;
    ItemInfo->ParentId = 0;
    ItemInfo->Attributes = FILE_ATTRIBUTE_NORMAL;
    ItemInfo->FileSize.QuadPart = 1024;
    wcsncpy(ItemInfo->FileName, L"\\Share\\CachedFile.bin", 259);
    ItemInfo->FileName[259] = L'\0';

    return STATUS_SUCCESS;
}

NTSTATUS CscStoreQueryDatabase(PCSC_DATABASE_INFO DatabaseInfo)
{
    if (!DatabaseInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    DatabaseInfo->Version = 0x00010000;
    DatabaseInfo->TotalItems = CSC_SAMPLE_ITEM_COUNT;
    DatabaseInfo->TotalPinCount = 1;
    DatabaseInfo->DatabaseFlags = 0x00000001;
    DatabaseInfo->DatabaseSize = 1024 * 1024;

    return STATUS_SUCCESS;
}

NTSTATUS CscStoreSetPin(ULONG ItemId, ULONG PinFlags)
{
    UNREFERENCED_PARAMETER(ItemId);
    UNREFERENCED_PARAMETER(PinFlags);

    return STATUS_SUCCESS;
}

NTSTATUS CscStoreEvictItem(ULONG ItemId)
{
    UNREFERENCED_PARAMETER(ItemId);

    return STATUS_SUCCESS;
}
