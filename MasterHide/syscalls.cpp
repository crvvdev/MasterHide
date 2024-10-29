#include "includes.hpp"

namespace masterhide
{
namespace syscalls
{
/// <summary>
/// Dynamic hash table pointer
/// </summary>
PRTL_DYNAMIC_HASH_TABLE g_hashTable = nullptr;

/// <summary>
/// Dynamic hash table context
/// </summary>
RTL_DYNAMIC_HASH_TABLE_CONTEXT g_hashTableContext{};

inline bool g_initialized = false;

typedef struct _SYSCALL_TABLE_ENTRY
{
    USHORT serviceIndex;
    RTL_DYNAMIC_HASH_TABLE_ENTRY hashTableEntry;

} SYSCALL_TABLE_ENTRY, *PSYSCALL_TABLE_ENTRY;

/// <summary>
/// This function will try to map and extract syscalls from provided file name and finally add them to dynamic hash
/// table if possible.
/// </summary>
/// <param name="fileName">File name to extract syscalls from</param>
/// <returns>NTSTATUS value</returns>
static NTSTATUS FillSyscallTable(_In_ PUNICODE_STRING fileName)
{
    PVOID mappedBase = nullptr;
    SIZE_T mappedSize = 0;

    NTSTATUS status = tools::MapFileInSystemSpace(fileName, &mappedBase, &mappedSize);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to map %wZ into system space!", fileName);
        return STATUS_UNSUCCESSFUL;
    }

    SCOPE_EXIT
    {
        MmUnmapViewInSystemSpace(mappedBase);
    };

    __try
    {
        PIMAGE_NT_HEADERS nth = nullptr;

        status = RtlImageNtHeaderEx(0, mappedBase, mappedSize, &nth);
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "RtlImageNtHeaderEx returned %!STATUS!", status);
            return STATUS_UNSUCCESSFUL;
        }

        ULONG exportDirSize = 0;

        const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            RtlImageDirectoryEntryToData(mappedBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportDirSize));
        if (!exportDirectory)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Invalid image export directory!");
            return STATUS_UNSUCCESSFUL;
        }

        auto moduleBase = reinterpret_cast<PUCHAR>(mappedBase);

        const PULONG addressOfNames = reinterpret_cast<PULONG>(moduleBase + exportDirectory->AddressOfNames);
        const PUSHORT addressOfNameOrdinals =
            reinterpret_cast<PUSHORT>(moduleBase + exportDirectory->AddressOfNameOrdinals);
        const PULONG addressOfFunctions = reinterpret_cast<PULONG>(moduleBase + exportDirectory->AddressOfFunctions);

        for (auto i = 0ul; i < exportDirectory->NumberOfNames; i++)
        {
            auto exportName = reinterpret_cast<LPCSTR>(moduleBase + addressOfNames[i]);
            auto procedureAddress = reinterpret_cast<PUCHAR>(moduleBase + addressOfFunctions[addressOfNameOrdinals[i]]);

            auto IsSyscall = [&]() -> BOOLEAN {
                return (procedureAddress[0] == 0x4C && procedureAddress[1] == 0x8B && procedureAddress[2] == 0xD1 &&
                        procedureAddress[3] == 0xB8);
            };

            // Check if the export is possibly a syscall
            if (IsSyscall())
            {
                ULONG64 functionData = *(ULONG64 *)procedureAddress;
                ULONG syscallNum = (functionData >> 8 * 4);
                syscallNum = syscallNum & 0xfff;

                // Allocate new entry and insert to hash table.
                auto entry = tools::AllocatePoolZero<PSYSCALL_TABLE_ENTRY>(NonPagedPool, sizeof(SYSCALL_TABLE_ENTRY),
                                                                           tags::TAG_HASH_TABLE_ENTRY);
                if (entry)
                {
                    const FNV1A_t serviceHash = FNV1A::Hash(exportName);
                    entry->serviceIndex = static_cast<USHORT>(syscallNum);

                    WppTracePrint(TRACE_LEVEL_VERBOSE, SYSCALLS, "serviceName: %s serviceIndex: %d serviceHash: %lld",
                                  exportName, syscallNum, serviceHash);

                    InitializeListHead(&entry->hashTableEntry.Linkage);
                    RtlInsertEntryHashTable(g_hashTable, &entry->hashTableEntry, ULONG_PTR(serviceHash),
                                            &g_hashTableContext);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Exception trying to parse PE %!STATUS!", status);
    }

    return status;
}

NTSTATUS Initialize()
{
    PAGED_CODE();
    NT_ASSERT(!g_initialized);

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    g_hashTable = tools::AllocatePoolZero<PRTL_DYNAMIC_HASH_TABLE>(NonPagedPool, sizeof(RTL_DYNAMIC_HASH_TABLE),
                                                                   tags::TAG_HASH_TABLE);
    if (!g_hashTable)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for dynamic hash table!");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!RtlCreateHashTable(&g_hashTable, 0, 0))
    {
        ExFreePool(g_hashTable);
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to create dynamic hash table!");
        return STATUS_UNSUCCESSFUL;
    }

    RtlInitHashTableContext(&g_hashTableContext);

    NTSTATUS status = FillSyscallTable(&g_NtdllPath);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(g_hashTable);
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to fill ntdll.dll syscall table!");
        return STATUS_UNSUCCESSFUL;
    }

    status = FillSyscallTable(&g_Win32UPath);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(g_hashTable);
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to fill win32u.dll syscall table!");
        return STATUS_UNSUCCESSFUL;
    }

    g_initialized = true;

    return STATUS_SUCCESS;
}

void Deinitialize()
{
    PAGED_CODE();

    if (!g_initialized)
    {
        return;
    }

    RTL_DYNAMIC_HASH_TABLE_ENUMERATOR hashTableEnumerator{};

    if (RtlInitEnumerationHashTable(g_hashTable, &hashTableEnumerator))
    {
        while (true)
        {
            PRTL_DYNAMIC_HASH_TABLE_ENTRY hashTableEntry =
                RtlEnumerateEntryHashTable(g_hashTable, &hashTableEnumerator);
            if (!hashTableEntry)
            {
                break;
            }

            RtlRemoveEntryHashTable(g_hashTable, hashTableEntry, &g_hashTableContext);

            PSYSCALL_TABLE_ENTRY entry = CONTAINING_RECORD(hashTableEntry, SYSCALL_TABLE_ENTRY, hashTableEntry);
            ExFreePool(entry);
        }
        RtlEndEnumerationHashTable(g_hashTable, &hashTableEnumerator);
    }

    RtlDeleteHashTable(g_hashTable);
    RtlReleaseHashTableContext(&g_hashTableContext);
    ExFreePool(g_hashTable);

    g_initialized = false;

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Successfully de-initialized syscalls interface!");
    return;
}

USHORT GetSyscallIndexByName(_In_ LPCSTR serviceName)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);

    USHORT serviceIndex = MAXUSHORT;
    FNV1A_t signature = FNV1A::Hash(serviceName);

    RTL_DYNAMIC_HASH_TABLE_ENUMERATOR hashTableEnumerator{};
    if (RtlInitEnumerationHashTable(g_hashTable, &hashTableEnumerator))
    {
        while (true)
        {
            PRTL_DYNAMIC_HASH_TABLE_ENTRY hashTableEntry =
                RtlEnumerateEntryHashTable(g_hashTable, &hashTableEnumerator);
            if (!hashTableEntry)
            {
                break;
            }

            if (hashTableEntry->Signature == signature)
            {
                PSYSCALL_TABLE_ENTRY entry = CONTAINING_RECORD(hashTableEntry, SYSCALL_TABLE_ENTRY, hashTableEntry);
                serviceIndex = entry->serviceIndex;
                break;
            }
        }
        RtlEndEnumerationHashTable(g_hashTable, &hashTableEnumerator);
    }

    if (serviceIndex == MAXUSHORT)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Service %s not found in hash table list!", serviceName);
    }

    return serviceIndex;
}
} // namespace syscalls
} // namespace masterhide