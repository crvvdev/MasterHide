#include "includes.hpp"

namespace masterhide
{
namespace syscalls
{
UNICODE_STRING g_NtdllPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
UNICODE_STRING g_Win32UPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\win32u.dll");

bool g_initialized = false;

/// <summary>
/// Dynamic hash table pointer
/// </summary>
PRTL_DYNAMIC_HASH_TABLE g_hashTable = nullptr;

/// <summary>
/// Dynamic hash table context
/// </summary>
RTL_DYNAMIC_HASH_TABLE_CONTEXT g_hashTableContext{};

void ClearAndDeleteHashTable();

typedef struct _SYSCALL_TABLE_ENTRY
{
    RTL_DYNAMIC_HASH_TABLE_ENTRY hashTableEntry;
    USHORT serviceIndex;

} SYSCALL_TABLE_ENTRY, *PSYSCALL_TABLE_ENTRY;

/// <summary>
/// This function will try to map and extract syscalls from provided file name and finally add them to dynamic hash
/// table if possible.
/// </summary>
/// <param name="fileName">File name to extract syscalls from</param>
/// <returns>NTSTATUS value</returns>
static NTSTATUS FillSyscallTable(_In_ PUNICODE_STRING fileName, _In_ bool win32k = false)
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
        PIMAGE_NT_HEADERS nth = RtlImageNtHeader(mappedBase);
        if (!nth)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Invalid NT header!");
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

        const auto addressOfNames = reinterpret_cast<PULONG>(moduleBase + exportDirectory->AddressOfNames);
        const auto addressOfNameOrdinals =
            reinterpret_cast<PUSHORT>(moduleBase + exportDirectory->AddressOfNameOrdinals);
        const auto addressOfFunctions = reinterpret_cast<PULONG>(moduleBase + exportDirectory->AddressOfFunctions);

        for (auto i = 0ul; i < exportDirectory->NumberOfNames; i++)
        {
            auto exportName = reinterpret_cast<LPCSTR>(moduleBase + addressOfNames[i]);
            auto procedureAddress = reinterpret_cast<PUCHAR>(moduleBase + addressOfFunctions[addressOfNameOrdinals[i]]);

            auto IsSyscall = [&]() -> BOOLEAN {
                return (procedureAddress[0] == 0x4C && procedureAddress[1] == 0x8B && procedureAddress[2] == 0xD1 &&
                        procedureAddress[3] == 0xB8);
            };

            // Check if the export is possibly a syscall
            if (strlen(exportName) > 2 && (exportName[0] == 'N' && exportName[1] == 't') && IsSyscall())
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
                    entry->serviceIndex =
                        win32k ? static_cast<USHORT>(syscallNum) + 0x1000 : static_cast<USHORT>(syscallNum);

                    InitializeListHead(&entry->hashTableEntry.Linkage);
                    RtlInsertEntryHashTable(g_hashTable, &entry->hashTableEntry, serviceHash, &g_hashTableContext);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Exception on FillSyscallTable %!STATUS!", status);
    }

    return status;
}

struct WIN32K_TABLE
{
    char Name[64];
    USHORT Index;

    WIN32K_TABLE(const char *name, USHORT index) : Index(index)
    {
        strcpy(Name, name);
    }
};

void FillWin32SyscallTableLegacy()
{
    USHORT NtUserWindowFromPoint = MAXUSHORT;
    USHORT NtUserQueryWindow = MAXUSHORT;
    USHORT NtUserFindWindowEx = MAXUSHORT;
    USHORT NtUserBuildHwndList = MAXUSHORT;
    USHORT NtUserGetForegroundWindow = MAXUSHORT;
    USHORT NtUserGetThreadState = MAXUSHORT;

    switch (KERNEL_BUILD_VERSION)
    {
    case WINDOWS_7_SP1:
        NtUserWindowFromPoint = 0x1014;
        NtUserQueryWindow = 0x1010;
        NtUserFindWindowEx = 0x106e;
        NtUserBuildHwndList = 0x101c;
        NtUserGetForegroundWindow = 0x103c;
        NtUserGetThreadState = 0x1000;
        break;
    case WINDOWS_8:
        NtUserWindowFromPoint = 4117;
        NtUserQueryWindow = 4113;
        NtUserFindWindowEx = 4206;
        NtUserBuildHwndList = 4125;
        NtUserGetForegroundWindow = 4157;
        NtUserGetThreadState = 4097;
        break;
    case WINDOWS_8_1:
        NtUserWindowFromPoint = 5130;
        NtUserQueryWindow = 4114;
        NtUserFindWindowEx = 4206;
        NtUserBuildHwndList = 4207;
        NtUserGetForegroundWindow = 4158;
        NtUserGetThreadState = 4098;
        break;
    }

    const WIN32K_TABLE win32kTable[] = {{"NtUserWindowFromPoint", NtUserWindowFromPoint},
                                        {"NtUserQueryWindow", NtUserQueryWindow},
                                        {"NtUserFindWindowEx", NtUserFindWindowEx},
                                        {"NtUserBuildHwndList", NtUserBuildHwndList},
                                        {"NtUserGetForegroundWindow", NtUserGetForegroundWindow},
                                        {"NtUserGetThreadState", NtUserGetThreadState}};

    for (auto &tableEntry : win32kTable)
    {
        auto entry = tools::AllocatePoolZero<PSYSCALL_TABLE_ENTRY>(NonPagedPool, sizeof(SYSCALL_TABLE_ENTRY),
                                                                   tags::TAG_HASH_TABLE_ENTRY);
        if (entry)
        {
            FNV1A_t serviceHash = FNV1A::Hash(tableEntry.Name);
            entry->serviceIndex = tableEntry.Index;

            InitializeListHead(&entry->hashTableEntry.Linkage);
            RtlInsertEntryHashTable(g_hashTable, &entry->hashTableEntry, serviceHash, &g_hashTableContext);
        }
    }
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

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to create hash table!");
        return STATUS_UNSUCCESSFUL;
    }

    RtlInitHashTableContext(&g_hashTableContext);

    NTSTATUS status = FillSyscallTable(&g_NtdllPath);
    if (!NT_SUCCESS(status))
    {
        ClearAndDeleteHashTable();

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to fill ntdll.dll syscall table!");
        return STATUS_UNSUCCESSFUL;
    }

    // win32u.dll is only exported starting Windows 10
    //
    if (KERNEL_BUILD_VERSION > WINDOWS_8_1)
    {
        status = FillSyscallTable(&g_Win32UPath, true);
        if (!NT_SUCCESS(status))
        {
            ClearAndDeleteHashTable();

            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to fill win32u.dll syscall table!");
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        FillWin32SyscallTableLegacy();
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

    ClearAndDeleteHashTable();
    g_initialized = false;

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Successfully de-initialized syscalls interface!");
    return;
}

void ClearAndDeleteHashTable()
{
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
        NT_ASSERT(FALSE);
    }

    return serviceIndex;
}
} // namespace syscalls
} // namespace masterhide