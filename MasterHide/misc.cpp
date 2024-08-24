﻿#include "includes.hpp"

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
    NT_ASSERT(g_initialized);

    PVOID mappedBase = nullptr;
    SIZE_T mappedSize = 0;

    NTSTATUS status = tools::MapFileInSystemSpace(fileName, &mappedBase, &mappedSize);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: Failed to map %wZ to system space!", fileName);
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
            DBGPRINT("Err: Invalid file NT header!");
            return STATUS_UNSUCCESSFUL;
        }

        const PIMAGE_DATA_DIRECTORY exportDataDirectory =
            &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!exportDataDirectory->VirtualAddress || !exportDataDirectory->Size)
        {
            DBGPRINT("Err: Invalid file export data directory!");
            return STATUS_UNSUCCESSFUL;
        }

        PUCHAR moduleBase = reinterpret_cast<PUCHAR>(mappedBase);

        const PIMAGE_EXPORT_DIRECTORY exportDirectory =
            tools::RVAtoRawAddress<PIMAGE_EXPORT_DIRECTORY>(nth, exportDataDirectory->VirtualAddress, moduleBase);

        const PULONG AddressOfNames = tools::RVAtoRawAddress<PULONG>(nth, exportDirectory->AddressOfNames, moduleBase);
        const PUSHORT AddressOfNameOrdinals =
            tools::RVAtoRawAddress<PUSHORT>(nth, exportDirectory->AddressOfNameOrdinals, moduleBase);
        const PULONG AddressOfFunctions =
            tools::RVAtoRawAddress<PULONG>(nth, exportDirectory->AddressOfFunctions, moduleBase);

        for (auto i = 0ul; i < exportDirectory->NumberOfNames; i++)
        {
            auto routineName = tools::RVAtoRawAddress<LPCSTR>(nth, AddressOfNames[i], moduleBase);
            auto routineAddress =
                tools::RVAtoRawAddress<PUCHAR>(nth, AddressOfFunctions[AddressOfNameOrdinals[i]], moduleBase);

            auto IsSyscall = [&]() -> BOOLEAN {
                return (routineAddress[0] == 0x4C && routineAddress[1] == 0x8B && routineAddress[2] == 0xD1 &&
                        routineAddress[3] == 0xB8);
            };

            // Check if the export is possibly a syscall
            if (IsSyscall())
            {
                ULONG64 functionData = *(ULONG64 *)routineAddress;
                ULONG syscallNum = (functionData >> 8 * 4);
                syscallNum = syscallNum & 0xfff;

                // Allocate new entry and insert to hash table.
                auto entry = tools::AllocatePoolZero<PSYSCALL_TABLE_ENTRY>(NonPagedPool, sizeof(SYSCALL_TABLE_ENTRY),
                                                                           tags::TAG_HASH_TABLE);
                if (entry)
                {
                    const FNV1A_t serviceHash = FNV1A::Hash(routineName);
                    entry->serviceIndex = static_cast<USHORT>(syscallNum);

                    InitializeListHead(&(entry->hashTableEntry.Linkage));
                    RtlInsertEntryHashTable(g_hashTable, &entry->hashTableEntry, ULONG_PTR(serviceHash),
                                            &g_hashTableContext);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBGPRINT("Err: Exception while trying to parse PE file!");

        status = GetExceptionCode();
    }

    return status;
}

bool Init()
{
    g_hashTable = tools::AllocatePoolZero<PRTL_DYNAMIC_HASH_TABLE>(NonPagedPool, sizeof(RTL_DYNAMIC_HASH_TABLE),
                                                                   tags::TAG_HASH_TABLE);
    if (!g_hashTable)
    {
        DBGPRINT("Err: Failed to allocate memory for dynamic hash table!");
        return false;
    }

    if (!RtlCreateHashTable(&g_hashTable, 0, 0))
    {
        ExFreePool(g_hashTable);
        DBGPRINT("Err: Failed to create dynamic hash table!");
        return false;
    }

    RtlInitHashTableContext(&g_hashTableContext);

    g_initialized = true;

    UNICODE_STRING ntdll = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
    UNICODE_STRING win32u = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\win32u.dll");

    FillSyscallTable(&ntdll);
    FillSyscallTable(&win32u);

    return true;
}

void Destroy()
{
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

    g_initialized = false;
}

USHORT GetSyscallIndexByName(_In_ LPCSTR serviceName)
{
    NT_ASSERT(g_initialized);

    USHORT serviceIndex = USHORT(-1);
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

    if (serviceIndex == USHORT(-1))
    {
        DBGPRINT("Service %s not found in hash table list!", serviceName);
    }

    return serviceIndex;
}
} // namespace syscalls

namespace tools
{
bool GetProcessFileName(_In_ PEPROCESS process, _Out_ PUNICODE_STRING processImageName)
{
    NT_ASSERT(processImageName);

    HANDLE processHandle{};

    NTSTATUS status = ObOpenObjectByPointer(process, 0, NULL, 0, 0, KernelMode, &processHandle);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: ObOpenObjectByPointer returned 0x%08X", status);
        return false;
    }

    SCOPE_EXIT
    {
        ZwClose(processHandle);
    };

    ULONG returnedLength = 0;

    status = ZwQueryInformationProcess(processHandle, ProcessImageFileName, nullptr, 0, &returnedLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        DBGPRINT("Err: ZwQueryInformationProcess returned 0x%08X", status);
        return false;
    }

    returnedLength *= (1 << 8);

    void *buffer = tools::AllocatePoolZero(NonPagedPool, returnedLength, tags::TAG_DEFAULT);
    if (!buffer)
    {
        DBGPRINT("Err: Failed to allocate %d bytes for ZwQueryInformationProcess", returnedLength);
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(buffer);
    };

    status = ZwQueryInformationProcess(processHandle, ProcessImageFileName, buffer, returnedLength, &returnedLength);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: ZwQueryInformationProcess[1] returned 0x%08X", status);
        return false;
    }

    processImageName->Length = 0;
    processImageName->MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
    processImageName->Buffer =
        tools::AllocatePoolZero<PWCH>(NonPagedPool, processImageName->MaximumLength, tags::TAG_DEFAULT);
    if (!processImageName->Buffer)
    {
        DBGPRINT("Err: Failed to allocate memory for process image file name");
        return false;
    }

    auto imageName = reinterpret_cast<PCUNICODE_STRING>(buffer);
    RtlCopyUnicodeString(processImageName, imageName);

    return true;
}

bool GetProcessFileName(_In_ HANDLE processId, _Out_ PUNICODE_STRING processImageName)
{
    NT_ASSERT(processImageName);

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(processId, &process);
    if (!NT_SUCCESS(status))
    {
        return false;
    }

    const bool result = GetProcessFileName(process, processImageName);
    ObDereferenceObject(process);

    return result;
}

PEPROCESS GetProcessByName(_In_ LPCWSTR processName)
{
    NT_ASSERT(processName);

    for (ULONG i = 4;   // Ignore system process
         i < 0xFFFFFFF; // Try to go tru all possible PIDs
         i += sizeof(ULONG))
    {
        PEPROCESS process = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(UlongToHandle(i), &process)))
        {
            continue;
        }

        UNICODE_STRING processFileName{};
        if (!GetProcessFileName(process, &processFileName))
        {
            ObDereferenceObject(process);
            continue;
        }

        SCOPE_EXIT
        {
            RtlFreeUnicodeString(&processFileName);
        };

        // safe operation because GetProcessFileName returns a null terminated string.
        PWSTR moduleName = wcsrchr(processFileName.Buffer, L'\\');
        if (moduleName)
        {
            ++moduleName;

            if (!wcscmp(moduleName, processName))
            {
                // Process was found.
                return process;
            }
        }

        ObDereferenceObject(process);
    }
    return nullptr;
}

bool DumpMZ(PUCHAR pImageBase)
{
    __try
    {
        if (!pImageBase)
        {
            DBGPRINT("[ DumpMZ ] Invalid image base!\n");
            return false;
        }

        ProbeForRead(pImageBase, sizeof(pImageBase), __alignof(pImageBase));

        PIMAGE_DOS_HEADER dos = PIMAGE_DOS_HEADER(pImageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            DBGPRINT("[ DumpMZ ] Invalid DOS signature!\n");
            return false;
        }

        PIMAGE_NT_HEADERS32 nt32 = PIMAGE_NT_HEADERS32(pImageBase + dos->e_lfanew);
        if (nt32->Signature != IMAGE_NT_SIGNATURE)
        {
            DBGPRINT("[ DumpMZ ] Invalid NT signature!\n");
            return false;
        }

        ULONG uImageSize = NULL;

        if (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        {
            uImageSize = nt32->OptionalHeader.SizeOfImage;
        }
        else
        {
            PIMAGE_NT_HEADERS64 nt64 = PIMAGE_NT_HEADERS64(pImageBase + dos->e_lfanew);
            uImageSize = nt64->OptionalHeader.SizeOfImage;
        }

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        {
            DBGPRINT("[ DumpMZ ] Curerent IRQL too high for IO operations!\n");
            return false;
        }

        DBGPRINT("[ DumpMZ ] ImageBase: 0x%p\n", pImageBase);
        DBGPRINT("[ DumpMZ ] ImageSize: 0x%X\n", uImageSize);

        wchar_t wsFilePath[MAX_PATH]{};
        RtlStringCbPrintfW(wsFilePath, sizeof(wsFilePath), L"\\SystemRoot\\Dumped_%p.dll", pImageBase);

        DBGPRINT("[ DumpMZ ] Save Location: %ws\n", wsFilePath);

        UNICODE_STRING wsFinalPath{};
        RtlInitUnicodeString(&wsFinalPath, wsFilePath);

        OBJECT_ATTRIBUTES oa{};
        InitializeObjectAttributes(&oa, &wsFinalPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        IO_STATUS_BLOCK io{};
        HANDLE hFile{};

        auto res = ZwCreateFile(&hFile, GENERIC_WRITE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(res))
        {
            DBGPRINT("[ DumpMZ ] ZwCreateFile failed 0x%X\n", res);
            return false;
        }

        res = ZwWriteFile(hFile, NULL, NULL, NULL, &io, pImageBase, uImageSize, NULL, NULL);
        if (!NT_SUCCESS(res))
        {
            ZwClose(hFile);
            DBGPRINT("[ DumpMZ ] ZwWriteFile failed 0x%X\n", res);
            return false;
        }

        DBGPRINT("[ DumpMZ ] Dump success!\n");
        ZwClose(hFile);
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

PVOID GetKernelBase()
{
    static PVOID kernelBase = nullptr;
    if (!kernelBase)
    {
        auto entry = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(PsLoadedModuleList->Flink);
        kernelBase = entry->DllBase;
    }
    return kernelBase;
}

bool GetModuleInformation(_In_ const char *moduleName, _Out_ PVOID *moduleBase, _Out_opt_ PULONG moduleSize)
{
    PAGED_CODE();
    NT_ASSERT(moduleName);
    NT_ASSERT(moduleBase);

    ULONG returnedBytes = 0;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &returnedBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH || status != STATUS_BUFFER_OVERFLOW)
    {
        // TODO: add verbose log
        return false;
    }

    // Just in case the info size increases in between calls.
    returnedBytes *= (1 << 8);

    auto systemInfoBuffer =
        tools::AllocatePoolZero<PSYSTEM_MODULE_INFORMATION>(PagedPool, returnedBytes, tags::TAG_DEFAULT);
    if (!systemInfoBuffer)
    {
        DBGPRINT("Err: Failed to allocate memory for ZwQuerySystemInformation\n");
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(systemInfoBuffer);
    };

    status = ZwQuerySystemInformation(SystemModuleInformation, systemInfoBuffer, returnedBytes, &returnedBytes);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: ZwQuerySystemInformation returned 0x%08X\n", status);
        return false;
    }

    for (unsigned i = 0; i < systemInfoBuffer->ModulesCount; ++i)
    {
        const SYSTEM_MODULE *systemModule = &systemInfoBuffer->Modules[i];

        if (!strcmp(systemModule->ImageName + systemModule->ModuleNameOffset, moduleName))
        {
            *moduleBase = systemModule->Base;

            if (moduleSize)
            {
                *moduleSize = systemModule->Size;
            }

            return true;
        }
    }

    return false;
}

NTSTATUS MapFileInSystemSpace(_In_ PUNICODE_STRING FileName, _Out_ PVOID *MappedBase, _Out_opt_ SIZE_T *MappedSize)
{
    NT_ASSERT(FileName);
    NT_ASSERT(MappedBase);

    PAGED_CODE();

    HANDLE fileHandle = NULL;
    HANDLE sectionHandle = NULL;
    PVOID sectionObject = nullptr;

    PVOID ViewBase = nullptr;
    SIZE_T ViewSize = 0;

    IO_STATUS_BLOCK iosb{};

    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    OBJECT_ATTRIBUTES oa2{};
    InitializeObjectAttributes(&oa2, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    NTSTATUS status =
        ZwCreateFile(&fileHandle, SYNCHRONIZE | FILE_READ_DATA, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("ZwCreateFile returned 0x%08X", status);
        return STATUS_UNSUCCESSFUL;
    }

    SCOPE_EXIT
    {
        ZwClose(fileHandle);
    };

    status = ZwCreateSection(&sectionHandle, SECTION_MAP_READ, &oa2, nullptr, PAGE_READONLY, SEC_COMMIT, fileHandle);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("ZwCreateFile returned 0x%08X", status);
        return STATUS_UNSUCCESSFUL;
    }

    SCOPE_EXIT
    {
        ZwClose(sectionHandle);
    };

    status = ObReferenceObjectByHandle(sectionHandle, SECTION_MAP_READ, nullptr, KernelMode, &sectionObject, nullptr);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("ObReferenceObjectByHandle returned 0x%08X", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = MmMapViewInSystemSpace(sectionObject, &ViewBase, &ViewSize);
    ObDereferenceObject(sectionObject);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("MmMapViewInSystemSpace returned 0x%08X", status);
        return STATUS_UNSUCCESSFUL;
    }

    *MappedBase = ViewBase;

    if (MappedSize)
    {
        *MappedSize = ViewSize;
    }

    return STATUS_SUCCESS;
}

const PUCHAR FindCodeCave(PUCHAR Code, ULONG ulCodeSize, size_t CaveLength)
{
    for (unsigned i = 0, j = 0; i < ulCodeSize; i++)
    {
        if (Code[i] == 0x90 || Code[i] == 0xCC)
        {
            j++;
        }
        else
        {
            j = 0;
        }

        if (j == CaveLength)
        {
            return PUCHAR((ULONG_PTR)Code + i - CaveLength + 1);
        }
    }
    return nullptr;
}

} // namespace tools
}; // namespace masterhide