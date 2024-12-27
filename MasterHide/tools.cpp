﻿#include "includes.hpp"

namespace masterhide
{
namespace mutex
{
NTSTATUS EResource::Initialize()
{
    PAGED_CODE();
    NT_ASSERT(!_initialized);

    if (_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    KeInitializeEvent(&_event, NotificationEvent, TRUE);
    _refCount.SetEvent(&_event);

    _eresource = tools::AllocatePoolZero<PERESOURCE>(NonPagedPool, sizeof(ERESOURCE), tags::TAG_ERESOURCE);
    if (!_eresource)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for resource!");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const NTSTATUS status = ExInitializeResourceLite(_eresource);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(_eresource);

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ExInitializeResource returned %!STATUS!", status);

        return status;
    }

    _initialized = true;

    return status;
}

NTSTATUS EResource::Deinitialize()
{
    PAGED_CODE();
    NT_ASSERT(_initialized);

    if (!_initialized)
    {
        return STATUS_UNSUCCESSFUL;
    }

    // Wait until there are no references left to the resource
    //
    _refCount.Wait();

    _initialized = false;

    ExDeleteResourceLite(_eresource);
    ExFreePool(_eresource);

    return STATUS_SUCCESS;
}

BOOLEAN EResource::LockExclusive(_In_ BOOLEAN wait)
{
    PAGED_CODE();
    NT_ASSERT(_initialized && "Possible bug, resource is not initialized but LockExclusive was called.");

    _refCount.IncRef();
    KeEnterCriticalRegion();
    return ExAcquireResourceExclusiveLite(_eresource, wait);
}

BOOLEAN EResource::LockShared(_In_ BOOLEAN wait)
{
    PAGED_CODE();
    NT_ASSERT(_initialized && "Possible bug, resource is not initialized but LockShared was called.");

    _refCount.IncRef();
    KeEnterCriticalRegion();
    return ExAcquireResourceSharedLite(_eresource, wait);
}

void EResource::Unlock()
{
    PAGED_CODE();
    NT_ASSERT(_initialized && "Possible bug, resource is not initialized but Unlock was called.");

    ExReleaseResourceAndLeaveCriticalRegion(_eresource);
    _refCount.DecRef();
}

} // namespace mutex

namespace tools
{
HANDLE GetProcessIDFromProcessHandle(_In_ HANDLE ProcessHandle)
{
    PAGED_CODE();

    if (ProcessHandle == ZwCurrentProcess())
    {
        return PsGetCurrentProcessId();
    }

    HANDLE Pid = (HANDLE)(LONG_PTR)-1;
    PEPROCESS Process = nullptr;

    const NTSTATUS status =
        ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, ExGetPreviousMode(),
                                  reinterpret_cast<PVOID *>(&Process), nullptr);
    if (NT_SUCCESS(status))
    {
        Pid = PsGetProcessId(Process);
        ObDereferenceObject(Process);
    }
    return Pid;
}

HANDLE GetProcessIDFromThreadHandle(_In_ HANDLE ThreadHandle)
{
    PAGED_CODE();

    if (ThreadHandle == ZwCurrentThread())
    {
        return PsGetThreadProcessId(PsGetCurrentThread());
    }

    HANDLE Pid = (HANDLE)(LONG_PTR)-1;
    PETHREAD Thread = nullptr;

    const NTSTATUS status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                      ExGetPreviousMode(), reinterpret_cast<PVOID *>(&Thread), nullptr);
    if (NT_SUCCESS(status))
    {
        Pid = PsGetThreadProcessId(Thread);
        ObDereferenceObject(Thread);
    }
    return Pid;
}

bool HasDebugPrivilege()
{
    LUID SeDebugPrivilege = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);

    if (SeSinglePrivilegeCheck(SeDebugPrivilege, ExGetPreviousMode()) == FALSE)
    {
        return false;
    }
    return true;
}

void DelayThread(_In_ LONG64 milliseconds, _In_ BOOLEAN alertable)
{
    PAGED_CODE();

    LARGE_INTEGER Delay;
    Delay.QuadPart = -milliseconds * 10000;
    KeDelayExecutionThread(KernelMode, alertable, &Delay);
}

bool GetProcessFileName(_In_ PEPROCESS process, _Out_ PUNICODE_STRING processImageName)
{
    PAGED_CODE();
    NT_ASSERT(processImageName);

    HANDLE processHandle{};

    NTSTATUS status =
        ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, 0, *PsProcessType, KernelMode, &processHandle);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ObOpenObjectByPointer returned %!STATUS!", status);
        return false;
    }

    SCOPE_EXIT
    {
        ObCloseHandle(processHandle, KernelMode);
    };

    ULONG returnedLength = 0;

    status = ZwQueryInformationProcess(processHandle, ProcessImageFileName, nullptr, 0, &returnedLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwQueryInformationProcess returned %!STATUS!", status);
        return false;
    }

    returnedLength *= 2;

    void *buffer = tools::AllocatePoolZero(NonPagedPool, returnedLength, tags::TAG_DEFAULT);
    if (!buffer)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for ZwQueryInformationProcess!");
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(buffer);
    };

    status = ZwQueryInformationProcess(processHandle, ProcessImageFileName, buffer, returnedLength, &returnedLength);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwQueryInformationProcess returned %!STATUS!", status);
        return false;
    }

    processImageName->Length = 0;
    processImageName->MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
    processImageName->Buffer =
        tools::AllocatePoolZero<PWCH>(NonPagedPool, processImageName->MaximumLength, tags::TAG_STRING);
    if (!processImageName->Buffer)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for process image file name!");
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
        //
        PWSTR moduleName = wcsrchr(processFileName.Buffer, L'\\');
        if (moduleName)
        {
            ++moduleName;

            if (!_wcsicmp(moduleName, processName))
            {
                // Process was found.
                return process;
            }
        }

        ObDereferenceObject(process);
    }
    return nullptr;
}

bool DumpPE(PUCHAR moduleBase, PUNICODE_STRING saveFileName)
{
    PAGED_CODE();
    NT_ASSERT(moduleBase);
    NT_ASSERT(saveFileName);

    __try
    {
        PIMAGE_DOS_HEADER dos = PIMAGE_DOS_HEADER(moduleBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Invalid DOS signature!");
            return false;
        }

        PIMAGE_NT_HEADERS64 nth64 = PIMAGE_NT_HEADERS64(moduleBase + dos->e_lfanew);
        if (nth64->Signature != IMAGE_NT_SIGNATURE)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Invalid PE signature!");
            return false;
        }

        PIMAGE_NT_HEADERS32 nth32 = nullptr;
        ULONG imageSize = 0;

        if (nth64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            nth32 = PIMAGE_NT_HEADERS32(nth64);
            imageSize = nth32->OptionalHeader.SizeOfImage;
        }
        else if (nth64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            imageSize = nth64->OptionalHeader.SizeOfImage;
        }
        else
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Unsupported image architecture!");
            return false;
        }

        auto imageBuffer = tools::AllocatePoolZero<PUCHAR>(NonPagedPool, imageSize, tags::TAG_DEFAULT);
        if (!imageBuffer)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %d bytes to dump module!", imageSize);
            return false;
        }

        SCOPE_EXIT
        {
            ExFreePool(imageBuffer);
        };

        PIMAGE_SECTION_HEADER section = nullptr;

        //
        // Write headers
        //
        if (nth32)
        {
            RtlCopyMemory(imageBuffer, moduleBase, nth32->OptionalHeader.SizeOfHeaders);
        }
        else
        {
            RtlCopyMemory(imageBuffer, moduleBase, nth64->OptionalHeader.SizeOfHeaders);
        }

        //
        // Fix sections
        //
        if (nth32)
        {
            ULONG i = 0;

            for (section = IMAGE_FIRST_SECTION(nth32); i < nth32->FileHeader.NumberOfSections; ++i, ++section)
            {
                RtlCopyMemory(imageBuffer + section->PointerToRawData, moduleBase + section->VirtualAddress,
                              section->SizeOfRawData);
            }
        }
        else
        {
            ULONG i = 0;

            for (section = IMAGE_FIRST_SECTION(nth64); i < nth64->FileHeader.NumberOfSections; ++i, ++section)
            {
                RtlCopyMemory(imageBuffer + section->PointerToRawData, moduleBase + section->VirtualAddress,
                              section->SizeOfRawData);
            }
        }

        OBJECT_ATTRIBUTES oa{};
        InitializeObjectAttributes(&oa, saveFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        IO_STATUS_BLOCK iosb{};

        HANDLE fileHandle{};

        //
        // Write fixed PE file to disk
        //
        NTSTATUS status = ZwCreateFile(&fileHandle, FILE_ALL_ACCESS, &oa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
                                       FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwCreateFile returned %!STATUS!", status);
            return false;
        }

        SCOPE_EXIT
        {
            ZwClose(fileHandle);
        };

        RtlZeroMemory(&iosb, sizeof(iosb));

        status = ZwWriteFile(fileHandle, nullptr, nullptr, nullptr, &iosb, imageBuffer, imageSize, nullptr, nullptr);
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwWriteFile returned %!STATUS!", status);
            return false;
        }

        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Image dump saved at %wZ", saveFileName);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Exception while trying to dump image %!STATUS!", GetExceptionCode());
        return false;
    }
    return true;
}

PIMAGE_SECTION_HEADER GetModuleSection(_In_ PIMAGE_NT_HEADERS nth, _In_ const char *secName)
{
    PAGED_CODE();
    NT_ASSERT(nth);
    NT_ASSERT(secName);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

    for (auto i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!strncmp((const CHAR *)sec->Name, secName, IMAGE_SIZEOF_SHORT_NAME))
        {
            return sec;
        }
    }
    return nullptr;
}

#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE(x, '0', '9') ? (x - '0') : ((x & (~0x20)) - 'A' + 0xa))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))

PUCHAR FindPattern(PUCHAR searchAddress, const size_t searchSize, const char *pattern)
{
    NT_ASSERT(searchAddress);
    NT_ASSERT(pattern);

    auto pat = reinterpret_cast<const unsigned char *>(pattern);
    PUCHAR firstMatch = nullptr;

    for (PUCHAR cur = searchAddress; cur < searchAddress + searchSize; ++cur)
    {
        if (*(PUCHAR)pat == static_cast<UCHAR>('\?') || *cur == getByte(pat))
        {
            if (!firstMatch)
            {
                firstMatch = cur;
            }

            pat += (*(USHORT *)pat == static_cast<USHORT>(16191) || *(PUCHAR)pat != static_cast<UCHAR>('\?')) ? 2 : 1;

            if (!*pat)
            {
                return firstMatch;
            }

            pat++;

            if (!*pat)
            {
                return firstMatch;
            }
        }
        else if (firstMatch)
        {
            cur = firstMatch;
            pat = reinterpret_cast<const unsigned char *>(pattern);
            firstMatch = nullptr;
        }
    }
    return NULL;
}

PUCHAR FindPattern(_In_ void *moduleAddress, _In_ const char *secName, _In_ const char *pattern)
{
    NT_ASSERT(secName);
    NT_ASSERT(pattern);

    __try
    {
        PIMAGE_NT_HEADERS nth = RtlImageNtHeader(moduleAddress);
        if (!nth)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to parse NT headers!");

            return nullptr;
        }

        PIMAGE_SECTION_HEADER sec = GetModuleSection(nth, secName);
        if (!sec)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Section %s not found!", secName);

            return nullptr;
        }

        auto *searchAddress = reinterpret_cast<PUCHAR>(moduleAddress) + sec->VirtualAddress;

        return FindPattern(searchAddress, sec->Misc.VirtualSize, pattern);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
}

NTSTATUS
QuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS systemInfoClass,
                       _Outptr_result_maybenull_ _At_(*systemInfo,
                                                      _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(return))
                           PVOID *systemInfo)
{
    PAGED_CODE();
    NT_ASSERT(systemInfo);

    *systemInfo = nullptr;

    NTSTATUS status;
    ULONG bufferSize = 0x10000;
    PVOID buffer = nullptr;

    // This will recursively call ZwQuerySystemInformation until all information is acquired.
    //
    while (true)
    {
        if (buffer)
        {
            ExFreePool(buffer);
            buffer = nullptr;
        }

        buffer = tools::AllocatePoolZero(NonPagedPool, bufferSize, tags::TAG_DEFAULT);
        if (!buffer)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(systemInfoClass, buffer, bufferSize, &bufferSize);
        if (NT_SUCCESS(status))
        {
            *systemInfo = buffer;
            break;
        }
        else if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
        {
            bufferSize *= 2;
            continue;
        }
        else
        {
            if (buffer)
            {
                ExFreePool(buffer);
                buffer = nullptr;
            }
            break;
        }
    }
    return status;
}

bool GetModuleInformation(_In_ const char *moduleName, _Out_ PVOID *moduleBase, _Out_opt_ PULONG moduleSize)
{
    PAGED_CODE();
    NT_ASSERT(moduleName);
    NT_ASSERT(moduleBase);

    PRTL_PROCESS_MODULES systemModules = nullptr;

    NTSTATUS status = QuerySystemInformation(SystemModuleInformation, reinterpret_cast<PVOID *>(&systemModules));
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(systemModules);
    };

    for (ULONG i = 0; i < systemModules->NumberOfModules; ++i)
    {
        const RTL_PROCESS_MODULE_INFORMATION *systemModule = &systemModules->Modules[i];

        if (!_stricmp((PCHAR)systemModule->FullPathName + systemModule->OffsetToFileName, moduleName))
        {
            *moduleBase = systemModule->ImageBase;

            if (moduleSize)
            {
                *moduleSize = systemModule->ImageSize;
            }

            return true;
        }
    }

    return false;
}

bool GetNtoskrnl(_Out_ PVOID *moduleBase, _Out_opt_ PULONG moduleSize)
{
    PAGED_CODE();
    NT_ASSERT(moduleBase);

    PRTL_PROCESS_MODULES systemModules = nullptr;

    NTSTATUS status = QuerySystemInformation(SystemModuleInformation, reinterpret_cast<PVOID *>(&systemModules));
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(systemModules);
    };

    const RTL_PROCESS_MODULE_INFORMATION *systemModule = &systemModules->Modules[0];

    *moduleBase = systemModule->ImageBase;

    if (moduleSize)
    {
        *moduleSize = systemModule->ImageSize;
    }

    return true;
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

    NTSTATUS status =
        ZwCreateFile(&fileHandle, FILE_READ_DATA, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                     FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwCreateFile returned %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    SCOPE_EXIT
    {
        ZwClose(fileHandle);
    };

    OBJECT_ATTRIBUTES oa2{};
    InitializeObjectAttributes(&oa2, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    status = ZwCreateSection(&sectionHandle, SECTION_MAP_READ, &oa2, nullptr, PAGE_READONLY, SEC_IMAGE, fileHandle);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwCreateSection returned %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    SCOPE_EXIT
    {
        ZwClose(sectionHandle);
    };

    status = ObReferenceObjectByHandle(sectionHandle, 0, nullptr, KernelMode, &sectionObject, nullptr);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ObReferenceObjectByHandle returned %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = MmMapViewInSystemSpace(sectionObject, &ViewBase, &ViewSize);
    ObDereferenceObject(sectionObject);

    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "MmMapViewInSystemSpace returned %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    *MappedBase = ViewBase;

    if (MappedSize)
    {
        *MappedSize = ViewSize;
    }

    return STATUS_SUCCESS;
}

UCHAR *FindCodeCave(UCHAR *const startAddress, ULONG searchSize, ULONG sizeNeeded)
{
    for (ULONG i = 0, j = 0; i < searchSize; i++)
    {
        if (startAddress[i] == 0x90 || startAddress[i] == 0xCC)
        {
            if (++j == sizeNeeded)
            {
                return startAddress + i - sizeNeeded + 1;
            }
        }
        else
        {
            j = 0;
        }
    }
    return nullptr;
}

KPROCESSOR_MODE SetPreviousMode(KPROCESSOR_MODE NewMode, ULONG_PTR thread)
{
    auto ret = *(UCHAR *)(thread + 0x1f6);
    *(UCHAR *)(thread + 0x1f6) = NewMode;

    return ret;
};

} // namespace tools
}; // namespace masterhide