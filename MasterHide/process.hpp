#pragma once

namespace masterhide
{
namespace process
{
#if 0

inline ULONG g_globalProcessPolicyFlags = 0;
#endif

enum EProcessPolicyFlags : ULONG
{
    ProcessPolicyFlagNtQuerySystemInformation = 0,
    ProcessPolicyFlagNtOpenProcess = (1 << 0),
    ProcessPolicyFlagNtAllocateVirtualMemory = (1 << 1),
    ProcessPolicyFlagNtFreeVirtualMemory = (1 << 2),
    ProcessPolicyFlagNtWriteVirtualMemory = (1 << 3),
    ProcessPolicyFlagNtDeviceIoControlFile = (1 << 4),
    ProcessPolicyFlagNtLoadDriver = (1 << 5),
    ProcessPolicyFlagNtSetInformationThread = (1 << 6),
    ProcessPolicyFlagNtQueryInformationProcess = (1 << 7),
    ProcessPolicyFlagNtSetInformationProcess = (1 << 8),
    ProcessPolicyFlagNtQueryObject = (1 << 9),
    ProcessPolicyFlagNtGetContextThread = (1 << 10),
    ProcessPolicyFlagNtSetContextThread = (1 << 11),
};

typedef struct _PROCESS_ENTRY
{
    PEPROCESS Process;
    HANDLE ProcessId;
    UNICODE_STRING ProcessFullPath;
    ULONG PolicyFlags;
    WCHAR FakeParentProcessName[_MAX_FNAME];
    union {
        struct
        {
            BOOLEAN PebBeingDebuggedCleared : 1;
            BOOLEAN HeapFlagsCleared : 1;
            BOOLEAN PebNtGlobalFlagCleared : 1;
            BOOLEAN KUserSharedDataCleared : 1;
            BOOLEAN HideFromDebuggerFlagCleared : 1;
            BOOLEAN BypassProcessFreezeFlagCleared : 1;
            BOOLEAN ProcessHandleTracingEnabled : 1;
            BOOLEAN ProcessBreakOnTerminationCleared : 1;
            BOOLEAN ThreadBreakOnTerminationCleared : 1;
            BOOLEAN ProcessDebugFlagsSaved : 1;
            BOOLEAN ProcessHandleTracingSaved : 1;
            BOOLEAN ValueProcessBreakOnTermination : 1;
            BOOLEAN ValueProcessDebugFlags : 1;
            BOOLEAN Monitored : 1;
            BOOLEAN Blacklisted : 1;
            BOOLEAN Protected : 1;
        } Flags;
        ULONG64 Long;
    };
    LONG RefCount;
    LIST_ENTRY ListEntry;

} PROCESS_ENTRY, *PPROCESS_ENTRY;

inline LIST_ENTRY g_processListHead{};
inline mutex::EResource g_processResource{};
inline bool g_initialized = false;

bool Initialize()
{
    if (g_initialized)
    {
        return true;
    }

    InitializeListHead(&g_processListHead);

    const NTSTATUS status = g_processResource.Initialize();
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Failed to initialize processes resource 0x%08X", status);
        return false;
    }

    g_initialized = true;
    return true;
}

void Destroy()
{
    if (!g_initialized)
    {
        return;
    }

    g_processResource.Destroy();

    g_initialized = false;
}

using ENUM_PROCESSES_CALLBACK = bool (*)(_In_ PPROCESS_ENTRY);

template <typename Callback = ENUM_PROCESSES_CALLBACK> bool EnumProcessesUnsafe(Callback &&callback)
{
    for (PLIST_ENTRY listEntry = g_processListHead.Flink; listEntry != &g_processListHead; listEntry = listEntry->Flink)
    {
        PPROCESS_ENTRY processEntry = CONTAINING_RECORD(listEntry, PROCESS_ENTRY, ListEntry);
        if (callback(processEntry))
        {
            return true;
        }
    }
    return false;
}

bool IsWhitelistedDriver(_In_ LPCSTR driverName)
{
    UNREFERENCED_PARAMETER(driverName);
    // TODO: implement
    return false;
}

void ReferenceObject(_In_ PPROCESS_ENTRY processEntry)
{
    NT_ASSERT(processEntry);
    InterlockedIncrement(&processEntry->RefCount);
}

void DereferenceObject(_In_ PPROCESS_ENTRY processEntry)
{
    NT_ASSERT(processEntry);
    InterlockedDecrement(&processEntry->RefCount);
}

PPROCESS_ENTRY GetProtectedProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(processId);

    PPROCESS_ENTRY resultProcessEntry = nullptr;

    if (g_processResource.LockShared())
    {
        EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
            if (processEntry->ProcessId == processId && processEntry->Flags.Protected == 1)
            {
                ReferenceObject(processEntry);
                resultProcessEntry = processEntry;
                return true;
            }
            return false;
        });

        g_processResource.Unlock();
    }

    return resultProcessEntry;
}

PPROCESS_ENTRY GetProtectedProcess(_In_ PEPROCESS process)
{
    NT_ASSERT(process);
    PAGED_CODE();

    return GetProtectedProcess(PsGetProcessId(process));
}

PPROCESS_ENTRY GetBlacklistedProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(processId);

    PPROCESS_ENTRY resultProcessEntry = nullptr;

    if (g_processResource.LockShared())
    {
        EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
            if (processEntry->ProcessId == processId && processEntry->Flags.Blacklisted == 1)
            {
                ReferenceObject(processEntry);
                resultProcessEntry = processEntry;
                return true;
            }
            return false;
        });

        g_processResource.Unlock();
    }

    return resultProcessEntry;
}

PPROCESS_ENTRY GetBlacklistedProcess(_In_ PEPROCESS process)
{
    NT_ASSERT(process);
    PAGED_CODE();

    return GetBlacklistedProcess(PsGetProcessId(process));
}

bool IsProtectedProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(processId);

    if (!g_processResource.LockShared())
    {
        return false;
    }

    SCOPE_EXIT
    {
        g_processResource.Unlock();
    };

    const auto result = EnumProcessesUnsafe(
        [&](PPROCESS_ENTRY entry) -> bool { return (entry->ProcessId == processId && entry->Flags.Protected == 1); });

    return result;
}

bool IsProtectedProcess(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(process);
    return IsProtectedProcess(PsGetProcessId(process));
}

bool IsProtectedProcess(_In_ PUNICODE_STRING processFullPath)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(processFullPath);

    if (!g_processResource.LockShared())
    {
        return false;
    }

    SCOPE_EXIT
    {
        g_processResource.Unlock();
    };

    const auto result = EnumProcessesUnsafe([&](PPROCESS_ENTRY entry) -> bool {
        return (!RtlCompareUnicodeString(&entry->ProcessFullPath, processFullPath, FALSE) &&
                entry->Flags.Protected == 1);
    });

    return result;
}

bool IsMonitoredProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(processId);

    if (!g_processResource.LockShared())
    {
        return false;
    }

    SCOPE_EXIT
    {
        g_processResource.Unlock();
    };

    const auto result = EnumProcessesUnsafe(
        [&](PPROCESS_ENTRY entry) -> bool { return (entry->ProcessId == processId && entry->Flags.Monitored == 1); });

    return result;
}

bool IsMonitoredProcess(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(process);
    return IsMonitoredProcess(PsGetProcessId(process));
}

bool IsBlacklistedProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(processId);

    if (!g_processResource.LockShared())
    {
        return false;
    }

    SCOPE_EXIT
    {
        g_processResource.Unlock();
    };

    const auto result = EnumProcessesUnsafe(
        [&](PPROCESS_ENTRY entry) -> bool { return (entry->ProcessId == processId && entry->Flags.Blacklisted == 1); });

    return result;
}

bool IsBlacklistedProcess(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(process);
    return IsBlacklistedProcess(PsGetProcessId(process));
}

#if 0
bool IsProcessInPolicy(_In_ PEPROCESS process)
{
    if (PsIsProtectedProcess(process) && !BooleanFlagOn(g_processPolicyFlags, ProcessPolicyFlagProtected))
    {
        // Ignore protected processes
        return false;
    }

    if (PsIsSystemProcess(process) && !BooleanFlagOn(g_processPolicyFlags, ProcessPolicyFlagSystem))
    {
        // Ignore system processes
        return false;
    }

    return process::IsProtectedProcess(process);
}

bool IsProcessInPolicy(_In_ HANDLE processHandle)
{
    PEPROCESS process = nullptr;

    const NTSTATUS status = ObReferenceObjectByHandle(processHandle, 0, *PsProcessType, KernelMode,
                                                      reinterpret_cast<PVOID *>(&process), nullptr);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: ObReferenceObjectByHandle returned 0x%08X", status);
        return false;
    }

    SCOPE_EXIT
    {
        ObDereferenceObject(process);
    };

    return IsProcessInPolicy(process);
}
#endif
} // namespace process
} // namespace masterhide