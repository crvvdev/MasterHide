#pragma once

namespace masterhide
{
namespace process
{
typedef struct _DEBUG_CONTEXT
{
    ULONG64 Dr0;
    ULONG64 Dr1;
    ULONG64 Dr2;
    ULONG64 Dr3;
    ULONG64 Dr6;
    ULONG64 Dr7;

    ULONG64 DebugControl;
    ULONG64 LastBranchFromRip;
    ULONG64 LastBranchToRip;
    ULONG64 LastExceptionFromRip;
    ULONG64 LastExceptionToRip;

} DEBUG_CONTEXT, *PDEBUG_CONTEXT;

typedef struct _WOW64_DEBUG_CONTEXT
{
    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;

} WOW64_DEBUG_CONTEXT, *PWOW64_DEBUG_CONTEXT;

typedef struct _KUSD
{
    PKUSER_SHARED_DATA KuserSharedData;
    PMMPTE PteKuserSharedData;
    ULONG OriginalKuserSharedDataPfn;
    ULONG64 BeginInterruptTime;
    ULONG64 BeginSystemTime;
    ULONG BeginLastSystemRITEventTickCount;
    ULONG64 BeginTickCount;
    ULONG64 BeginTimeUpdateLock;
    ULONG64 BeginBaselineSystemQpc;
    ULONG64 DeltaInterruptTime;
    ULONG64 DeltaSystemTime;
    ULONG DeltaLastSystemRITEventTickCount;
    ULONG64 DeltaTickCount;
    ULONG64 DeltaTimeUpdateLock;
    ULONG64 DeltaBaselineSystemQpc;

} KUSD, *PKUSD;

typedef struct _THREAD_ENTRY
{
    PETHREAD Thread;
    WOW64_DEBUG_CONTEXT SavedWow64DebugContext;
    DEBUG_CONTEXT SavedDebugContext;
    union {
        struct
        {
            BOOLEAN IsThreadHidden : 1;
            BOOLEAN BreakOnTermination : 1;
        } Flags;
        LONG Long;
    };
    LIST_ENTRY ListEntry;

} THREAD_ENTRY, *PTHREAD_ENTRY;

typedef struct _PROCESS_ENTRY
{
    PEPROCESS Process;
    HANDLE ProcessId;
    UNICODE_STRING ImageFileName;
    ProcessPolicyFlag_t PolicyFlags;
    WCHAR FakeParentProcessName[_MAX_FNAME];
    LARGE_INTEGER FakePerformanceCounter;
    LARGE_INTEGER FakeSystemTime;
    union {
        struct
        {
            BOOLEAN ProcessPaused : 1;
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
        } Flags;
        LONG Long;
    };
    KUSD Kusd;
    THREAD_ENTRY Threads;
    mutex::EResource ThreadsResource;
    LIST_ENTRY ListEntry;

    [[nodiscard]] PTHREAD_ENTRY AppendThreadList(_In_ PETHREAD thread);

} PROCESS_ENTRY, *PPROCESS_ENTRY;

inline LIST_ENTRY g_processListHead{};
inline mutex::EResource g_processResource{};
inline bool g_initialized = false;

NTSTATUS Initialize();
void Deinitialize();

PVOID AllocateProcessEntry(_In_ SIZE_T size);
void FreeProcessEntry(_In_ PVOID object);
void DeleteProcessEntry(_In_ PVOID object);

[[nodiscard]] NTSTATUS AddProcessEntry(_In_ PEPROCESS process, _In_ ProcessPolicyFlag_t flags);
[[nodiscard]] NTSTATUS AddProcessEntry(_In_ HANDLE processId, _In_ ProcessPolicyFlag_t flags);

[[nodiscard]] PPROCESS_ENTRY GetProcessEntry(_In_ PEPROCESS process);
[[nodiscard]] PPROCESS_ENTRY GetProcessEntry(_In_ HANDLE processId);

[[nodiscard]] NTSTATUS UpdateProcessEntry(_In_ PEPROCESS process, _In_ ProcessPolicyFlag_t flags);
[[nodiscard]] NTSTATUS UpdateProcessEntry(_In_ HANDLE processId, _In_ ProcessPolicyFlag_t flags);

NTSTATUS RemoveProcessEntry(_In_ PEPROCESS process);
NTSTATUS RemoveProcessEntry(_In_ HANDLE processId);

[[nodiscard]] bool IsProtectedProcess(_In_ HANDLE processId);
[[nodiscard]] bool IsProtectedProcess(_In_ PEPROCESS process);
[[nodiscard]] bool IsProtectedProcess(_In_ PUNICODE_STRING processFullPath);

[[nodiscard]] bool IsMonitoredProcess(_In_ HANDLE processId);
[[nodiscard]] bool IsMonitoredProcess(_In_ PEPROCESS process);
[[nodiscard]] bool IsMonitoredProcess(_In_ PUNICODE_STRING processFullPath);

[[nodiscard]] bool IsHiddenFromDebugProcess(_In_ HANDLE processId);
[[nodiscard]] bool IsHiddenFromDebugProcess(_In_ PEPROCESS process);
[[nodiscard]] bool IsHiddenFromDebugProcess(_In_ PUNICODE_STRING processFullPath);

void GetBegin(_In_ PEPROCESS process);
void UpdateDelta(_In_ PEPROCESS process);
void CounterUpdater(PVOID Context);
BOOLEAN StopCounterForProcess(_In_ PEPROCESS process);
BOOLEAN ResumeCounterForProcess(_In_ PEPROCESS process);
NTSTATUS ModifyCounterForProcess(_In_ PEPROCESS process, _In_ BOOLEAN status);

bool ClearHeapFlags(PEPROCESS process);
bool SetPebDeuggerFlag(PEPROCESS process, BOOLEAN value);
bool ClearPebNtGlobalFlag(PEPROCESS process);

bool ClearBypassProcessFreezeFlag(_In_ PPROCESS_ENTRY processEntry);
bool ClearThreadHideFromDebuggerFlag(_In_ PPROCESS_ENTRY processEntry);
bool ClearProcessBreakOnTerminationFlag(_In_ PPROCESS_ENTRY processEntry);
void SaveProcessDebugFlags(_In_ PPROCESS_ENTRY processEntry);
void SaveProcessHandleTracing(_In_ PPROCESS_ENTRY processEntry);
bool ClearThreadBreakOnTerminationFlags(_In_ PPROCESS_ENTRY processEntry);

void HookKuserSharedData(_In_ PPROCESS_ENTRY processEntry);
void UnHookKuserSharedData(PPROCESS_ENTRY processEntry);

using ENUM_PROCESSES_CALLBACK = bool (*)(_In_ PPROCESS_ENTRY);

template <typename Callback = ENUM_PROCESSES_CALLBACK> bool EnumProcessesUnsafe(Callback &&callback)
{
    NT_ASSERT(g_initialized);

    if (!IsListEmpty(&g_processListHead))
    {
        for (PLIST_ENTRY listEntry = g_processListHead.Flink; listEntry != &g_processListHead;
             listEntry = listEntry->Flink)
        {
            PPROCESS_ENTRY processEntry = CONTAINING_RECORD(listEntry, PROCESS_ENTRY, ListEntry);
            if (callback(processEntry))
            {
                return true;
            }
        }
    }
    return false;
}

namespace rules
{
typedef struct _PROCESS_RULE_ENTRY
{
    UNICODE_STRING ImageFileName;
    ProcessPolicyFlag_t PolicyFlags;
    LIST_ENTRY ListEntry;

} PROCESS_RULE_ENTRY, *PPROCESS_RULE_ENTRY;

inline LIST_ENTRY g_processRuleListHead{};
inline mutex::EResource g_processRuleResource{};
inline bool g_initialized = false;

NTSTATUS Initialize();
void Deinitialize();

using ENUM_RULE_PROCESSES_CALLBACK = bool (*)(_In_ PPROCESS_RULE_ENTRY);

template <typename Callback = ENUM_RULE_PROCESSES_CALLBACK> bool EnumRuleProcessesUnsafe(Callback &&callback)
{
    NT_ASSERT(g_initialized);

    if (!IsListEmpty(&g_processRuleListHead))
    {
        for (PLIST_ENTRY listEntry = g_processRuleListHead.Flink; listEntry != &g_processRuleListHead;
             listEntry = listEntry->Flink)
        {
            PPROCESS_RULE_ENTRY processRuleEntry = CONTAINING_RECORD(listEntry, PROCESS_RULE_ENTRY, ListEntry);
            if (callback(processRuleEntry))
            {
                return true;
            }
        }
    }
    return false;
}

[[nodiscard]] NTSTATUS AddProcessRuleEntry(_In_ PUNICODE_STRING imageFileName, _In_ ProcessPolicyFlag_t flags);

[[nodiscard]] NTSTATUS UpdateProcessRuleEntry(_In_ PUNICODE_STRING imageFileName, _In_ ProcessPolicyFlag_t flags);
[[nodiscard]] PPROCESS_RULE_ENTRY GetProcessRuleEntry(_In_ PCUNICODE_STRING imageFileName);

NTSTATUS RemoveProcessRuleEntry(_In_ PCUNICODE_STRING imageFileName);
} // namespace rules
} // namespace process
} // namespace masterhide