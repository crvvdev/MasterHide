#pragma once

namespace masterhide
{
namespace process
{
using ProcessPolicyFlag_t = LONG64;

enum EProcessPolicyFlags : ProcessPolicyFlag_t
{
    ProcessPolicyFlagNone = 0,

    // Control policy flags
    ProcessPolicyFlagMonitored = BIT(0),
    ProcessPolicyFlagProtected = BIT(1),
    ProcessPolicyFlagHideFromDebugger = BIT(2),

    // Hooks
    ProcessPolicyFlagNtQuerySystemInformation = BIT(3),
    ProcessPolicyFlagNtOpenProcess = BIT(4),
    ProcessPolicyFlagNtAllocateVirtualMemory = BIT(5),
    ProcessPolicyFlagNtFreeVirtualMemory = BIT(6),
    ProcessPolicyFlagNtWriteVirtualMemory = BIT(7),
    ProcessPolicyFlagNtDeviceIoControlFile = BIT(8),
    ProcessPolicyFlagNtLoadDriver = BIT(9),
    ProcessPolicyFlagNtSetInformationThread = BIT(10),
    ProcessPolicyFlagNtQueryInformationProcess = BIT(11),
    ProcessPolicyFlagNtSetInformationProcess = BIT(12),
    ProcessPolicyFlagNtQueryObject = BIT(13),
    ProcessPolicyFlagNtGetContextThread = BIT(14),
    ProcessPolicyFlagNtSetContextThread = BIT(15),
    ProcessPolicyFlagNtUserWindowFromPoint = BIT(16),
    ProcessPolicyFlagNtUserQueryWindow = BIT(17),
    ProcessPolicyFlagNtUserFindWindowEx = BIT(18),
    ProcessPolicyFlagNtUserBuildHwndList = BIT(19),
    ProcessPolicyFlagNtUserGetForegroundWindow = BIT(20),
    ProcessPolicyFlagNtContinue = BIT(21),
    ProcessPolicyFlagNtYieldExecution = BIT(22),
    ProcessPolicyFlagNtQueryInformationThread = BIT(23),
    ProcessPolicyFlagNtQueryInformationJobObject = BIT(24),
    ProcessPolicyFlagNtQuerySystemTime = BIT(25),
    ProcessPolicyFlagNtQueryPerformanceCounter = BIT(26),
    ProcessPolicyFlagNtSystemDebugControl = BIT(27),
    ProcessPolicyFlagNtClose = BIT(28),
    ProcessPolicyFlagNtCreateThreadEx = BIT(29),
    ProcessPolicyFlagNtOpenThread = BIT(30),
    ProcessPolicyFlagHideKUserSharedData = BIT(31),

    // Misc
    ProcessPolicyFlagClearThreadHideFromDebuggerFlag = BIT(32),
    ProcessPolicyFlagClearBypassProcessFreeze = BIT(33),
    ProcessPolicyFlagClearPebBeingDebugged = BIT(34),
    ProcessPolicyFlagClearPebNtGlobalFlag = BIT(35),
    ProcessPolicyFlagClearHeapFlags = BIT(36),
    ProcessPolicyFlagClearKUserSharedData = BIT(37),
    ProcessPolicyFlagClearProcessBreakOnTerminationFlag = BIT(38),
    ProcessPolicyFlagClearThreadBreakOnTerminationFlag = BIT(39),
    ProcessPolicyFlagSaveProcessDebugFlags = BIT(40),
    ProcessPolicyFlagSaveProcessHandleTracing = BIT(41),
    ProcessPolicyFlagHideChildFromDebugger = BIT(42),
};

#define PROCESS_POLICY_FLAG_PROTECTED process::ProcessPolicyFlagProtected
#define PROCESS_POLICY_FLAG_MONITORED process::ProcessPolicyFlagMonitored
#define PROCESS_POLICY_FLAG_HIDE_FROM_DEBUGGER process::ProcessPolicyFlagHideFromDebugger
#define PROCESS_POLICY_FLAG_ALL                                                                                        \
    (process::ProcessPolicyFlagNtQuerySystemInformation | process::ProcessPolicyFlagNtOpenProcess |                    \
     process::ProcessPolicyFlagNtLoadDriver | process::ProcessPolicyFlagNtSetInformationThread |                       \
     process::ProcessPolicyFlagNtQueryInformationProcess | process::ProcessPolicyFlagNtQueryObject |                   \
     process::ProcessPolicyFlagNtGetContextThread | process::ProcessPolicyFlagNtSetContextThread |                     \
     process::ProcessPolicyFlagNtUserWindowFromPoint | process::ProcessPolicyFlagNtUserQueryWindow |                   \
     process::ProcessPolicyFlagNtUserFindWindowEx | process::ProcessPolicyFlagNtUserBuildHwndList |                    \
     process::ProcessPolicyFlagNtUserGetForegroundWindow | process::ProcessPolicyFlagNtContinue |                      \
     process::ProcessPolicyFlagNtYieldExecution | process::ProcessPolicyFlagNtQueryInformationThread |                 \
     process::ProcessPolicyFlagNtQueryInformationJobObject | process::ProcessPolicyFlagNtQuerySystemTime |             \
     process::ProcessPolicyFlagNtQueryPerformanceCounter | process::ProcessPolicyFlagNtSystemDebugControl |            \
     process::ProcessPolicyFlagNtClose | process::ProcessPolicyFlagNtCreateThreadEx |                                  \
     process::ProcessPolicyFlagHideKUserSharedData | process::ProcessPolicyFlagClearThreadHideFromDebuggerFlag |       \
     process::ProcessPolicyFlagClearBypassProcessFreeze | process::ProcessPolicyFlagClearPebBeingDebugged |            \
     process::ProcessPolicyFlagClearPebNtGlobalFlag | process::ProcessPolicyFlagClearHeapFlags |                       \
     process::ProcessPolicyFlagClearKUserSharedData | process::ProcessPolicyFlagClearProcessBreakOnTerminationFlag |   \
     process::ProcessPolicyFlagClearThreadBreakOnTerminationFlag | process::ProcessPolicyFlagSaveProcessDebugFlags |   \
     process::ProcessPolicyFlagSaveProcessHandleTracing | process::ProcessPolicyFlagHideChildFromDebugger)
#define PROCESS_POLICY_HIDE_FROM_DEBUGGER (PROCESS_POLICY_FLAG_HIDE_FROM_DEBUGGER | PROCESS_POLICY_FLAG_ALL)
#define PROCESS_POLICY_MONITORED (PROCESS_POLICY_FLAG_MONITORED | PROCESS_POLICY_FLAG_ALL)
#define PROCESS_POLICY_PROTECTED (PROCESS_POLICY_FLAG_PROTECTED | PROCESS_POLICY_FLAG_ALL)

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