#pragma once

namespace masterhide
{
namespace rules
{
// Enums
//
using ProcessPolicyFlag_t = LONG64;

enum EProcessPolicyFlags : ProcessPolicyFlag_t
{
    ProcessPolicyFlagNone = 0,

    // General rules
    ProcessPolicyFlagMonitor = BIT(0),
    ProcessPolicyFlagHijack = BIT(1),
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

#define PROCESS_POLICY_FLAG_HIJACK rules::ProcessPolicyFlagHijack
#define PROCESS_POLICY_FLAG_MONITOR rules::ProcessPolicyFlagMonitor
#define PROCESS_POLICY_FLAG_HIDE_FROM_DEBUGGER rules::ProcessPolicyFlagHideFromDebugger
#define PROCESS_POLICY_FLAG_ALL                                                                                        \
    (rules::ProcessPolicyFlagNtQuerySystemInformation | rules::ProcessPolicyFlagNtOpenProcess |                        \
     rules::ProcessPolicyFlagNtLoadDriver | rules::ProcessPolicyFlagNtSetInformationThread |                           \
     rules::ProcessPolicyFlagNtQueryInformationProcess | rules::ProcessPolicyFlagNtQueryObject |                       \
     rules::ProcessPolicyFlagNtGetContextThread | rules::ProcessPolicyFlagNtSetContextThread |                         \
     rules::ProcessPolicyFlagNtUserWindowFromPoint | rules::ProcessPolicyFlagNtUserQueryWindow |                       \
     rules::ProcessPolicyFlagNtUserFindWindowEx | rules::ProcessPolicyFlagNtUserBuildHwndList |                        \
     rules::ProcessPolicyFlagNtUserGetForegroundWindow | rules::ProcessPolicyFlagNtContinue |                          \
     rules::ProcessPolicyFlagNtYieldExecution | rules::ProcessPolicyFlagNtQueryInformationThread |                     \
     rules::ProcessPolicyFlagNtQueryInformationJobObject | rules::ProcessPolicyFlagNtQuerySystemTime |                 \
     rules::ProcessPolicyFlagNtQueryPerformanceCounter | rules::ProcessPolicyFlagNtSystemDebugControl |                \
     rules::ProcessPolicyFlagNtClose | rules::ProcessPolicyFlagNtCreateThreadEx |                                      \
     rules::ProcessPolicyFlagHideKUserSharedData | rules::ProcessPolicyFlagClearThreadHideFromDebuggerFlag |           \
     rules::ProcessPolicyFlagClearBypassProcessFreeze | rules::ProcessPolicyFlagClearPebBeingDebugged |                \
     rules::ProcessPolicyFlagClearPebNtGlobalFlag | rules::ProcessPolicyFlagClearHeapFlags |                           \
     rules::ProcessPolicyFlagClearKUserSharedData | rules::ProcessPolicyFlagClearProcessBreakOnTerminationFlag |       \
     rules::ProcessPolicyFlagClearThreadBreakOnTerminationFlag | rules::ProcessPolicyFlagSaveProcessDebugFlags |       \
     rules::ProcessPolicyFlagSaveProcessHandleTracing | rules::ProcessPolicyFlagHideChildFromDebugger)

#define PROCESS_POLICY_HIDE_FROM_DEBUGGER (PROCESS_POLICY_FLAG_HIDE_FROM_DEBUGGER | PROCESS_POLICY_FLAG_ALL)

#define PROCESS_POLICY_HIJACK (PROCESS_POLICY_FLAG_HIJACK | PROCESS_POLICY_FLAG_ALL)

#define PROCESS_POLICY_ALL                                                                                             \
    (PROCESS_POLICY_FLAG_HIJACK | PROCESS_POLICY_FLAG_MONITOR | PROCESS_POLICY_FLAG_HIDE_FROM_DEBUGGER |               \
     PROCESS_POLICY_FLAG_ALL)

enum EObjectType : INT
{
    ObjectTypeInvalid = 0,
    ObjectTypeProcessEntry,
    ObjectTypeProcessRule
};

// Structs
//
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

    PTHREAD_ENTRY AppendThreadList(_In_ PETHREAD thread);

} PROCESS_ENTRY, *PPROCESS_ENTRY;

typedef struct _PROCESS_RULE_ENTRY
{
    UNICODE_STRING ImageFileName;
    ProcessPolicyFlag_t PolicyFlags;
    LIST_ENTRY ListEntry;

} PROCESS_RULE_ENTRY, *PPROCESS_RULE_ENTRY;

// Globals
//
inline LIST_ENTRY g_processRuleListHead{};
inline mutex::EResource g_processRuleResource{};
inline LIST_ENTRY g_processListHead{};
inline mutex::EResource g_processResource{};
inline bool g_initialized = false;

// Functions
//
NTSTATUS Initialize();
void Deinitialize();

void CounterUpdater(PVOID Context);

using ENUM_RULE_PROCESSES_CALLBACK = bool (*)(_In_ PPROCESS_RULE_ENTRY);

template <typename Callback = ENUM_RULE_PROCESSES_CALLBACK> bool EnumRuleProcessesUnsafe(Callback &&callback)
{
    if (!g_initialized)
    {
        return false;
    }

    if (IsListEmpty(&g_processRuleListHead))
    {
        // No entries in list.
        return false;
    }

    for (PLIST_ENTRY listEntry = g_processRuleListHead.Flink; listEntry != &g_processRuleListHead;
         listEntry = listEntry->Flink)
    {
        PPROCESS_RULE_ENTRY processRuleEntry = CONTAINING_RECORD(listEntry, PROCESS_RULE_ENTRY, ListEntry);
        if (callback(processRuleEntry))
        {
            return true;
        }
    }
    return false;
}

using ENUM_PROCESSES_CALLBACK = bool (*)(_In_ PPROCESS_ENTRY);

template <typename Callback = ENUM_PROCESSES_CALLBACK> bool EnumProcessesUnsafe(Callback &&callback)
{
    if (!g_initialized)
    {
        return false;
    }

    if (IsListEmpty(&g_processListHead))
    {
        // No entries in list.
        return false;
    }

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

bool IsWhitelistedDriver(_In_ LPCSTR driverName);

// void ReferenceObject(_In_ PVOID object);
// void DereferenceObject(_In_ PVOID object);

[[nodiscard]] NTSTATUS AddProcessRuleEntry(_In_ PUNICODE_STRING imageFileName, _In_ ProcessPolicyFlag_t flags);
[[nodiscard]] PPROCESS_RULE_ENTRY GetProcessRuleEntry(_In_ PCUNICODE_STRING imageFileName);

[[nodiscard]] NTSTATUS AddProcessEntry(_In_ PEPROCESS process, _In_ ProcessPolicyFlag_t flags);

[[nodiscard]] NTSTATUS UpdateProcessEntry(_In_ PEPROCESS process, _In_ ProcessPolicyFlag_t flags);
[[nodiscard]] NTSTATUS UpdateProcessEntry(_In_ HANDLE processId, _In_ ProcessPolicyFlag_t flags);

[[nodiscard]] PPROCESS_ENTRY GetProcessEntry(_In_ HANDLE processId);
[[nodiscard]] PPROCESS_ENTRY GetProcessEntry(_In_ PEPROCESS process);

bool IsHijackedProcess(_In_ HANDLE processId);
bool IsHijackedProcess(_In_ PEPROCESS process);
bool IsHijackedProcess(_In_ PUNICODE_STRING processFullPath);

bool IsMonitoredProcess(_In_ HANDLE processId);
bool IsMonitoredProcess(_In_ PEPROCESS process);
bool IsMonitoredProcess(_In_ PUNICODE_STRING processFullPath);

bool IsHiddenFromDebugProcess(_In_ HANDLE processId);
bool IsHiddenFromDebugProcess(_In_ PEPROCESS process);
bool IsHiddenFromDebugProcess(_In_ PUNICODE_STRING processFullPath);

NTSTATUS RemoveProcessEntry(_In_ HANDLE processId);
NTSTATUS RemoveProcessEntry(_In_ PEPROCESS process);

NTSTATUS ModifyCounterForProcess(_In_ PEPROCESS process, _In_ BOOLEAN status);

} // namespace rules

namespace process
{
bool ClearHeapFlags(PEPROCESS process);
bool SetPebDeuggerFlag(PEPROCESS process, BOOLEAN value);
bool ClearPebNtGlobalFlag(PEPROCESS process);

bool ClearBypassProcessFreezeFlag(_In_ rules::PPROCESS_ENTRY processEntry);
bool ClearThreadHideFromDebuggerFlag(_In_ rules::PPROCESS_ENTRY processEntry);
bool ClearProcessBreakOnTerminationFlag(_In_ rules::PPROCESS_ENTRY processEntry);
void SaveProcessDebugFlags(_In_ rules::PPROCESS_ENTRY processEntry);
void SaveProcessHandleTracing(_In_ rules::PPROCESS_ENTRY processEntry);
bool ClearThreadBreakOnTerminationFlags(_In_ rules::PPROCESS_ENTRY processEntry);

void HookKuserSharedData(_In_ rules::PPROCESS_ENTRY processEntry);
void UnHookKuserSharedData(rules::PPROCESS_ENTRY processEntry);
}; // namespace process
} // namespace masterhide