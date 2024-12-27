#pragma once

#define MASTERHIDE_GUID L"{EDC00A52-CBB9-490E-89A3-69E3FFF137BA}"

#define IOCTL_MASTERHIDE_ADD_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_REMOVE_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_UPDATE_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_PROCESS_RESUME CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_PROCESS_STOP CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#ifndef BIT
#define BIT(x) (1LL << (x))
#endif

namespace masterhide
{
enum HookType : int
{
    HookTypeInvalid,
    HookTypeInfinityHook,
    HookTypeKasperskyHook,
    HookTypeMax
};

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
    ProcessPolicyFlagNtQueryInformationProcess = BIT(4),
    ProcessPolicyFlagNtSetInformationProcess = BIT(5),
    ProcessPolicyFlagNtQueryInformationThread = BIT(6),
    ProcessPolicyFlagNtSetInformationThread = BIT(7),
    ProcessPolicyFlagNtGetContextThread = BIT(8),
    ProcessPolicyFlagNtSetContextThread = BIT(9),
    ProcessPolicyFlagNtCreateThreadEx = BIT(10),
    ProcessPolicyFlagNtQueryObject = BIT(11),
    ProcessPolicyFlagNtGetNextProcess = BIT(12),
    ProcessPolicyFlagNtCreateUserProcess = BIT(13),
    ProcessPolicyFlagNtUserWindowFromPoint = BIT(14),
    ProcessPolicyFlagNtUserQueryWindow = BIT(15),
    ProcessPolicyFlagNtUserFindWindowEx = BIT(16),
    ProcessPolicyFlagNtUserBuildHwndList = BIT(17),
    ProcessPolicyFlagNtUserGetForegroundWindow = BIT(18),
    ProcessPolicyFlagNtContinue = BIT(19),
    ProcessPolicyFlagNtYieldExecution = BIT(20),
    ProcessPolicyFlagNtQueryInformationJobObject = BIT(21),
    ProcessPolicyFlagNtQuerySystemTime = BIT(22),
    ProcessPolicyFlagNtQueryPerformanceCounter = BIT(23),
    ProcessPolicyFlagNtSystemDebugControl = BIT(24),
    ProcessPolicyFlagNtClose = BIT(25),
    ProcessPolicyFlagHideKUserSharedData = BIT(26),

    // Misc
    ProcessPolicyFlagClearThreadHideFromDebuggerFlag = BIT(27),
    ProcessPolicyFlagClearBypassProcessFreeze = BIT(28),
    ProcessPolicyFlagClearPebBeingDebugged = BIT(29),
    ProcessPolicyFlagClearPebNtGlobalFlag = BIT(30),
    ProcessPolicyFlagClearHeapFlags = BIT(31),
    ProcessPolicyFlagClearKUserSharedData = BIT(32),
    ProcessPolicyFlagClearProcessBreakOnTerminationFlag = BIT(33),
    ProcessPolicyFlagClearThreadBreakOnTerminationFlag = BIT(34),
    ProcessPolicyFlagSaveProcessDebugFlags = BIT(35),
    ProcessPolicyFlagSaveProcessHandleTracing = BIT(36),
    ProcessPolicyFlagHideChildFromDebugger = BIT(37),
    ProcessPolicyFlagHideSystemCodeIntegrity = BIT(38),
    ProcessPolicyFlagBypassInstrumentationCallback = BIT(39),
};

#define PROCESS_POLICY_FLAG_PROTECTED ProcessPolicyFlagProtected
#define PROCESS_POLICY_FLAG_MONITORED ProcessPolicyFlagMonitored
#define PROCESS_POLICY_FLAG_HIDE_FROM_DEBUGGER ProcessPolicyFlagHideFromDebugger
#define PROCESS_POLICY_FLAG_ALL                                                                                        \
    (ProcessPolicyFlagNtQuerySystemInformation | ProcessPolicyFlagNtSetInformationThread |                             \
     ProcessPolicyFlagNtQueryInformationProcess | ProcessPolicyFlagNtQueryObject |                                     \
     ProcessPolicyFlagNtGetContextThread | ProcessPolicyFlagNtSetContextThread |                                       \
     ProcessPolicyFlagNtUserWindowFromPoint | ProcessPolicyFlagNtUserQueryWindow |                                     \
     ProcessPolicyFlagNtUserFindWindowEx | ProcessPolicyFlagNtUserBuildHwndList |                                      \
     ProcessPolicyFlagNtUserGetForegroundWindow | ProcessPolicyFlagNtContinue | ProcessPolicyFlagNtYieldExecution |    \
     ProcessPolicyFlagNtQueryInformationThread | ProcessPolicyFlagNtQueryInformationJobObject |                        \
     ProcessPolicyFlagNtQuerySystemTime | ProcessPolicyFlagNtQueryPerformanceCounter |                                 \
     ProcessPolicyFlagNtSystemDebugControl | ProcessPolicyFlagNtClose | ProcessPolicyFlagNtCreateThreadEx |            \
     ProcessPolicyFlagHideKUserSharedData | ProcessPolicyFlagClearThreadHideFromDebuggerFlag |                         \
     ProcessPolicyFlagClearBypassProcessFreeze | ProcessPolicyFlagClearPebBeingDebugged |                              \
     ProcessPolicyFlagClearPebNtGlobalFlag | ProcessPolicyFlagClearHeapFlags | ProcessPolicyFlagClearKUserSharedData | \
     ProcessPolicyFlagClearProcessBreakOnTerminationFlag | ProcessPolicyFlagClearThreadBreakOnTerminationFlag |        \
     ProcessPolicyFlagSaveProcessDebugFlags | ProcessPolicyFlagSaveProcessHandleTracing |                              \
     ProcessPolicyFlagHideChildFromDebugger | ProcessPolicyFlagHideSystemCodeIntegrity |                               \
     ProcessPolicyFlagBypassInstrumentationCallback)
#define PROCESS_POLICY_HIDE_FROM_DEBUGGER (PROCESS_POLICY_FLAG_HIDE_FROM_DEBUGGER | PROCESS_POLICY_FLAG_ALL)
#define PROCESS_POLICY_MONITORED (PROCESS_POLICY_FLAG_MONITORED | PROCESS_POLICY_FLAG_ALL)
#define PROCESS_POLICY_PROTECTED (PROCESS_POLICY_FLAG_PROTECTED | PROCESS_POLICY_FLAG_ALL)

//constexpr auto flags =
//    (ProcessPolicyFlagHideFromDebugger | ProcessPolicyFlagNtQuerySystemInformation |
//     ProcessPolicyFlagNtSetInformationThread | ProcessPolicyFlagNtQueryInformationProcess |
//     ProcessPolicyFlagNtQueryObject | ProcessPolicyFlagNtGetContextThread | ProcessPolicyFlagNtSetContextThread |
//     ProcessPolicyFlagNtUserWindowFromPoint | ProcessPolicyFlagNtUserQueryWindow | ProcessPolicyFlagNtUserFindWindowEx |
//     ProcessPolicyFlagNtUserBuildHwndList | ProcessPolicyFlagNtUserGetForegroundWindow | ProcessPolicyFlagNtContinue |
//     ProcessPolicyFlagNtYieldExecution | ProcessPolicyFlagNtQueryInformationThread |
//     ProcessPolicyFlagNtQueryInformationJobObject | ProcessPolicyFlagNtQuerySystemTime |
//     ProcessPolicyFlagNtQueryPerformanceCounter | ProcessPolicyFlagNtSystemDebugControl | ProcessPolicyFlagNtClose |
//     ProcessPolicyFlagNtCreateThreadEx | ProcessPolicyFlagHideKUserSharedData | ProcessPolicyFlagNtGetNextProcess |
//     ProcessPolicyFlagClearThreadHideFromDebuggerFlag | ProcessPolicyFlagClearBypassProcessFreeze |
//     ProcessPolicyFlagClearPebBeingDebugged | ProcessPolicyFlagClearPebNtGlobalFlag | ProcessPolicyFlagClearHeapFlags |
//     ProcessPolicyFlagClearKUserSharedData | ProcessPolicyFlagClearProcessBreakOnTerminationFlag |
//     ProcessPolicyFlagClearThreadBreakOnTerminationFlag | ProcessPolicyFlagSaveProcessDebugFlags |
//     ProcessPolicyFlagSaveProcessHandleTracing | ProcessPolicyFlagHideChildFromDebugger |
//     ProcessPolicyFlagHideSystemCodeIntegrity | ProcessPolicyFlagBypassInstrumentationCallback);

typedef struct _PROCESS_RULE
{
    UNICODE_STRING ImageFileName;
    ULONG ProcessId;
    BOOLEAN UseProcessId;
    ProcessPolicyFlag_t PolicyFlags;

} PROCESS_RULE, *PPROCESS_RULE;
} // namespace masterhide