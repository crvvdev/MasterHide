using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace MasterHideGUI
{
    public static class IoctlCodes
    {
        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_SPECIAL_ACCESS = 0;

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
        {
            return ((deviceType << 16) | (access << 14) | (function << 2) | method);
        }

        public static readonly uint IOCTL_MASTERHIDE_ADD_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IOCTL_MASTERHIDE_REMOVE_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IOCTL_MASTERHIDE_UPDATE_RULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IOCTL_MASTERHIDE_PROCESS_RESUME = CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IOCTL_MASTERHIDE_PROCESS_STOP = CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    public enum HookType : int
    {
        HookTypeInvalid,
        HookTypeInfinityHook,
        HookTypeKasperskyHook,
        HookTypeMax
    }

    [Flags]
    public enum ProcessPolicyFlags : ulong
    {
        ProcessPolicyFlagNone = 0,

        // Control policy flags
        ProcessPolicyFlagMonitored = 1L << 0,
        ProcessPolicyFlagProtected = 1L << 1,
        ProcessPolicyFlagHideFromDebugger = 1L << 2,

        // Hooks
        ProcessPolicyFlagNtQuerySystemInformation = 1L << 3,
        ProcessPolicyFlagNtQueryInformationProcess = 1L << 4,
        ProcessPolicyFlagNtSetInformationProcess = 1L << 5,
        ProcessPolicyFlagNtQueryInformationThread = 1L << 6,
        ProcessPolicyFlagNtSetInformationThread = 1L << 7,
        ProcessPolicyFlagNtGetContextThread = 1L << 8,
        ProcessPolicyFlagNtSetContextThread = 1L << 9,
        ProcessPolicyFlagNtCreateThreadEx = 1L << 10,
        ProcessPolicyFlagNtQueryObject = 1L << 11,
        ProcessPolicyFlagNtGetNextProcess = 1L << 12,
        ProcessPolicyFlagNtCreateUserProcess = 1L << 13,
        ProcessPolicyFlagNtUserWindowFromPoint = 1L << 14,
        ProcessPolicyFlagNtUserQueryWindow = 1L << 15,
        ProcessPolicyFlagNtUserFindWindowEx = 1L << 16,
        ProcessPolicyFlagNtUserBuildHwndList = 1L << 17,
        ProcessPolicyFlagNtUserGetForegroundWindow = 1L << 18,
        ProcessPolicyFlagNtContinue = 1L << 19,
        ProcessPolicyFlagNtYieldExecution = 1L << 20,
        ProcessPolicyFlagNtQueryInformationJobObject = 1L << 21,
        ProcessPolicyFlagNtQuerySystemTime = 1L << 22,
        ProcessPolicyFlagNtQueryPerformanceCounter = 1L << 23,
        ProcessPolicyFlagNtSystemDebugControl = 1L << 24,
        ProcessPolicyFlagNtClose = 1L << 25,
        ProcessPolicyFlagHideKUserSharedData = 1L << 26,

        // Misc
        ProcessPolicyFlagClearThreadHideFromDebuggerFlag = 1L << 27,
        ProcessPolicyFlagClearBypassProcessFreeze = 1L << 28,
        ProcessPolicyFlagClearPebBeingDebugged = 1L << 29,
        ProcessPolicyFlagClearPebNtGlobalFlag = 1L << 30,
        ProcessPolicyFlagClearHeapFlags = 1L << 31,
        ProcessPolicyFlagClearKUserSharedData = 1L << 32,
        ProcessPolicyFlagClearProcessBreakOnTerminationFlag = 1L << 33,
        ProcessPolicyFlagClearThreadBreakOnTerminationFlag = 1L << 34,
        ProcessPolicyFlagSaveProcessDebugFlags = 1L << 35,
        ProcessPolicyFlagSaveProcessHandleTracing = 1L << 36,
        ProcessPolicyFlagHideChildFromDebugger = 1L << 37,
        ProcessPolicyFlagHideSystemCodeIntegrity = 1L << 38,
        ProcessPolicyFlagBypassInstrumentationCallback = 1L << 39,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESS_RULE
    {
        public WinAPI.UNICODE_STRING ImageFileName;
        public uint ProcessId;

        [MarshalAs(UnmanagedType.U1)]
        public bool UseProcessId;

        public long PolicyFlags;
    }
}
