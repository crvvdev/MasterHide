#include "includes.hpp"

namespace masterhide
{
namespace dyn
{
DynamicContext_t DynCtx{};

static NTSTATUS GetOffsets()
{
    switch (KERNEL_BUILD_VERSION)
    {
    case WINDOWS_11_VERSION_21H2:
    case WINDOWS_11_VERSION_22H2:
    case WINDOWS_11_VERSION_23H2:
    case WINDOWS_11_VERSION_24H2: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x560;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x560;
        DynCtx.Offsets.PicoContext = 0x630;
        DynCtx.Offsets.RestrictSetThreadContext = 0x460;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x5c0;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_22H2:
    case WINDOWS_10_VERSION_21H1:
    case WINDOWS_10_VERSION_21H2:
    case WINDOWS_10_VERSION_20H2:
    case WINDOWS_10_VERSION_20H1: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x510;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x510;
        DynCtx.Offsets.PicoContext = 0x5e0;
        DynCtx.Offsets.RestrictSetThreadContext = 0x460;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x5c0;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_19H2:
    case WINDOWS_10_VERSION_19H1: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6e0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6e0;
        DynCtx.Offsets.PicoContext = 0x7a8;
        DynCtx.Offsets.RestrictSetThreadContext = 0x308;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x468;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE5: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6d0;
        DynCtx.Offsets.PicoContext = 0x798;
        DynCtx.Offsets.RestrictSetThreadContext = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x468;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE4: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6d0;
        DynCtx.Offsets.PicoContext = 0x7a0;
        DynCtx.Offsets.RestrictSetThreadContext = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x468;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE3: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6d0;
        DynCtx.Offsets.PicoContext = 0x7a0;
        DynCtx.Offsets.RestrictSetThreadContext = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x468;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE2: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6c8;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6c8;
        DynCtx.Offsets.PicoContext = 0x798;
        DynCtx.Offsets.RestrictSetThreadContext = 0x810;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x468;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE1: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6c0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6c0;
        DynCtx.Offsets.PicoContext = 0x790;
        DynCtx.Offsets.RestrictSetThreadContext = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x468;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_THRESHOLD2: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6bc;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6bc;
        DynCtx.Offsets.PicoContext = 0x788;
        DynCtx.Offsets.RestrictSetThreadContext = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x468;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_10_VERSION_THRESHOLD1: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6bc;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6bc;
        DynCtx.Offsets.PicoContext = 0x788;
        DynCtx.Offsets.RestrictSetThreadContext = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x460;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_8_1: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x6b4;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x6b4;
        DynCtx.Offsets.PicoContext = 0x770;
        DynCtx.Offsets.RestrictSetThreadContext = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x450;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_8: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x42c;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x42c;
        DynCtx.Offsets.PicoContext = 0x770;
        DynCtx.Offsets.RestrictSetThreadContext = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x450;
        DynCtx.Offsets.SystemCallNumber = 0x80;
        break;
    }
    case WINDOWS_7_SP1:
    case WINDOWS_7: {
        DynCtx.Offsets.BypassProcessFreezeFlag = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlag = 0x448;
        DynCtx.Offsets.ThreadBreakOnTerminationFlag = 0x448;
        DynCtx.Offsets.PicoContext = 0;
        DynCtx.Offsets.RestrictSetThreadContext = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfo = 0x390;
        DynCtx.Offsets.SystemCallNumber = 0x1f8;
        break;
    }
    default: {
        return STATUS_NOT_SUPPORTED;
    }
    }

    return STATUS_SUCCESS;
}

NTSTATUS Initialize()
{
    NT_ASSERT(!g_initialized);

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    RTL_OSVERSIONINFOW os{};
    os.dwOSVersionInfoSize = sizeof(os);

    NTSTATUS status = RtlGetVersion(&os);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "RtlGetVersion returned %!STATUS!", status);

        return status;
    }

    PVOID ntoskrnlBase = nullptr;
    ULONG ntoskrnlSize = 0;

    if (!tools::GetNtoskrnl(&ntoskrnlBase, &ntoskrnlSize))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to obtain ntoskrnl.exe information!");

        return STATUS_NOT_SUPPORTED;
    }

    KERNEL_BASE = ntoskrnlBase;
    KERNEL_SIZE = ntoskrnlSize;
    KERNEL_BUILD_MAJOR = os.dwMajorVersion;
    KERNEL_BUILD_MINOR = os.dwMinorVersion;
    KERNEL_BUILD_VERSION = os.dwBuildNumber;

    DBGPRINT("Windows major %d minor %d build %d", KERNEL_BUILD_MAJOR, KERNEL_BUILD_MINOR, KERNEL_BUILD_VERSION);

    if (KERNEL_BUILD_VERSION < WINDOWS_7_SP1 || KERNEL_BUILD_VERSION > WINDOWS_11_VERSION_24H2)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Unsupported windows version!");

        return STATUS_NOT_SUPPORTED;
    }

    if (MASTERHIDE_HOOK_TYPE == HookTypeInfinityHook)
    {
        if (KERNEL_BUILD_VERSION <= WINDOWS_7_SP1 || KERNEL_BUILD_VERSION >= WINDOWS_11_VERSION_21H2)
        {
            DynCtx.Offsets.GetCpuClock = 0x18;
        }
        else
        {
            DynCtx.Offsets.GetCpuClock = 0x28;
        }

        PUCHAR EtwpDebuggerData = tools::FindPattern(KERNEL_BASE, ".rdata", "2C 08 04 38 0C");
        if (!EtwpDebuggerData)
        {
            EtwpDebuggerData = tools::FindPattern(KERNEL_BASE, ".data", "2C 08 04 38 0C");
            if (!EtwpDebuggerData)
            {
                EtwpDebuggerData = tools::FindPattern(KERNEL_BASE, ".text", "2C 08 04 38 0C");
                if (!EtwpDebuggerData)
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "EtwpDebuggerData not found!");
                    return STATUS_PROCEDURE_NOT_FOUND;
                }
            }
        }

        EtwpDebuggerData -= 2;

        if (!MmIsAddressValid(EtwpDebuggerData))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Invalid EtwpDebuggerData at 0x%p", EtwpDebuggerData);
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        DBGPRINT("EtwpDebuggerData = 0x%p", EtwpDebuggerData);
        DynCtx.Kernel.EtwpDebuggerData = reinterpret_cast<ULONG_PTR>(EtwpDebuggerData);

        // Starting Win10 1909 a new method to achieve infinityhook is necessary
        //
        if (KERNEL_BUILD_VERSION > WINDOWS_10_VERSION_19H2)
        {
            const PUCHAR HvlpReferenceTscPage =
                tools::FindPattern(KERNEL_BASE, ".text", "48 8B 05 ?? ?? ?? ?? 48 8B 40 08 48 8B 0D");
            if (!HvlpReferenceTscPage)
            {
                WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "HvlpReferenceTscPage not found!");
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            DBGPRINT("HvlpReferenceTscPageRef = 0x%p", HvlpReferenceTscPage);
            DynCtx.Kernel.HvlpReferenceTscPage = reinterpret_cast<ULONG_PTR>(HvlpReferenceTscPage);

            PUCHAR HvlGetQpcBias = tools::FindPattern(
                KERNEL_BASE, ".text", "48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 8B F9 48 85");
            if (!HvlGetQpcBias)
            {
                WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "HvlGetQpcBias not found!");
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            HvlGetQpcBias += 0x22;

            DBGPRINT("HvlGetQpcBiasRef = 0x%p", HvlGetQpcBias);
            DynCtx.Kernel.HvlGetQpcBias = reinterpret_cast<ULONG_PTR>(HvlGetQpcBias);
        }
    }

    if (KERNEL_BUILD_VERSION >= 14322 /*Win10 August 2016*/)
    {
        WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "Initializing debugger block to obtain PTE information");

        auto InitializeDebuggerBlock = []() -> bool {
            CONTEXT context = {0};
            context.ContextFlags = CONTEXT_FULL;
            RtlCaptureContext(&context);

            auto dumpHeader = tools::AllocatePoolZero<PDUMP_HEADER>(NonPagedPool, DUMP_BLOCK_SIZE, tags::TAG_DEFAULT);
            if (!dumpHeader)
            {
                return false;
            }

            KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader);
            RtlCopyMemory(&DynCtx.Kernel.KdBlock, reinterpret_cast<PUCHAR>(dumpHeader) + KDDEBUGGER_DATA_OFFSET,
                          sizeof(DynCtx.Kernel.KdBlock));

            ExFreePool(dumpHeader);
            return true;
        };

        if (!InitializeDebuggerBlock())
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to read debugger block!");

            return STATUS_NOT_SUPPORTED;
        }

        PteInitialize(DynCtx.Kernel.KdBlock.PteBase, *(PMMPFN *)DynCtx.Kernel.KdBlock.MmPfnDatabase);
    }

    status = GetOffsets();
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to fill dynamic system offsets!");

        return status;
    }

    g_initialized = true;

    return STATUS_SUCCESS;
}
} // namespace dyn
} // namespace masterhide