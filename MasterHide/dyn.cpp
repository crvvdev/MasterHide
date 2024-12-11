#include "includes.hpp"

namespace masterhide
{
namespace dyn
{
DynamicContext_t DynCtx{};

static NTSTATUS GetOffsets()
{
    NTSTATUS status = STATUS_SUCCESS;

    if (KERNEL_BUILD >= WINDOWS_11_VERSION_21H2)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x560;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x560;
        DynCtx.Offsets.PicoContextOffset = 0x630;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x460;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x5c0;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_22H2 || KERNEL_BUILD == WINDOWS_10_VERSION_21H1 ||
             KERNEL_BUILD == WINDOWS_10_VERSION_21H2 || KERNEL_BUILD == WINDOWS_10_VERSION_20H2 ||
             KERNEL_BUILD == WINDOWS_10_VERSION_20H1)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x510;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x510;
        DynCtx.Offsets.PicoContextOffset = 0x5e0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x460;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x5c0;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_19H2 || KERNEL_BUILD == WINDOWS_10_VERSION_19H1)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6e0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6e0;
        DynCtx.Offsets.PicoContextOffset = 0x7a8;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x308;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_REDSTONE5)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
        DynCtx.Offsets.PicoContextOffset = 0x798;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_REDSTONE4)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
        DynCtx.Offsets.PicoContextOffset = 0x7a0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_REDSTONE3)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
        DynCtx.Offsets.PicoContextOffset = 0x7a0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_REDSTONE2)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6c8;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6c8;
        DynCtx.Offsets.PicoContextOffset = 0x798;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x810;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_REDSTONE1)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6c0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6c0;
        DynCtx.Offsets.PicoContextOffset = 0x790;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_THRESHOLD2)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
        DynCtx.Offsets.PicoContextOffset = 0x788;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
    }
    else if (KERNEL_BUILD == WINDOWS_10_VERSION_THRESHOLD1)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
        DynCtx.Offsets.PicoContextOffset = 0x788;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x460;
    }
    else if (KERNEL_BUILD == WINDOWS_8_1)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6b4;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6b4;
        DynCtx.Offsets.PicoContextOffset = 0x770;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x450;
    }
    else if (KERNEL_BUILD == WINDOWS_8)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x42c;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x42c;
        DynCtx.Offsets.PicoContextOffset = 0x770;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x450;
    }
    else if (KERNEL_BUILD == WINDOWS_7_SP1 || KERNEL_BUILD == WINDOWS_7)
    {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x448;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x448;
        DynCtx.Offsets.PicoContextOffset = 0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x390;
    }
    else
    {
        status = STATUS_NOT_SUPPORTED;
    }

    return status;
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
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to obtain kernel NT headers!");

        return STATUS_NOT_SUPPORTED;
    }

    DynCtx.Kernel.Base = ntoskrnlBase;
    DynCtx.Kernel.Size = ntoskrnlSize;

    const ULONG majorVersion = os.dwMajorVersion;
    const ULONG minorVersion = os.dwMinorVersion;

    // Verify if Windows version is supported
    //
    if (!((majorVersion == 10 && minorVersion == 1) || // Windows 11
          (majorVersion == 10 && minorVersion == 0) || // Windows 10
          (majorVersion == 6 && minorVersion == 3) ||  // Windows 8.1
          (majorVersion == 6 && minorVersion == 2) ||  // Windows 8
          (majorVersion == 6 && minorVersion == 1)))   // Windows 7
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Unsupported Windows version! major:%d minor:%d", majorVersion,
                      minorVersion);

        return STATUS_NOT_SUPPORTED;
    }

    DynCtx.Kernel.MajorVersion = majorVersion;
    DynCtx.Kernel.MinorVersion = minorVersion;
    DynCtx.Kernel.BuildVersion = os.dwBuildNumber;

#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
    if (KERNEL_BUILD >= WINDOWS_11_VERSION_21H2)
    {
        DynCtx.Offsets.GetCpuClock = 0x18;
    }
    else
    {
        DynCtx.Offsets.GetCpuClock = 0x28;
    }

    PUCHAR EtwpDebuggerData = tools::FindPattern(KERNEL_BASE, ".data", "2C 08 04 38 0C");
    if (!EtwpDebuggerData)
    {
        EtwpDebuggerData = tools::FindPattern(KERNEL_BASE, ".rdata", "2C 08 04 38 0C");
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
    if (KERNEL_BUILD > WINDOWS_10_VERSION_19H2)
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

        PUCHAR HvlGetQpcBias = tools::FindPattern(KERNEL_BASE, ".text",
                                                  "48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 8B F9 48 85");
        if (!HvlGetQpcBias)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "HvlGetQpcBias not found!");
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        HvlGetQpcBias += 0x22;

        DBGPRINT("HvlGetQpcBiasRef = 0x%p", HvlGetQpcBias);
        DynCtx.Kernel.HvlGetQpcBias = reinterpret_cast<ULONG_PTR>(HvlGetQpcBias);
    }
#endif

    if (KERNEL_BUILD > WINDOWS_10_VERSION_THRESHOLD2)
    {
        WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "Windows 10 Threshold 2+ detect, initializing debugger block");

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