#include "includes.hpp"

namespace masterhide
{
namespace dyn
{
static void GetOffsets()
{
    if (KERNEL_BUILD >= WINDOWS_11)
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

    const NTSTATUS status = RtlGetVersion(&os);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "RtlGetVersion returned %!STATUS!", status);
        return false;
    }

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
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Unsupported Windows version major:%d minor:%d", majorVersion,
                      minorVersion);
        return STATUS_UNSUCCESSFUL;
    }

    DynCtx.Kernel.MajorVersion = majorVersion;
    DynCtx.Kernel.MinorVersion = minorVersion;
    DynCtx.Kernel.BuildVersion = os.dwBuildNumber;

    // Quick and dirty way to obtain kernel base and size
    //
    PVOID kernelBase = nullptr;
    RtlPcToFileHeader(&RtlGetVersion, &kernelBase);

    if (!kernelBase)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Kernel base not found!");
        return STATUS_UNSUCCESSFUL;
    }

    PIMAGE_NT_HEADERS nth = RtlImageNtHeader(kernelBase);

    DynCtx.Kernel.Base = PUCHAR(kernelBase);
    DynCtx.Kernel.Size = nth->OptionalHeader.SizeOfImage;

    GetOffsets();

    g_initialized = true;

    return STATUS_SUCCESS;
}
} // namespace dyn
} // namespace masterhide