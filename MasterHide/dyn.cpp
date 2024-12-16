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
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x560;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x560;
        DynCtx.Offsets.PicoContextOffset = 0x630;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x460;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x5c0;
        break;
    }
    case WINDOWS_10_VERSION_22H2:
    case WINDOWS_10_VERSION_21H1:
    case WINDOWS_10_VERSION_21H2:
    case WINDOWS_10_VERSION_20H2:
    case WINDOWS_10_VERSION_20H1: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x510;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x510;
        DynCtx.Offsets.PicoContextOffset = 0x5e0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x460;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x5c0;
        break;
    }
    case WINDOWS_10_VERSION_19H2:
    case WINDOWS_10_VERSION_19H1: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0x74;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6e0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6e0;
        DynCtx.Offsets.PicoContextOffset = 0x7a8;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x308;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE5: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
        DynCtx.Offsets.PicoContextOffset = 0x798;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE4: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
        DynCtx.Offsets.PicoContextOffset = 0x7a0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE3: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
        DynCtx.Offsets.PicoContextOffset = 0x7a0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x300;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE2: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6c8;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6c8;
        DynCtx.Offsets.PicoContextOffset = 0x798;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0x810;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
        break;
    }
    case WINDOWS_10_VERSION_REDSTONE1: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6c0;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6c0;
        DynCtx.Offsets.PicoContextOffset = 0x790;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
        break;
    }
    case WINDOWS_10_VERSION_THRESHOLD2: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
        DynCtx.Offsets.PicoContextOffset = 0x788;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x468;
        break;
    }
    case WINDOWS_10_VERSION_THRESHOLD1: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
        DynCtx.Offsets.PicoContextOffset = 0x788;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x460;
        break;
    }
    case WINDOWS_8_1: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x6b4;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x6b4;
        DynCtx.Offsets.PicoContextOffset = 0x770;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x450;
        break;
    }
    case WINDOWS_8: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x42c;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x42c;
        DynCtx.Offsets.PicoContextOffset = 0x770;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x450;
        break;
    }
    case WINDOWS_7_SP1:
    case WINDOWS_7: {
        DynCtx.Offsets.BypassProcessFreezeFlagOffset = 0;
        DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset = 0x448;
        DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset = 0x448;
        DynCtx.Offsets.PicoContextOffset = 0;
        DynCtx.Offsets.RestrictSetThreadContextOffset = 0;
        DynCtx.Offsets.SeAuditProcessCreationInfoOffset = 0x390;
        break;
    }
    default: {
        return STATUS_NOT_SUPPORTED;
    }
    }

    return STATUS_SUCCESS;
}

static PULONG_PTR GetKeServiceDescriptorTable(PULONG_PTR *KeServiceDescriptorTableShadow)
{
    // this code was stolen from BE.
    ULONG64 KiSystemCall64;      // r9
    ULONG64 KiSystemCall64_;     // rdx
    ULONG64 v5;                  // r10
    bool i;                      // cf
    __int64 KiSystemServiceUser; // rax
    ULONG64 v8;                  // rcx

    ULONG64 *KeServiceDescriptorTable = NULL;

    KiSystemCall64 = __readmsr(IA32_LSTAR_MSR);
    KiSystemCall64_ = KiSystemCall64;
    v5 = KiSystemCall64 + 0x1000;

    for (i = KiSystemCall64 < KiSystemCall64 + 0x1000; i; i = KiSystemCall64_ < v5)
    {
        if (*(UCHAR *)KiSystemCall64_ == 0x4C && *(UCHAR *)(KiSystemCall64_ + 1) == 0x8D &&
            *(UCHAR *)(KiSystemCall64_ + 2) == 0x15 && *(UCHAR *)(KiSystemCall64_ + 7) == 0x4C &&
            *(UCHAR *)(KiSystemCall64_ + 8) == 0x8D && *(UCHAR *)(KiSystemCall64_ + 9) == 0x1D)
        {
            KeServiceDescriptorTable = (ULONG64 *)(*(INT32 *)(KiSystemCall64_ + 3) + KiSystemCall64_ + 7);

            if (KeServiceDescriptorTable)
            {
                if (KeServiceDescriptorTableShadow)
                {
                    KiSystemCall64_ += 7;
                    *KeServiceDescriptorTableShadow =
                        (ULONG64 *)(*(INT32 *)(KiSystemCall64_ + 3) + KiSystemCall64_ + 7);
                }

                goto Exit;
            }

            break;
        }
        ++KiSystemCall64_;
    }

    if (KERNEL_BUILD_VERSION > WINDOWS_10_VERSION_REDSTONE4)
    {
        while (KiSystemCall64 < v5)
        {
            if (*(UCHAR *)KiSystemCall64 == 0xE9 && *(UCHAR *)(KiSystemCall64 + 5) == 0xC3 &&
                !*(UCHAR *)(KiSystemCall64 + 6))
            {
                KiSystemServiceUser = *(INT32 *)(KiSystemCall64 + 1);

                v8 = KiSystemServiceUser + KiSystemCall64 + 5;
                if (v8)
                {
                    while (v8 < KiSystemServiceUser + KiSystemCall64 + 0x1005)
                    {
                        if (*(UCHAR *)v8 == 0x4C && *(UCHAR *)(v8 + 1) == 0x8D && *(UCHAR *)(v8 + 2) == 0x15 &&
                            *(UCHAR *)(v8 + 7) == 0x4C && *(UCHAR *)(v8 + 8) == 0x8D && *(UCHAR *)(v8 + 9) == 0x1D)
                        {
                            KeServiceDescriptorTable = (ULONG64 *)(*(INT32 *)(v8 + 3) + v8 + 7);

                            if (KeServiceDescriptorTable)
                            {
                                if (KeServiceDescriptorTableShadow)
                                {
                                    v8 += 7;
                                    *KeServiceDescriptorTableShadow = (ULONG64 *)(*(INT32 *)(v8 + 3) + v8 + 7);
                                }

                                goto Exit;
                            }

                            return NULL;
                        }
                        ++v8;
                    }
                }

                return NULL;
            }
            ++KiSystemCall64;
        }
    }

Exit:
    return KeServiceDescriptorTable;
};

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

    if (KERNEL_BUILD_VERSION < WINDOWS_7 || KERNEL_BUILD_VERSION > WINDOWS_11_VERSION_24H2)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Unsupported windows version!");

        return STATUS_NOT_SUPPORTED;
    }

#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
    if (KERNEL_BUILD_VERSION >= WINDOWS_11_VERSION_21H2)
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

    if (KERNEL_BUILD_VERSION > WINDOWS_10_VERSION_THRESHOLD2)
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

    PULONG_PTR KeServiceDescriptorTableShadow = NULL;
    PULONG_PTR KeServiceDescriptorTable = GetKeServiceDescriptorTable(&KeServiceDescriptorTableShadow);
    if (!KeServiceDescriptorTable)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "KeServiceDescriptorTable not found!");

        return STATUS_PROCEDURE_NOT_FOUND;
    }

    DynCtx.Kernel.KeServiceDescriptorTable = KeServiceDescriptorTable;
    DynCtx.Kernel.KeServiceDescriptorTableShadow = KeServiceDescriptorTableShadow;

    DBGPRINT("KeServiceDescriptorTable = 0x%p", DynCtx.Kernel.KeServiceDescriptorTable);
    DBGPRINT("KeServiceDescriptorTableShadow = 0x%p", DynCtx.Kernel.KeServiceDescriptorTableShadow);

    g_initialized = true;

    return STATUS_SUCCESS;
}
} // namespace dyn
} // namespace masterhide