#include "includes.hpp"

#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
NTSTATUS InitializeInfinityHook(_In_ SSDT_CALLBACK ssdtCallback)
{
    PAGED_CODE();

    NTSTATUS status;

    g_SsdtCallback = ssdtCallback;

    status = ModifyTraceSettings(CKCL_TRACE_SYSCALL);
    if (!NT_SUCCESS(status))
    {
        status = ModifyTraceSettings(CKCL_TRACE_START);
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL,
                          "ModifyTraceSettings(CKCL_TRACE_START) "
                          "failed %!STATUS!",
                          status);

            return status;
        }

        status = ModifyTraceSettings(CKCL_TRACE_SYSCALL);
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL,
                          "ModifyTraceSettings(CKCL_TRACE_SYSCALL) "
                          "failed %!STATUS!",
                          status);

            return status;
        }
    }

    ULONG64 CkclWmiLoggerContext;
    PVOID EtwpDebuggerData;
    PULONG64 EtwpDebuggerDataSilo;
    PVOID syscallEntry;

    EtwpDebuggerData = reinterpret_cast<VOID *>(dyn::DynCtx.Kernel.EtwpDebuggerData);
    DBGPRINT("EtwpDebuggerData = 0x%p", EtwpDebuggerData);

    EtwpDebuggerDataSilo = *reinterpret_cast<PULONG64 *>(PTR_OFFSET_ADD(EtwpDebuggerData, 0x10));
    DBGPRINT("EtwpDebuggerDataSilo = 0x%p", EtwpDebuggerDataSilo);

    if (!MmIsAddressValid(EtwpDebuggerDataSilo))
    {
        goto Exit;
    }

    CkclWmiLoggerContext = EtwpDebuggerDataSilo[2];
    DBGPRINT("CkclWmiLoggerContext = 0x%016llX", CkclWmiLoggerContext);

    if (!CkclWmiLoggerContext)
    {
        goto Exit;
    }

    g_GetCpuClock = dyn::DynCtx.GetCpuClock(CkclWmiLoggerContext);
    DBGPRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);

    if (!MmIsAddressValid(g_GetCpuClock))
    {
        goto Exit;
    }

    syscallEntry = GetSyscallEntry();
    if (!syscallEntry)
    {
        goto Exit;
    }

    DBGPRINT("syscallEntry = 0x%p", syscallEntry);

    g_SyscallTableAddress = PAGE_ALIGN(syscallEntry);
    DBGPRINT("g_SyscallTableAddress = 0x%p", g_SyscallTableAddress);

    if (!g_SyscallTableAddress)
    {
        goto Exit;
    }

    if (StartSyscallHook())
    {
        return STATUS_SUCCESS;
    }

Exit:
    return STATUS_UNSUCCESSFUL;
}

void CleanupInfinityHook()
{
    if (g_WatchdogThreadHandle)
    {
        g_WatchdogSignal = TRUE;

        // Wait for thread to terminate
        //
        ZwWaitForSingleObject(g_WatchdogThreadHandle, FALSE, nullptr);
        ZwClose(g_WatchdogThreadHandle);
        g_WatchdogThreadHandle = nullptr;
    }

    if (g_GetCpuClock)
    {
        InterlockedExchangePointer(g_GetCpuClock, g_GetCpuClockOriginal);
    }

    if (g_HvlGetQpcBias)
    {
        InterlockedExchangePointer(g_HvlGetQpcBias, g_HvlGetQpcBiasOriginal);
    }

    // Restart trace session
    //
    NTSTATUS Status = ModifyTraceSettings(CKCL_TRACE_END);
    if (NT_SUCCESS(Status))
    {
        ModifyTraceSettings(CKCL_TRACE_START);
    }

    DBGPRINT("Cleaned up infinityhook");
}

VOID WatchdogThread(_In_ PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    DBGPRINT("Created watchdog thread for infinityhook");

    while (!g_WatchdogSignal)
    {
        // This will ensure infinityhook is still active all the time
        //
        if (dyn::DynCtx.Kernel.BuildVersion <= WINDOWS_10_VERSION_19H2)
        {
            if (g_GetCpuClock && MmIsAddressValid(g_GetCpuClock))
            {
                // GetCpuClock is a pointer before build 2004
                //
                PVOID oldValue =
                    InterlockedCompareExchangePointer(g_GetCpuClock, &SyscallHookHandler, g_GetCpuClockOriginal);
                if (oldValue == g_GetCpuClockOriginal)
                {
                    g_GetCpuClockOriginal = oldValue;
                }
            }
        }
        else
        {
            if (g_GetCpuClock && MmIsAddressValid(g_GetCpuClock))
            {
                // GetCpuClock is a variable starting build 2004, by changing GetCpuClock to 2 we're telling to use
                // HvlGetQpcBias internally
                //
                PVOID oldValue = InterlockedCompareExchangePointer(g_GetCpuClock, ULongToPtr(2), g_GetCpuClockOriginal);
                if (oldValue == g_GetCpuClockOriginal)
                {
                    g_GetCpuClockOriginal = oldValue;
                }
            }

            if (g_HvlGetQpcBias && MmIsAddressValid(g_HvlGetQpcBias))
            {
                PVOID oldValue =
                    InterlockedCompareExchangePointer(g_HvlGetQpcBias, &hkHvlGetQpcBias, g_HvlGetQpcBiasOriginal);
                if (oldValue == g_HvlGetQpcBiasOriginal)
                {
                    g_HvlGetQpcBiasOriginal = oldValue;
                }
            }
        }

        tools::DelayThread(512);
    }

    DBGPRINT("Exiting watchdog thread for infinityhook");

    PsTerminateSystemThread(STATUS_SUCCESS);
}

BOOLEAN
StartSyscallHook(VOID)
{
    PAGED_CODE();

    if (!g_GetCpuClock || !MmIsAddressValid(g_GetCpuClock))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Invalid g_GetCpuClock!");
        return FALSE;
    }

    if (dyn::DynCtx.Kernel.BuildVersion <= WINDOWS_10_VERSION_19H2)
    {
        g_GetCpuClockOriginal = InterlockedExchangePointer(g_GetCpuClock, &SyscallHookHandler);

        DBGPRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);
        DBGPRINT("g_GetCpuClockOriginal = 0x%p", g_GetCpuClockOriginal);
    }
    else
    {
        g_GetCpuClockOriginal = InterlockedExchangePointer(g_GetCpuClock, ULongToPtr(2));

        DBGPRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);
        DBGPRINT("g_GetCpuClockOriginal = 0x%p", g_GetCpuClockOriginal);

        ULONG_PTR HvlpReferenceTscPage = dyn::DynCtx.Kernel.HvlpReferenceTscPage;

        g_HvlpReferenceTscPage = tools::RipToAbsolute<PVOID *>(HvlpReferenceTscPage, 3, 7);
        DBGPRINT("g_HvlpReferenceTscPage = 0x%p", g_HvlpReferenceTscPage);

        ULONG_PTR HvlGetQpcBias = dyn::DynCtx.Kernel.HvlGetQpcBias;

        g_HvlGetQpcBias = tools::RipToAbsolute<PVOID *>(HvlGetQpcBias, 3, 7);
        DBGPRINT("g_HvlGetQpcBias = 0x%p", g_HvlGetQpcBias);

        g_HvlGetQpcBiasOriginal = InterlockedExchangePointer(g_HvlGetQpcBias, &hkHvlGetQpcBias);
        DBGPRINT("g_HvlGetQpcBiasOriginal = 0x%p", g_HvlGetQpcBiasOriginal);
    }

    const NTSTATUS status = PsCreateSystemThread(&g_WatchdogThreadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr,
                                                 &WatchdogThread, nullptr);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "PsCreateSystemThread returned %!STATUS!", status);

        CleanupInfinityHook();
        return FALSE;
    }

    return TRUE;
}

NTSTATUS
ModifyTraceSettings(_In_ const CKCL_TRACE_OPERATION &TraceOperation)
{
    PAGED_CODE();

    auto traceProperty = tools::AllocatePoolZero<CKCL_TRACE_PROPERTIES *>(NonPagedPool, PAGE_SIZE, tags::TAG_DEFAULT);
    if (!traceProperty)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL,
                      "Could not allocate "
                      "memory for trace properties!");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SCOPE_EXIT
    {
        ExFreePool(traceProperty);
    };

    traceProperty->Wnode.BufferSize = PAGE_SIZE;
    traceProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProperty->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
    traceProperty->Wnode.Guid = {0x54DEA73A, 0xED1F, 0x42A4, {0xAF, 0x71, 0x3E, 0x63, 0xD0, 0x56, 0xF1, 0x74}};
    traceProperty->Wnode.ClientContext = 1;
    traceProperty->BufferSize = sizeof(ULONG);
    traceProperty->MinimumBuffers = traceProperty->MaximumBuffers = 2;
    traceProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

    NTSTATUS status = STATUS_ACCESS_DENIED;
    ULONG returnLength = 0UL;

    switch (TraceOperation)
    {
    case CKCL_TRACE_START: {
        status = ZwTraceControl(EtwpStartTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_END: {
        status = ZwTraceControl(EtwpStopTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_SYSCALL: {
        traceProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
        status = ZwTraceControl(EtwpUpdateTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    }

    return status;
}

PVOID GetSyscallEntry()
{
    PAGED_CODE();

    PIMAGE_NT_HEADERS64 nth = RtlImageNtHeader(dyn::DynCtx.Kernel.Base);
    if (!nth)
    {
        return nullptr;
    }

    PVOID syscallEntry = reinterpret_cast<PVOID>(__readmsr(IA32_LSTAR_MSR));

    // If KVASCODE section does not exists it probably means the system does not support it.
    //
    PIMAGE_SECTION_HEADER section = tools::GetModuleSection(nth, "KVASCODE");
    if (!section)
    {
        return syscallEntry;
    }

    const PVOID sectionBase = reinterpret_cast<PUCHAR>(dyn::DynCtx.Kernel.Base) + section->VirtualAddress;
    const ULONG sectionSize = section->Misc.VirtualSize;

    // Is the value within this KVA shadow region? If not, we're done.
    //
    if (!(syscallEntry >= sectionBase && syscallEntry < reinterpret_cast<PUCHAR>(sectionBase) + sectionSize))
    {
        return syscallEntry;
    }

    // This is KiSystemCall64Shadow.
    //
    hde64s hde{};
    int totalBytesRead = 0;

    for (PUCHAR KiSystemServiceUser = reinterpret_cast<PUCHAR>(syscallEntry); /* */;
         KiSystemServiceUser, totalBytesRead += hde.len)
    {
        // Note: This jump should not be very far in theory so lets just try the next 512 bytes
        //
        if (totalBytesRead >= 512 || !hde64_disasm(KiSystemServiceUser, &hde))
        {
            break;
        }

        // Disassemble every instruction till the first near jmp (E9).
        //
        if (hde.opcode != 0xE9)
        {
            continue;
        }

        // Ignore jmps within the KVA shadow region.
        //
        syscallEntry = KiSystemServiceUser + static_cast<INT32>(hde.len) + static_cast<INT32>(hde.imm.imm32);
        if (syscallEntry >= sectionBase && syscallEntry < reinterpret_cast<PUCHAR>(sectionBase) + sectionSize)
        {
            continue;
        }

        // Found KiSystemServiceUser.
        //
        return syscallEntry;
    }
    return nullptr;
}

ULONG64
SyscallHookHandler(VOID)
{
#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

    if (ExGetPreviousMode() == KernelMode)
    {
        return __rdtsc();
    }

    const auto currentThread = __readgsqword(0x188);
    const ULONG systemCallIndex = *(ULONG *)(currentThread + 0x80); // KTHREAD->SystemCallNumber

    const auto stackMax = __readgsqword(KPCR_RSP_BASE);
    const PVOID *stackFrame = (PVOID *)_AddressOfReturnAddress();

    UINT offset = 0;

    // First walk backwards on the stack to find the 2 magic values.
    for (PVOID *stackCurrent = (PVOID *)stackMax; stackCurrent > stackFrame; --stackCurrent)
    {
        PULONG AsUlong = (PULONG)stackCurrent;
        if (*AsUlong != INFINITYHOOK_MAGIC_1)
        {
            continue;
        }

        // If the first magic is set, check for the second magic.
        --stackCurrent;

        PUSHORT AsShort = (PUSHORT)stackCurrent;
        if (*AsShort != INFINITYHOOK_MAGIC_2)
        {
            continue;
        }

        // Now we reverse the direction of the stack walk.
        for (; (ULONG_PTR)stackCurrent < stackMax; ++stackCurrent)
        {
            PULONGLONG AsUlonglong = (PULONGLONG)stackCurrent;

            if (!(PAGE_ALIGN(*AsUlonglong) >= g_SyscallTableAddress &&
                  PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)g_SyscallTableAddress + (PAGE_SIZE * 2))))
            {
                continue;
            }

            offset = (UINT)((ULONG_PTR)stackCurrent - (ULONG_PTR)stackFrame);
            break;
        }

        break;
    }

    if (offset)
    {
        PVOID *stackCurrent = (PVOID *)((ULONG_PTR)stackFrame + offset);

        if (*(ULONG_PTR *)stackCurrent >= (ULONG_PTR)g_SyscallTableAddress &&
            *(ULONG_PTR *)stackCurrent < ((ULONG_PTR)g_SyscallTableAddress + (PAGE_SIZE * 2)))
        {
            PVOID *systemCallFunction = &stackCurrent[9];

            if (g_SsdtCallback)
            {
                g_SsdtCallback(systemCallIndex, systemCallFunction);
            }
        }
    }

    return __rdtsc();
}

ULONG64
hkHvlGetQpcBias(VOID)
{
    SyscallHookHandler();

    return *((ULONG64 *)(*((ULONG64 *)g_HvlpReferenceTscPage)) + 3);
}
#endif