#include "includes.hpp"

NTSTATUS InitializeInfinityHook(_In_ SSDT_CALLBACK ssdtCallback)
{
    PAGED_CODE();
    NT_ASSERT(ssdtCallback);

    g_SsdtCallback = ssdtCallback;

    NTSTATUS status;

    ModifyTraceSettings(CKCL_TRACE_END);

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

    ULONG_PTR EtwpDebuggerData = dyn::DynCtx.Kernel.EtwpDebuggerData;
    DBGPRINT("EtwpDebuggerData = 0x%p", (void *)EtwpDebuggerData);

    auto *EtwpDebuggerDataSilo = *reinterpret_cast<PULONG_PTR *>(PTR_OFFSET_ADD(EtwpDebuggerData, 0x10));
    DBGPRINT("EtwpDebuggerDataSilo = 0x%p", EtwpDebuggerDataSilo);

    if (!MmIsAddressValid(EtwpDebuggerDataSilo))
    {
        return STATUS_UNSUCCESSFUL;
    }

    ULONG_PTR CkclWmiLoggerContext = EtwpDebuggerDataSilo[2];
    DBGPRINT("CkclWmiLoggerContext = 0x%p", (void *)CkclWmiLoggerContext);

    if (!CkclWmiLoggerContext)
    {
        return STATUS_UNSUCCESSFUL;
    }

    g_GetCpuClock = dyn::DynCtx.GetCpuClock(CkclWmiLoggerContext);
    DBGPRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);

    if (!MmIsAddressValid(g_GetCpuClock))
    {
        return STATUS_UNSUCCESSFUL;
    }

    PVOID syscallEntry = GetSyscallEntry();
    DBGPRINT("syscallEntry = 0x%p", syscallEntry);

    if (!syscallEntry)
    {
        return STATUS_UNSUCCESSFUL;
    }

    g_SyscallTableAddress = PAGE_ALIGN(syscallEntry);
    DBGPRINT("g_SyscallTableAddress = 0x%p", g_SyscallTableAddress);

    if (!g_SyscallTableAddress)
    {
        return STATUS_UNSUCCESSFUL;
    }

    return StartSyscallHook() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

void DeinitializeInfinityHook()
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

    // Restart trace session to ensure cleanup
    //
    NTSTATUS Status = ModifyTraceSettings(CKCL_TRACE_END);
    if (NT_SUCCESS(Status))
    {
        ModifyTraceSettings(CKCL_TRACE_START);
    }

    DBGPRINT("Deinitialized infinityhook");
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

        DeinitializeInfinityHook();
        return FALSE;
    }

    return TRUE;
}

NTSTATUS
ModifyTraceSettings(_In_ const CKCL_TRACE_OPERATION &traceOperation)
{
    PAGED_CODE();

    auto traceProperty = tools::AllocatePoolZero<PCKCL_TRACE_PROPERTIES>(NonPagedPool, PAGE_SIZE, tags::TAG_DEFAULT);
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

    auto providerName = tools::AllocatePoolZero<PWCH>(NonPagedPool, 0x1000, tags::TAG_STRING);
    if (!providerName)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL,
                      "Could not allocate "
                      "memory for provider name!");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SCOPE_EXIT
    {
        ExFreePool(providerName);
    };

    NTSTATUS status = RtlStringCchCopyW(providerName, 0x1000 / sizeof(wchar_t), L"Circular Kernel Context Logger");
    if (!providerName)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "RtlStringCchCopyW failed %!STATUS!", status);

        return status;
    }

    RtlInitUnicodeString(&traceProperty->ProviderName, providerName);
    traceProperty->Wnode.BufferSize = PAGE_SIZE;
    traceProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProperty->Wnode.Guid = CkclSessionGuid;
    traceProperty->Wnode.ClientContext = 1;
    traceProperty->BufferSize = sizeof(ULONG);
    traceProperty->MinimumBuffers = traceProperty->MaximumBuffers = 2;
    traceProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

    status = STATUS_ACCESS_DENIED;
    ULONG returnLength = 0UL;

    KPROCESSOR_MODE origMode = ExGetPreviousMode();
    if (origMode == UserMode)
    {
        tools::SetPreviousMode(KernelMode);
    }

    switch (traceOperation)
    {
    case CKCL_TRACE_START: {
        status = NtTraceControl(EtwpStartTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_END: {
        status = NtTraceControl(EtwpStopTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_SYSCALL: {
        traceProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
        status = NtTraceControl(EtwpUpdateTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    }

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "NtTraceControl returned %!STATUS! retLength: %u", status,
                  returnLength);

    tools::SetPreviousMode(origMode);
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

    const auto currentThread = reinterpret_cast<ULONG_PTR>(KeGetCurrentThread());
    const auto systemCallIndex = *(ULONG *)(currentThread + dyn::DynCtx.Offsets.SystemCallNumber);

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