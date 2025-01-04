#include "includes.hpp"

namespace masterhide
{
using namespace process;

namespace hooks
{
KMUTEX g_NtCloseMutex{};
bool g_initialized = false;

#define BACKUP_RETURNLENGTH()                                                                                          \
    ULONG TempReturnLength = 0;                                                                                        \
    if (ARGUMENT_PRESENT(ReturnLength))                                                                                \
    {                                                                                                                  \
        ProbeForWrite(ReturnLength, sizeof(ULONG), 1);                                                                 \
        TempReturnLength = *ReturnLength;                                                                              \
    }

#define RESTORE_RETURNLENGTH()                                                                                         \
    if (ARGUMENT_PRESENT(ReturnLength))                                                                                \
    (*ReturnLength) = TempReturnLength

HOOK_ENTRY g_HookList[] = {
    // NT
    //
    {
        "NtQuerySystemInformation",
        FALSE,
        &hkNtQuerySystemInformation,
    },
    {"NtSetInformationThread", FALSE, &hkNtSetInformationThread},
    {"NtQueryInformationThread", FALSE, &hkNtQueryInformationThread},
    {"NtSetInformationProcess", FALSE, &hkNtSetInformationProcess},
    {"NtQueryInformationProcess", FALSE, &hkNtQueryInformationProcess},
    {"NtQueryObject", FALSE, &hkNtQueryObject},
    {"NtCreateThreadEx", FALSE, &hkNtCreateThreadEx},
    {"NtGetContextThread", FALSE, &hkNtGetContextThread},
    {"NtSetContextThread", FALSE, &hkNtSetContextThread},
    {"NtContinue", FALSE, &hkNtContinue},
    {"NtYieldExecution", FALSE, &hkNtYieldExecution},
    {"NtClose", FALSE, &hkNtClose},
    {"NtSystemDebugControl", FALSE, &hkNtSystemDebugControl},
    {"NtQuerySystemTime", FALSE, &hkNtQuerySystemTime},
    {"NtQueryPerformanceCounter", FALSE, &hkNtQueryPerformanceCounter},
    {"NtQueryInformationJobObject", FALSE, &hkNtQueryInformationJobObject},
    {"NtGetNextProcess", FALSE, &hkNtGetNextProcess},
    {"NtCreateUserProcess", FALSE, &hkNtCreateUserProcess},
    //{"NtCreateFile", FALSE, &hkNtCreateFile},
    // Win32K
    //
    {"NtUserWindowFromPoint", TRUE, &hkNtUserWindowFromPoint},
    {"NtUserQueryWindow", TRUE, &hkNtUserQueryWindow},
    {"NtUserFindWindowEx", TRUE, &hkNtUserFindWindowEx},
    {"NtUserBuildHwndList", TRUE, &hkNtUserBuildHwndList},
    {"NtUserGetForegroundWindow", TRUE, &hkNtUserGetForegroundWindow},
    {"NtUserGetThreadState", TRUE, nullptr},
};

FORCEINLINE PHOOK_ENTRY FindHookEntry(_In_ FNV1A_t serviceNameHash)
{
    for (auto &entry : g_HookList)
    {
        if (serviceNameHash == FNV1A::Hash(entry.ServiceName))
        {
            return &entry;
        }
    }

    NT_ASSERT(FALSE);

#if !DBG
    __fastfail(FAST_FAIL_INVALID_ARG);
#endif

    return nullptr;
}

void __fastcall SsdtCallback(ULONG ServiceIndex, PVOID *ServiceAddress)
{
    for (HOOK_ENTRY &entry : g_HookList)
    {
        if (ServiceIndex == entry.ServiceIndex)
        {
            if (entry.OriginalFunc == nullptr)
            {
                entry.OriginalFunc = *ServiceAddress;
            }

            if (entry.NewFunc)
            {
                *ServiceAddress = entry.NewFunc;
            }

            return;
        }
    }
}

[[nodiscard]] static NTSTATUS CreateHooks()
{
    PAGED_CODE();

    for (HOOK_ENTRY &entry : g_HookList)
    {
        KeInitializeEvent(&entry.Event, NotificationEvent, TRUE);
        entry.RefCount.SetEvent(&entry.Event);

        // Some actions has to be done based on Windows builds
        //
        USHORT serviceIndex = MAXUSHORT;

        if (KERNEL_BUILD_VERSION <= WINDOWS_7_SP1)
        {
            if (!strcmp(entry.ServiceName, "NtUserBuildHwndList"))
            {
                entry.NewFunc = &hkNtUserBuildHwndList_Win7;
            }
        }
        else if (KERNEL_BUILD_VERSION >= WINDOWS_10_VERSION_20H1)
        {
            if (!strcmp(entry.ServiceName, "NtContinue"))
            {
                serviceIndex = syscalls::GetSyscallIndexByName("NtContinueEx");
                goto validateIndex;
            }
        }

        // NtQuerySystemTime is not exported by ntdll.dll so we have to obtain the index that way
        //
        if (!strcmp(entry.ServiceName, "NtQuerySystemTime"))
        {
            serviceIndex = syscalls::GetSyscallIndexByName("NtAccessCheckByTypeAndAuditAlarm");
            if (serviceIndex == MAXUSHORT)
            {
                WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Could not find index for service NtQuerySystemTime");
                return STATUS_PROCEDURE_NOT_FOUND;
            }
            serviceIndex += 1;
        }
        else
        {
            serviceIndex = syscalls::GetSyscallIndexByName(entry.ServiceName);
        }

    validateIndex:
        if (serviceIndex == MAXUSHORT)
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Could not find index for service %s", entry.ServiceName);
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        entry.ServiceIndex = serviceIndex;

        if (MASTERHIDE_HOOK_TYPE == HookTypeKasperskyHook)
        {
            if (entry.Win32k)
            {
                if (!kaspersky::hook_shadow_ssdt_routine(entry.ServiceIndex, entry.NewFunc,
                                                         reinterpret_cast<PVOID *>(&entry.OriginalFunc)))
                {
                    return STATUS_UNSUCCESSFUL;
                }
            }
            else
            {
                if (!kaspersky::hook_ssdt_routine(entry.ServiceIndex, entry.NewFunc,
                                                  reinterpret_cast<PVOID *>(&entry.OriginalFunc)))
                {
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }
        else if (MASTERHIDE_HOOK_TYPE == HookTypeInfinityHook)
        {
            // Nothing has to be done, relevant action is already done at SsdtCallback
        }

        DBGPRINT("Created hook for service %s at index %u", entry.ServiceName, entry.ServiceIndex);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS UninstallHooks()
{
    PAGED_CODE();

    if (MASTERHIDE_HOOK_TYPE == HookTypeInfinityHook)
    {
        DeinitializeInfinityHook();
    }

    for (HOOK_ENTRY &entry : g_HookList)
    {
        if (MASTERHIDE_HOOK_TYPE == HookTypeKasperskyHook)
        {
            if (entry.Win32k)
            {
                if (!kaspersky::unhook_shadow_ssdt_routine(entry.ServiceIndex, entry.OriginalFunc))
                {
                    return STATUS_UNSUCCESSFUL;
                }
            }
            else
            {
                if (!kaspersky::unhook_ssdt_routine(entry.ServiceIndex, entry.OriginalFunc))
                {
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }

        DBGPRINT("Waiting for references in %s", entry.ServiceName);

        const NTSTATUS status = entry.RefCount.Wait();
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Could not wait for hook %s reference count %!STATUS!",
                          entry.ServiceName, status);
            return status;
        }

        entry.OriginalFunc = nullptr;
    }

    return STATUS_SUCCESS;
}

NTSTATUS Initialize()
{
    PAGED_CODE();
    NT_ASSERT(!g_initialized);

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    NTSTATUS status = STATUS_SUCCESS;

    KeInitializeMutex(&g_NtCloseMutex, 0);

    if (MASTERHIDE_HOOK_TYPE == HookTypeKasperskyHook)
    {
        DBGPRINT("Using kaspersky hook.");

        if (!::utils::init())
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to initialize utils!");
            return STATUS_UNSUCCESSFUL;
        }

        if (!kaspersky::is_klhk_loaded() || !kaspersky::initialize())
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to load kaspersky!");
            return STATUS_UNSUCCESSFUL;
        }

        status = kaspersky::hvm_init();
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "hvm_init returned %!STATUS!", status);
            return STATUS_UNSUCCESSFUL;
        }

        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Kaspersky hypervisor is set up!");
    }
    else if (MASTERHIDE_HOOK_TYPE == HookTypeInfinityHook)
    {
        status = InitializeInfinityHook(&SsdtCallback);
        if (!NT_SUCCESS(status))
        {
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "InitializeInfinityHook returned %!STATUS!", status);
            return STATUS_UNSUCCESSFUL;
        }
    }

    status = CreateHooks();
    if (!NT_SUCCESS(status))
    {
        if (MASTERHIDE_HOOK_TYPE == HookTypeInfinityHook)
        {
            DeinitializeInfinityHook();
        }

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "CreateHooks returned %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    g_initialized = true;

    return status;
}

void Deinitialize()
{
    PAGED_CODE();

    if (!g_initialized)
    {
        return;
    }

    const NTSTATUS status = UninstallHooks();
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_WARNING, GENERAL,
                      "UninstallHooks returned %!STATUS!, one of more hooks where not successfully unninstalled!",
                      status);
    }

    g_initialized = false;

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Successfully de-initialized hooks interface!");
    return;
}

NTSTATUS NTAPI hkNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtQuerySystemTime"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a ruled process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtQuerySystemTime))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                __try
                {
                    ProbeForWrite(SystemTime, sizeof(ULONG64), 4);

                    if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideKUserSharedData))
                    {
                        SystemTime->QuadPart = *(ULONG64 *)&processEntry->Kusd.KuserSharedData->SystemTime;
                    }
                    else
                    {
                        if (processEntry->FakeSystemTime.QuadPart == NULL)
                        {
                            KeQuerySystemTime(&processEntry->FakeSystemTime);
                        }

                        SystemTime->QuadPart = processEntry->FakeSystemTime.QuadPart;
                        processEntry->FakeSystemTime.QuadPart += 1;
                    }

                    status = STATUS_SUCCESS;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                }

                handled = true;
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtQuerySystemTime)>(hookEntry->OriginalFunc)(SystemTime);
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "NtQuerySystemTime from pid %u returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtQuerySystemTime)>(hookEntry->OriginalFunc)(SystemTime);
}

NTSTATUS NTAPI hkNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtQueryPerformanceCounter"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a ruled process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtQueryPerformanceCounter))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                __try
                {
                    ProbeForWrite(PerformanceCounter, sizeof(ULONG64), 4);

                    if (PerformanceFrequency != NULL)
                    {
                        ProbeForWrite(PerformanceFrequency, sizeof(ULONG64), 4);
                    }

                    if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideKUserSharedData))
                    {
                        PerformanceCounter->QuadPart = processEntry->Kusd.KuserSharedData->BaselineSystemTimeQpc;
                    }
                    else
                    {
                        if (processEntry->FakePerformanceCounter.QuadPart == NULL)
                        {
                            processEntry->FakePerformanceCounter = KeQueryPerformanceCounter(NULL);
                        }

                        PerformanceCounter->QuadPart = processEntry->FakePerformanceCounter.QuadPart;
                        processEntry->FakePerformanceCounter.QuadPart += 1;
                    }

                    if (PerformanceFrequency != NULL)
                    {
                        PerformanceFrequency->QuadPart = KuserSharedData->QpcFrequency;
                    }

                    status = STATUS_SUCCESS;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                }

                handled = true;
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtQueryPerformanceCounter)>(hookEntry->OriginalFunc)(
                    PerformanceCounter, PerformanceFrequency);
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtQueryPerformanceCounter from pid %u returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtQueryPerformanceCounter)>(hookEntry->OriginalFunc)(PerformanceCounter,
                                                                                             PerformanceFrequency);
}

NTSTATUS NTAPI hkNtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength,
                                      PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtSystemDebugControl"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a ruled process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtSystemDebugControl))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                if (Command != SysDbgGetTriageDump && Command != SysDbgGetLiveKernelDump)
                {
                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                  "Spoofed NtSystemDebugControl(commad:%d) anti-debug query!", Command);

                    status = STATUS_DEBUGGER_INACTIVE;
                    handled = true;
                }
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtSystemDebugControl)>(hookEntry->OriginalFunc)(
                    Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtSystemDebugControl from pid %u Command %u returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), Command, status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtSystemDebugControl)>(hookEntry->OriginalFunc)(
        Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
}

NTSTATUS NTAPI hkNtClose(HANDLE Handle)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtClose"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a ruled process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtClose))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                // If two or more threads were to simultaneously check and act on this information without
                // synchronization, it might lead to inconsistent states where a handle that is meant to be
                // protected gets closed, or an exception is raised improperly.
                KeWaitForSingleObject(&g_NtCloseMutex, Executive, KernelMode, FALSE, nullptr);

                OBJECT_HANDLE_ATTRIBUTE_INFORMATION handleAttribInfo{};

                status =
                    reinterpret_cast<decltype(&hkNtQueryObject)>(FindHookEntry(FNV("NtQueryObject"))->OriginalFunc)(
                        Handle, static_cast<OBJECT_INFORMATION_CLASS>(ObjectDataInformation), &handleAttribInfo,
                        sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION), nullptr);

                if (status == STATUS_INVALID_HANDLE)
                {
                    KeReleaseMutex(&g_NtCloseMutex, FALSE);

                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Spoofed NtClose(Invalid Handle) anti-debug query!");

                    if (processEntry->Flags.ProcessHandleTracingEnabled)
                    {
                        return KeRaiseUserException(STATUS_INVALID_HANDLE);
                    }

                    status = STATUS_INVALID_HANDLE;
                    handled = true;
                }

                if (NT_SUCCESS(status))
                {
                    if (handleAttribInfo.ProtectFromClose == TRUE)
                    {
                        KeReleaseMutex(&g_NtCloseMutex, FALSE);

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtClose(ProtectFromClose) anti-debug query!");

                        if (processEntry->Flags.ProcessHandleTracingEnabled)
                        {
                            return KeRaiseUserException(STATUS_HANDLE_NOT_CLOSABLE);
                        }

                        status = STATUS_HANDLE_NOT_CLOSABLE;
                        handled = true;
                    }
                }

                KeReleaseMutex(&g_NtCloseMutex, FALSE);
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtClose)>(hookEntry->OriginalFunc)(Handle);
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "NtClose from pid %ureturned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtClose)>(hookEntry->OriginalFunc)(Handle);
}

NTSTATUS NTAPI hkNtYieldExecution()
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtYieldExecution"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a ruled process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtYieldExecution))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Spoofed NtYieldExecution anti-debug query!");

                reinterpret_cast<decltype(&hkNtYieldExecution)>(hookEntry->OriginalFunc)();
                status = STATUS_SUCCESS;
                handled = true;
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtYieldExecution)>(hookEntry->OriginalFunc)();
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "NtYieldExecution from pid %ureturned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), status);
            }
        }
    }
    return reinterpret_cast<decltype(&hkNtYieldExecution)>(hookEntry->OriginalFunc)();
}

NTSTATUS NTAPI hkNtContinue(PCONTEXT Context, ULONG64 TestAlert)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtContinue"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a ruled process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtContinue))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                __try
                {
                    ProbeForRead(Context, sizeof(*Context), __alignof(_CONTEXT));

                    PTHREAD_ENTRY threadEntry = processEntry->AppendThreadList(PsGetCurrentThread());

                    if ((Context->Dr0 != __readdr(0) && Context->Dr1 != __readdr(1) && Context->Dr2 != __readdr(2) &&
                         Context->Dr3 != __readdr(3) && Context->ContextFlags & 0x10 && threadEntry))
                    {
                        RtlCopyMemory(&threadEntry->SavedDebugContext.Dr0, &Context->Dr0, sizeof(ULONG64) * 6);
                        RtlCopyMemory(&threadEntry->SavedDebugContext.DebugControl, &Context->DebugControl,
                                      sizeof(ULONG64) * 5);
                    }

                    Context->ContextFlags &= ~0x10;

                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Spoofed NtContinue anti-debug query!");

                    status = reinterpret_cast<decltype(&hkNtContinue)>(hookEntry->OriginalFunc)(Context, TestAlert);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                }

                handled = true;
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtContinue)>(hookEntry->OriginalFunc)(Context, TestAlert);
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "NtContinue from pid %u returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtContinue)>(hookEntry->OriginalFunc)(Context, TestAlert);
}

NTSTATUS NTAPI hkNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags,
                                  PHANDLE NewProcessHandle)
{
    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtGetNextProcess"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    NTSTATUS status = reinterpret_cast<decltype(&hkNtGetNextProcess)>(hookEntry->OriginalFunc)(
        ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a ruled process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtGetNextProcess))
        {
            __try
            {
                // No probe is required in this context, we already check if function return successful status.
                //
                if (NT_SUCCESS(status) && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                {
                    PEPROCESS process = nullptr;
                    if (NT_SUCCESS(ObReferenceObjectByHandle(*NewProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION,
                                                             *PsProcessType, previousMode,
                                                             reinterpret_cast<PVOID *>(&process), nullptr)))
                    {
                        if (IsProtectedProcess(process))
                        {
                            HANDLE oldHandleValue = *NewProcessHandle;

                            status = reinterpret_cast<decltype(&hkNtGetNextProcess)>(hookEntry->OriginalFunc)(
                                *NewProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);

                            ObCloseHandle(oldHandleValue, UserMode);
                        }

                        ObDereferenceObject(process);
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "NtGetNextProcess from pid %u returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), status);
            }
        }
    }
    return status;
}

NTSTATUS NTAPI hkNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                        PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtSetInformationThread"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtSetInformationThread))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger) &&
                (ThreadInformationClass == ThreadHideFromDebugger || ThreadInformationClass == ThreadWow64Context ||
                 ThreadInformationClass == ThreadBreakOnTermination))
            {
                __try
                {
                    if (ThreadInformationLength != 0)
                    {
                        ProbeForRead(ThreadInformation, ThreadInformationLength, TYPE_ALIGNMENT(ULONG));
                    }

                    PETHREAD thread = nullptr;

                    if (ThreadHandle == ZwCurrentThread())
                    {
                        thread = PsGetCurrentThread();
                    }
                    else
                    {
                        status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                           previousMode, reinterpret_cast<PVOID *>(&thread), nullptr);
                        if (!NT_SUCCESS(status))
                        {
                            goto Exit;
                        }

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(thread);
                        };
                    }

                    PPROCESS_ENTRY threadProcessEntry = GetProcessEntry(PsGetThreadProcessId(thread));

                    SCOPE_EXIT
                    {
                        if (threadProcessEntry)
                        {
                            object::DereferenceObject(threadProcessEntry);
                            threadProcessEntry = nullptr;
                        }
                    };

                    if (threadProcessEntry &&
                        BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagNtSetInformationThread))
                    {
                        if (BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                        {
                            if (ThreadInformationClass == ThreadHideFromDebugger)
                            {
                                if (ThreadInformationLength != 0)
                                {
                                    status = STATUS_INFO_LENGTH_MISMATCH;
                                    goto Exit;
                                }

                                PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    threadEntry->Flags.IsThreadHidden = TRUE;

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtSetInformationThread(ThreadHideFromDebugger) tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }

                                status = STATUS_SUCCESS;
                                handled = true;
                            }
                            else if (ThreadInformationClass == ThreadWow64Context)
                            {
                                if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
                                {
                                    status = STATUS_INFO_LENGTH_MISMATCH;
                                    goto Exit;
                                }

                                PVOID WoW64Process = PsGetCurrentProcessWow64Process();
                                if (!WoW64Process)
                                {
                                    status = STATUS_INVALID_PARAMETER;
                                    goto Exit;
                                }

                                auto Wow64Context = static_cast<PWOW64_CONTEXT>(ThreadInformation);
                                ULONG OriginalFlags = Wow64Context->ContextFlags;

                                Wow64Context->ContextFlags &= ~0x10;

                                status = reinterpret_cast<decltype(&hkNtSetInformationThread)>(hookEntry->OriginalFunc)(
                                    ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

                                if (OriginalFlags & 0x10)
                                {
                                    Wow64Context->ContextFlags |= 0x10;

                                    PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                    if (threadEntry)
                                    {
                                        RtlCopyMemory(&threadEntry->SavedWow64DebugContext, &Wow64Context->Dr0,
                                                      sizeof(ULONG) * 6);

                                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                      "Spoofed NtSetInformationThread(ThreadWow64Context) tid:%d",
                                                      HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                    }
                                }

                                handled = true;
                            }
                            else if (ThreadInformationClass == ThreadBreakOnTermination)
                            {
                                if (ThreadInformationLength != sizeof(ULONG))
                                {
                                    status = STATUS_INFO_LENGTH_MISMATCH;
                                    goto Exit;
                                }

                                volatile ULONG Touch = *(ULONG *)ThreadInformation;
                                UNREFERENCED_PARAMETER(Touch);

                                // Caller process needs debug privileges
                                //
                                if (!tools::HasDebugPrivilege())
                                {
                                    status = STATUS_PRIVILEGE_NOT_HELD;
                                    goto Exit;
                                }

                                PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    threadEntry->Flags.BreakOnTermination = *(ULONG *)ThreadInformation ? TRUE : FALSE;

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtSetInformationThread(ThreadBreakOnTermination) tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }

                                status = STATUS_SUCCESS;
                                handled = true;
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    handled = true;
                }
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtSetInformationThread)>(hookEntry->OriginalFunc)(
                    ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
            }

        Exit:
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtSetInformationThread from pid %u ThreadHandle = 0x%p ThreadInformationClass %d "
                              "returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), ThreadHandle, ThreadInformationClass, status);
            }
            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtSetInformationThread)>(hookEntry->OriginalFunc)(
        ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI hkNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                          PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtQueryInformationThread"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtQueryInformationThread))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger) && ThreadInformation &&
                (ThreadInformationClass == ThreadHideFromDebugger ||
                 ThreadInformationClass == ThreadBreakOnTermination || ThreadInformationClass == ThreadWow64Context))
            {
                NTSTATUS status = STATUS_SUCCESS;
                bool handled = false;

                __try
                {
                    const ULONG alignment = ThreadInformationLength < 4 ? 1 : 4;

                    if (ThreadInformationLength != 0)
                    {
                        ProbeForWrite(ThreadInformation, ThreadInformationLength, alignment);
                    }

                    if (ARGUMENT_PRESENT(ReturnLength))
                    {
                        ProbeForWrite(ReturnLength, sizeof(*ReturnLength), 1);
                    }

                    PETHREAD thread = nullptr;

                    if (ThreadHandle == ZwCurrentThread())
                    {
                        thread = PsGetCurrentThread();
                    }
                    else
                    {
                        status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                           previousMode, reinterpret_cast<PVOID *>(&thread), nullptr);
                        if (!NT_SUCCESS(status))
                        {
                            goto Exit;
                        }

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(thread);
                        };
                    }

                    PPROCESS_ENTRY threadProcessEntry = GetProcessEntry(PsGetThreadProcessId(thread));

                    SCOPE_EXIT
                    {
                        if (threadProcessEntry)
                        {
                            object::DereferenceObject(threadProcessEntry);
                            threadProcessEntry = nullptr;
                        }
                    };

                    // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
                    //
                    if (threadProcessEntry &&
                        BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagNtQueryInformationThread))
                    {
                        if (BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                        {
                            PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                            if (threadEntry)
                            {
                                if (ThreadInformationClass == ThreadHideFromDebugger)
                                {
                                    if (ThreadInformationLength != 1)
                                    {
                                        status = STATUS_INFO_LENGTH_MISMATCH;
                                        goto Exit;
                                    }

                                    *(BOOLEAN *)ThreadInformation = threadEntry->Flags.IsThreadHidden;

                                    if (ReturnLength != 0)
                                    {
                                        *ReturnLength = 1;
                                    }

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtQueryInformationThread(ThreadHideFromDebugger) tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));

                                    status = STATUS_SUCCESS;
                                    handled = true;
                                }
                                else if (ThreadInformationClass == ThreadBreakOnTermination)
                                {
                                    if (ThreadInformationLength != 4)
                                    {
                                        status = STATUS_INFO_LENGTH_MISMATCH;
                                        goto Exit;
                                    }

                                    *(ULONG *)ThreadInformation = threadEntry->Flags.BreakOnTermination;

                                    if (ReturnLength != NULL)
                                    {
                                        *ReturnLength = 4;
                                    }

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtQueryInformationThread(ThreadBreakOnTermination) tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));

                                    status = STATUS_SUCCESS;
                                    handled = true;
                                }
                                else if (ThreadInformationClass == ThreadWow64Context)
                                {
                                    if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
                                    {
                                        status = STATUS_INFO_LENGTH_MISMATCH;
                                        goto Exit;
                                    }

                                    PWOW64_CONTEXT Context = PWOW64_CONTEXT(ThreadInformation);
                                    ULONG OriginalFlags = Context->ContextFlags;

                                    Context->ContextFlags &= ~0x10;

                                    status = reinterpret_cast<decltype(&hkNtQueryInformationThread)>(
                                        hookEntry->OriginalFunc)(ThreadHandle, ThreadInformationClass,
                                                                 ThreadInformation, ThreadInformationLength,
                                                                 ReturnLength);

                                    if (NT_SUCCESS(status) && OriginalFlags & 0x10)
                                    {
                                        Context->ContextFlags |= 0x10;

                                        RtlCopyMemory(&Context->Dr0, &threadEntry->SavedWow64DebugContext,
                                                      sizeof(ULONG) * 6);

                                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                      "Spoofed NtQueryInformationThread(ThreadWow64Context) tid:%d",
                                                      HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                    }

                                    handled = true;
                                }
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    handled = true;
                }

                if (!handled)
                {
                    status = reinterpret_cast<decltype(&hkNtQueryInformationThread)>(hookEntry->OriginalFunc)(
                        ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
                }

            Exit:
                if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
                {
                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                  "NtQueryInformationThread from pid %u ThreadHandle = 0x%p ThreadInformationClass %d "
                                  "returned %!STATUS!\n",
                                  HandleToUlong(PsGetCurrentProcessId()), ThreadHandle, ThreadInformationClass, status);
                }

                return status;
            }
        }
    }
    return reinterpret_cast<decltype(&hkNtQueryInformationThread)>(hookEntry->OriginalFunc)(
        ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

NTSTATUS NTAPI hkNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                           PVOID ProcessInformation, ULONG ProcessInformationLength,
                                           PULONG ReturnLength)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtQueryInformationProcess"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtQueryInformationProcess))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger) &&
                (ProcessInformationClass == ProcessDebugObjectHandle || ProcessInformationClass == ProcessDebugPort ||
                 ProcessInformationClass == ProcessDebugFlags || ProcessInformationClass == ProcessBreakOnTermination ||
                 ProcessInformationClass == ProcessBasicInformation || ProcessInformationClass == ProcessIoCounters ||
                 ProcessInformationClass == ProcessInstrumentationCallback ||
                 ProcessInformationClass == ProcessHandleTracing))
            {
                NTSTATUS status = STATUS_SUCCESS;
                bool handled = false;

                __try
                {
                    if (ProcessInformationLength != 0)
                    {
                        ProbeForWrite(ProcessInformation, ProcessInformationLength, 4);
                    }

                    if (ReturnLength != 0)
                    {
                        ProbeForWrite(ReturnLength, sizeof(*ReturnLength), 1);
                    }

                    PEPROCESS process = nullptr;

                    if (ProcessHandle == ZwCurrentProcess())
                    {
                        process = PsGetCurrentProcess();
                    }
                    else
                    {
                        status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType,
                                                           previousMode, reinterpret_cast<PVOID *>(&process), nullptr);
                        if (!NT_SUCCESS(status))
                        {
                            goto Exit;
                        }

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(process);
                        };
                    }

                    PPROCESS_ENTRY threadProcessEntry = GetProcessEntry(PsGetProcessId(process));

                    SCOPE_EXIT
                    {
                        if (threadProcessEntry)
                        {
                            object::DereferenceObject(threadProcessEntry);
                            threadProcessEntry = nullptr;
                        }
                    };

                    if (threadProcessEntry &&
                        BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagNtQueryInformationProcess))
                    {
                        if (BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                        {
                            if (ProcessInformationClass == ProcessDebugObjectHandle)
                            {
                                *static_cast<PHANDLE>(ProcessInformation) = nullptr;

                                if (ReturnLength != nullptr)
                                {
                                    *ReturnLength = sizeof(HANDLE);
                                }

                                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                              "Spoofed NtQueryInformationProcess(ProcessDebugObjectHandle) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                status = STATUS_PORT_NOT_SET;
                                handled = true;
                            }
                            else if (ProcessInformationClass == ProcessInstrumentationCallback &&
                                     BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                   ProcessPolicyFlagBypassInstrumentationCallback))
                            {
                                WppTracePrint(
                                    TRACE_LEVEL_VERBOSE, GENERAL,
                                    "Spoofed NtQueryInformationProcess(ProcessInstrumentationCallback) tid:%d",
                                    HandleToUlong(threadProcessEntry->ProcessId));

                                status = STATUS_INVALID_INFO_CLASS;
                                handled = true;
                            }
                            else if (ProcessInformationClass == ProcessDebugPort)
                            {
                                BACKUP_RETURNLENGTH();

                                *(static_cast<PHANDLE>(ProcessInformation)) = nullptr;

                                if (ReturnLength != nullptr)
                                {
                                    *ReturnLength = sizeof(HANDLE);
                                }

                                RESTORE_RETURNLENGTH();

                                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                              "Spoofed NtQueryInformationProcess(ProcessDebugPort) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                status = STATUS_SUCCESS;
                                handled = true;
                            }
                            else if (ProcessInformationClass == ProcessDebugFlags)
                            {
                                BACKUP_RETURNLENGTH();

                                *((ULONG *)ProcessInformation) =
                                    ((threadProcessEntry->Flags.ValueProcessDebugFlags & PROCESS_NO_DEBUG_INHERIT) != 0)
                                        ? 0
                                        : PROCESS_DEBUG_INHERIT;

                                if (ReturnLength != nullptr)
                                {
                                    *ReturnLength = sizeof(ULONG);
                                }

                                RESTORE_RETURNLENGTH();

                                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                              "Spoofed NtQueryInformationProcess(ProcessDebugFlags) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                status = STATUS_SUCCESS;
                                handled = true;
                            }
                            else if (ProcessInformationClass == ProcessBreakOnTermination)
                            {
                                BACKUP_RETURNLENGTH();

                                *((ULONG *)ProcessInformation) =
                                    threadProcessEntry->Flags.ValueProcessBreakOnTermination;

                                RESTORE_RETURNLENGTH();

                                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                              "Spoofed NtQueryInformationProcess(ProcessBreakOnTermination) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                status = STATUS_SUCCESS;
                                handled = true;
                            }

                            status = reinterpret_cast<decltype(&hkNtQueryInformationProcess)>(hookEntry->OriginalFunc)(
                                ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength,
                                ReturnLength);

                            if (NT_SUCCESS(status))
                            {
                                if (ProcessInformationClass == ProcessBasicInformation) // Fake parent
                                {
                                    BACKUP_RETURNLENGTH();

                                    PEPROCESS parentProcess =
                                        tools::GetProcessByName(threadProcessEntry->FakeParentProcessName);
                                    if (parentProcess)
                                    {
                                        (static_cast<PPROCESS_BASIC_INFORMATION>(ProcessInformation))
                                            ->InheritedFromUniqueProcessId =
                                            HandleToUlong(PsGetProcessId(parentProcess));

                                        ObDereferenceObject(parentProcess);
                                    }

                                    RESTORE_RETURNLENGTH();

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtQueryInformationProcess(ProcessBasicInformation) tid:%d",
                                                  HandleToUlong(threadProcessEntry->ProcessId));

                                    status = STATUS_SUCCESS;
                                    handled = true;
                                }

                                else if (ProcessInformationClass == ProcessHandleTracing)
                                {
                                    BACKUP_RETURNLENGTH();
                                    RESTORE_RETURNLENGTH(); // Trigger any possible exceptions caused by messing
                                                            // with the output buffer before changing the final
                                                            // return status

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtQueryInformationProcess(ProcessHandleTracing) tid:%d",
                                                  HandleToUlong(threadProcessEntry->ProcessId));

                                    status = threadProcessEntry->Flags.ProcessHandleTracingEnabled
                                                 ? STATUS_SUCCESS
                                                 : STATUS_INVALID_PARAMETER;
                                    handled = true;
                                }
                                else if (ProcessInformationClass == ProcessIoCounters)
                                {
                                    BACKUP_RETURNLENGTH();

                                    ((PIO_COUNTERS)ProcessInformation)->OtherOperationCount = 1;

                                    RESTORE_RETURNLENGTH();

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtQueryInformationProcess(ProcessIoCounters) tid:%d",
                                                  HandleToUlong(threadProcessEntry->ProcessId));

                                    status = STATUS_SUCCESS;
                                    handled = true;
                                }
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    handled = true;
                }

                if (!handled)
                {
                    status = reinterpret_cast<decltype(&hkNtQueryInformationProcess)>(hookEntry->OriginalFunc)(
                        ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength,
                        ReturnLength);
                }

            Exit:
                if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
                {
                    WppTracePrint(
                        TRACE_LEVEL_VERBOSE, GENERAL,
                        "NtQueryInformationProcess from pid %u ProcessHandle = 0x%p ProcessInformationClass %d "
                        "returned %!STATUS!\n",
                        HandleToUlong(PsGetCurrentProcessId()), ProcessHandle, ProcessInformationClass, status);
                }

                return status;
            }
        }
    }
    return reinterpret_cast<decltype(&hkNtQueryInformationProcess)>(hookEntry->OriginalFunc)(
        ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI hkNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                         PVOID ProcessInformation, ULONG ProcessInformationLength)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtSetInformationProcess"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtSetInformationProcess))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger) &&
                (ProcessInformationClass == ProcessBreakOnTermination || ProcessInformationClass == ProcessDebugFlags ||
                 ProcessInformationClass == ProcessInstrumentationCallback ||
                 ProcessInformationClass == ProcessHandleTracing))
            {
                NTSTATUS status = STATUS_SUCCESS;
                bool handled = false;

                __try
                {
                    if (ProcessInformationLength != 0)
                    {
                        ProbeForRead(ProcessInformation, ProcessInformationLength, 1);
                    }

                    PEPROCESS process = nullptr;

                    if (ProcessHandle == ZwCurrentProcess())
                    {
                        process = PsGetCurrentProcess();
                    }
                    else
                    {
                        status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType,
                                                           previousMode, reinterpret_cast<PVOID *>(&process), nullptr);
                        if (!NT_SUCCESS(status))
                        {
                            goto Exit;
                        }

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(process);
                        };
                    }

                    PPROCESS_ENTRY threadProcessEntry = GetProcessEntry(PsGetProcessId(process));

                    SCOPE_EXIT
                    {
                        if (threadProcessEntry)
                        {
                            object::DereferenceObject(threadProcessEntry);
                            threadProcessEntry = nullptr;
                        }
                    };

                    if (threadProcessEntry &&
                        BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagNtSetInformationProcess))
                    {
                        if (ProcessInformationClass == ProcessBreakOnTermination)
                        {
                            if (ProcessInformationLength != sizeof(ULONG))
                            {
                                status = STATUS_INFO_LENGTH_MISMATCH;
                                goto Exit;
                            }

                            volatile ULONG Touch = *(ULONG *)ProcessInformation;
                            UNREFERENCED_PARAMETER(Touch);

                            // A process must have debug privileges enabled to set the ProcessBreakOnTermination
                            // flag
                            if (!tools::HasDebugPrivilege())
                            {
                                status = STATUS_PRIVILEGE_NOT_HELD;
                                goto Exit;
                            }

                            threadProcessEntry->Flags.ValueProcessBreakOnTermination = *(ULONG *)ProcessInformation & 1;

                            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                          "Spoofed NtSetInformationProcess(ProcessBreakOnTermination) tid:%d",
                                          HandleToUlong(threadProcessEntry->ProcessId));

                            status = STATUS_SUCCESS;
                            handled = true;
                        }
                        else if (ProcessInformationClass == ProcessInstrumentationCallback &&
                                 BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                               ProcessPolicyFlagBypassInstrumentationCallback))
                        {
                            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                          "Spoofed NtSetInformationProcess(ProcessInstrumentationCallback) tid:%d",
                                          HandleToUlong(threadProcessEntry->ProcessId));

                            status = STATUS_SUCCESS;
                            handled = true;
                        }
                        else if (ProcessInformationClass == ProcessDebugFlags)
                        {
                            if (ProcessInformationLength != sizeof(ULONG))
                            {
                                status = STATUS_INFO_LENGTH_MISMATCH;
                                goto Exit;
                            }

                            ULONG Flags = *(ULONG *)ProcessInformation;
                            if ((Flags & ~PROCESS_DEBUG_INHERIT) != 0)
                            {
                                status = STATUS_INVALID_PARAMETER;
                                goto Exit;
                            }

                            if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
                            {
                                threadProcessEntry->Flags.ValueProcessDebugFlags = 0;
                            }
                            else
                            {
                                threadProcessEntry->Flags.ValueProcessDebugFlags = TRUE;
                            }

                            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                          "Spoofed NtSetInformationProcess(ProcessDebugFlags) tid:%d",
                                          HandleToUlong(threadProcessEntry->ProcessId));

                            status = STATUS_SUCCESS;
                            handled = true;
                        }
                        else if (ProcessInformationClass == ProcessHandleTracing)
                        {
                            const bool enable = ProcessInformationLength != 0;
                            if (enable)
                            {
                                if (ProcessInformationLength != sizeof(ULONG) &&
                                    ProcessInformationLength != (sizeof(ULONG64)))
                                {
                                    status = STATUS_INFO_LENGTH_MISMATCH;
                                    goto Exit;
                                }

                                auto *phtEx = static_cast<PPROCESS_HANDLE_TRACING_ENABLE_EX>(ProcessInformation);
                                if (phtEx->Flags != 0)
                                {
                                    status = STATUS_INVALID_PARAMETER;
                                    goto Exit;
                                }
                            }

                            processEntry->Flags.ProcessHandleTracingEnabled = enable;

                            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                          "Spoofed NtSetInformationProcess(ProcessHandleTracing) tid:%d",
                                          HandleToUlong(threadProcessEntry->ProcessId));

                            status = STATUS_SUCCESS;
                            handled = true;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    handled = true;
                }

            Exit:
                if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
                {
                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                  "NtSetInformationProcess from pid %u ProcessHandle = 0x%p ProcessInformationClass %d "
                                  "returned %!STATUS!\n",
                                  HandleToUlong(PsGetCurrentProcessId()), ProcessHandle, ProcessInformationClass,
                                  status);
                }

                return status;
            }
        }
    }
    return reinterpret_cast<decltype(&hkNtSetInformationProcess)>(hookEntry->OriginalFunc)(
        ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

void FilterObject(_In_ POBJECT_TYPE_INFORMATION object)
{
    PAGED_CODE();
    NT_ASSERT(object);

    UNICODE_STRING debugObjectName = RTL_CONSTANT_STRING(L"DebugObject");
    if (RtlEqualUnicodeString(&debugObjectName, &object->TypeName, FALSE))
    {
        // Subtract just one from both counts for our debugger, unless the query was a generic one for all object
        // types
        if (object->TotalNumberOfObjects > 1)
        {
            object->TotalNumberOfObjects = 1;
            object->TotalNumberOfHandles = 1;
        }
        else
        {
            object->TotalNumberOfObjects = 0;
            object->TotalNumberOfHandles = 0;
        }
    }
}

void FilterObjects(_In_ POBJECT_ALL_INFORMATION objectAllInformation)
{
    PAGED_CODE();
    NT_ASSERT(objectAllInformation);

    POBJECT_TYPE_INFORMATION object = objectAllInformation->ObjectInformation;

    for (ULONG i = 0; i < objectAllInformation->NumberOfObjectsTypes; i++)
    {
        FilterObject(object);

        object = reinterpret_cast<POBJECT_TYPE_INFORMATION>(reinterpret_cast<PCHAR>(object + 1) +
                                                            ALIGN_UP(object->TypeName.MaximumLength, ULONG_PTR));
    }
}

NTSTATUS NTAPI hkNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation,
                               ULONG ObjectInformationLength, PULONG ReturnLength)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtQueryObject"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    NTSTATUS status = reinterpret_cast<decltype(&hkNtQueryObject)>(hookEntry->OriginalFunc)(
        Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtQueryObject))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                if (NT_SUCCESS(status) && ObjectInformation &&
                    (ObjectInformationClass == ObjectTypesInformation ||
                     ObjectInformationClass == ObjectTypeInformation))
                {
                    __try
                    {
                        ProbeForWrite(ObjectInformation, ObjectInformationLength, 1);

                        if (ObjectInformationClass == ObjectTypesInformation)
                        {
                            BACKUP_RETURNLENGTH();

                            FilterObjects(static_cast<POBJECT_ALL_INFORMATION>(ObjectInformation));

                            RESTORE_RETURNLENGTH();

                            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                          "Spoofed NtQueryObject(ObjectTypesInformation) tid:%d",
                                          HandleToUlong(processEntry->ProcessId));
                        }
                        else if (ObjectInformationClass == ObjectTypeInformation)
                        {
                            BACKUP_RETURNLENGTH();

                            FilterObject(static_cast<POBJECT_TYPE_INFORMATION>(ObjectInformation));

                            RESTORE_RETURNLENGTH();

                            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                          "Spoofed NtQueryObject(ObjectTypeInformation) tid:%d",
                                          HandleToUlong(processEntry->ProcessId));
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        status = GetExceptionCode();
                    }
                }
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtQueryObject from pid %u Handle = 0x%p ObjectInformationClass %d "
                              "returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), Handle, ObjectInformationClass, status);
            }
        }
    }
    return status;
}

NTSTATUS NTAPI hkNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess,
                                     ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes,
                                     POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags,
                                     PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
                                     PVOID CreateInfo,   // PPS_CREATE_INFO
                                     PVOID AttributeList // PPS_ATTRIBUTE_LIST
)
{
    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtCreateUserProcess"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    NTSTATUS status = reinterpret_cast<decltype(&hkNtCreateUserProcess)>(hookEntry->OriginalFunc)(
        ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes,
        ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtCreateUserProcess))
        {
            __try
            {
                if (NT_SUCCESS(status) &&
                    BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideChildFromDebugger))
                {
                    PEPROCESS process = nullptr;
                    if (NT_SUCCESS(ObReferenceObjectByHandle(*ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION,
                                                             *PsProcessType, previousMode,
                                                             reinterpret_cast<PVOID *>(&process), nullptr)))
                    {
                        const NTSTATUS status2 = AddProcessEntry(process, processEntry->PolicyFlags);
                        if (!NT_SUCCESS(status2))
                        {
                            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Failed to add new process entry %!STATUS!\n",
                                          status2);
                        }

                        ObDereferenceObject(process);
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtCreateUserProcess from pid %u ProcessHandle = 0x%p ThreadHandle = 0x%p "
                              "ProcessDesiredAccess 0x%08X ThreadDesiredAccess 0x%08X "
                              "returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), ProcessHandle, ThreadHandle, ProcessDesiredAccess,
                              ThreadDesiredAccess, status);
            }
        }
    }
    return status;
}

NTSTATUS NTAPI hkNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                  HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
                                  SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtCreateThreadEx"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode && (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER ||
                                     CreateFlags & THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE))
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtCreateThreadEx))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                const ULONG OriginalFlags = CreateFlags;
                ULONG ClearFlags = OriginalFlags & ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);

                if (KERNEL_BUILD_VERSION >= WINDOWS_10_VERSION_19H1)
                {
                    ClearFlags = OriginalFlags &
                                 ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE);
                }

                status = reinterpret_cast<decltype(&hkNtCreateThreadEx)>(hookEntry->OriginalFunc)(
                    ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, ClearFlags,
                    ZeroBits, StackSize, MaximumStackSize, AttributeList);
                handled = true;

                if (NT_SUCCESS(status))
                {
                    PETHREAD thread = nullptr;
                    if (NT_SUCCESS(ObReferenceObjectByHandle(*ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                             previousMode, reinterpret_cast<PVOID *>(&thread), NULL)))
                    {
                        SCOPE_EXIT
                        {
                            ObDereferenceObject(thread);
                        };

                        PEPROCESS process = nullptr;

                        if (ProcessHandle == ZwCurrentProcess())
                        {
                            process = PsGetCurrentProcess();
                        }
                        else
                        {
                            if (!NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION,
                                                                      *PsProcessType, previousMode,
                                                                      reinterpret_cast<PVOID *>(&process), NULL)))
                            {
                                goto Exit;
                            }

                            SCOPE_EXIT
                            {
                                ObDereferenceObject(process);
                            };
                        }

                        PPROCESS_ENTRY threadProcessEntry = GetProcessEntry(process);

                        SCOPE_EXIT
                        {
                            if (threadProcessEntry)
                            {
                                object::DereferenceObject(threadProcessEntry);
                                threadProcessEntry = nullptr;
                            }
                        };

                        // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
                        //
                        if (threadProcessEntry &&
                            BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagNtCreateThreadEx))
                        {
                            if (BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                            {
                                PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    threadEntry->Flags.IsThreadHidden =
                                        OriginalFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;

                                    WppTracePrint(
                                        TRACE_LEVEL_VERBOSE, GENERAL,
                                        "NtCreateThreadEx hide thread %u from pid %u from debugger and freeze",
                                        HandleToUlong(PsGetThreadId(thread)),
                                        HandleToUlong(threadProcessEntry->ProcessId));
                                }
                            }
                        }
                    }
                }
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtCreateThreadEx)>(hookEntry->OriginalFunc)(
                    ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags,
                    ZeroBits, StackSize, MaximumStackSize, AttributeList);
            }

        Exit:
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtCreateThreadEx from pid %u ProcessHandle = 0x%p StartRoutine 0x%p Argument 0x%p "
                              "CreateFlags %d "
                              "returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), ProcessHandle, StartRoutine, Argument,
                              CreateFlags, status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtCreateThreadEx)>(hookEntry->OriginalFunc)(
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits,
        StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NTAPI hkNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtGetContextThread"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtGetContextThread))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                __try
                {
                    ProbeForWrite(ThreadContext, sizeof(*ThreadContext), TYPE_ALIGNMENT(CONTEXT));

                    PETHREAD thread = nullptr;

                    if (ThreadHandle == ZwCurrentThread())
                    {
                        thread = PsGetCurrentThread();
                    }
                    else
                    {
                        if (!NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                                  previousMode, reinterpret_cast<PVOID *>(&thread),
                                                                  nullptr)))
                        {
                            goto Exit;
                        }
                    }

                    PPROCESS_ENTRY threadProcessEntry = GetProcessEntry(PsGetThreadProcessId(thread));

                    SCOPE_EXIT
                    {
                        ObDereferenceObject(thread);

                        if (threadProcessEntry)
                        {
                            object::DereferenceObject(threadProcessEntry);
                            threadProcessEntry = nullptr;
                        }
                    };

                    if (threadProcessEntry &&
                        BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagNtGetContextThread))
                    {
                        if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                        {
                            ULONG OriginalFlags = ThreadContext->ContextFlags;
                            ThreadContext->ContextFlags &= ~0x10;

                            status = reinterpret_cast<decltype(&hkNtGetContextThread)>(hookEntry->OriginalFunc)(
                                ThreadHandle, ThreadContext);

                            if (OriginalFlags & 0x10)
                            {
                                ThreadContext->ContextFlags |= 0x10;

                                PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    RtlCopyMemory(&ThreadContext->Dr0, &threadEntry->SavedDebugContext.Dr0,
                                                  sizeof(ULONG64) * 6);
                                    RtlCopyMemory(&ThreadContext->DebugControl,
                                                  &threadEntry->SavedDebugContext.DebugControl, sizeof(ULONG64) * 5);

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Spoofed NtGetContextThread tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }
                                else
                                {
                                    RtlSecureZeroMemory(&ThreadContext->Dr0, sizeof(ULONG64) * 6);
                                    RtlSecureZeroMemory(&ThreadContext->DebugControl, sizeof(ULONG64) * 5);
                                }
                            }

                            handled = true;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    handled = true;
                }
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtGetContextThread)>(hookEntry->OriginalFunc)(ThreadHandle,
                                                                                                    ThreadContext);
            }

        Exit:
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtGetContextThread from pid %u ThreadHandle = 0x%p returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), ThreadHandle, status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtGetContextThread)>(hookEntry->OriginalFunc)(ThreadHandle, ThreadContext);
}

NTSTATUS NTAPI hkNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtSetContextThread"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtSetContextThread))
        {
            NTSTATUS status = STATUS_SUCCESS;
            bool handled = false;

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                __try
                {
                    ProbeForWrite(ThreadContext, sizeof(*ThreadContext), TYPE_ALIGNMENT(CONTEXT));

                    PETHREAD thread = nullptr;

                    if (ThreadHandle == ZwCurrentThread())
                    {
                        thread = PsGetCurrentThread();
                    }
                    else
                    {
                        if (!NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                                  previousMode, reinterpret_cast<PVOID *>(&thread),
                                                                  nullptr)))
                        {
                            goto Exit;
                        }
                    }

                    PPROCESS_ENTRY threadProcessEntry = GetProcessEntry(PsGetThreadProcessId(thread));

                    SCOPE_EXIT
                    {
                        ObDereferenceObject(thread);

                        if (threadProcessEntry)
                        {
                            object::DereferenceObject(threadProcessEntry);
                            threadProcessEntry = nullptr;
                        }
                    };

                    if (threadProcessEntry &&
                        BooleanFlagOn(threadProcessEntry->PolicyFlags, ProcessPolicyFlagNtSetContextThread))
                    {
                        if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                        {
                            ULONG OriginalFlags = ThreadContext->ContextFlags;
                            ThreadContext->ContextFlags &= ~0x10;

                            status = reinterpret_cast<decltype(&hkNtSetContextThread)>(hookEntry->OriginalFunc)(
                                ThreadHandle, ThreadContext);

                            if (OriginalFlags & 0x10)
                            {
                                ThreadContext->ContextFlags |= 0x10;

                                PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    RtlCopyMemory(&threadEntry->SavedDebugContext.Dr0, &ThreadContext->Dr0,
                                                  sizeof(ULONG64) * 6);
                                    RtlCopyMemory(&threadEntry->SavedDebugContext.DebugControl,
                                                  &ThreadContext->DebugControl, sizeof(ULONG64) * 5);

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Spoofed NtSetContextThread tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }
                            }

                            handled = true;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    handled = true;
                }
            }

            if (!handled)
            {
                status = reinterpret_cast<decltype(&hkNtSetContextThread)>(hookEntry->OriginalFunc)(ThreadHandle,
                                                                                                    ThreadContext);
            }

        Exit:
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtSetContextThread from pid %u ThreadHandle = 0x%p returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), ThreadHandle, status);
            }

            return status;
        }
    }
    return reinterpret_cast<decltype(&hkNtSetContextThread)>(hookEntry->OriginalFunc)(ThreadHandle, ThreadContext);
}

void FilterJobProcessList(PJOBOBJECT_BASIC_PROCESS_ID_LIST JobInformation, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = JobInformation->NumberOfAssignedProcesses;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        const auto processId = (HANDLE)JobInformation->ProcessIdList[i];
        if (process::IsProtectedProcess(processId))
        {
            JobInformation->NumberOfAssignedProcesses--;
            JobInformation->NumberOfProcessIdsInList--;
            *pReturnLengthAdjust += sizeof(ULONG_PTR);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                JobInformation->ProcessIdList[j] = JobInformation->ProcessIdList[j + 1];
                RtlZeroMemory(&JobInformation->ProcessIdList[j + 1], sizeof(JobInformation->ProcessIdList[j + 1]));
            }
            i--;
        }
    }
}

NTSTATUS NTAPI hkNtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass,
                                             PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength)
{
    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtQueryInformationJobObject"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    auto status = reinterpret_cast<decltype(&hkNtQueryInformationJobObject)>(hookEntry->OriginalFunc)(
        JobHandle, JobInformationClass, JobInformation, JobInformationLength, ReturnLength);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        process::PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) process has entry and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtQueryInformationJobObject))
        {
            if (NT_SUCCESS(status) && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger) &&
                JobInformationClass == JobObjectBasicProcessIdList)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterJobProcessList(static_cast<PJOBOBJECT_BASIC_PROCESS_ID_LIST>(JobInformation),
                                     &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
                {
                    TempReturnLength -= ReturnLengthAdjust;
                }

                RESTORE_RETURNLENGTH();

                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "Spoofed NtQueryInformationJobObject(JobObjectBasicProcessIdList) pid:%d",
                              HandleToUlong(processEntry->ProcessId));
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtQueryInformationJobObject from pid %u JobHandle = 0x%p JobInformationClass = %u "
                              "returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), JobHandle, JobInformationClass, status);
            }
        }
    }
    return status;
}

void FilterHandleInfo(PSYSTEM_HANDLE_INFORMATION pHandleInfo, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = pHandleInfo->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        if (IsProtectedProcess((HANDLE)pHandleInfo->Handles[i].UniqueProcessId))
        {
            pHandleInfo->NumberOfHandles--;
            *pReturnLengthAdjust += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                pHandleInfo->Handles[j] = pHandleInfo->Handles[j + 1];
                RtlZeroMemory(&pHandleInfo->Handles[j + 1], sizeof(pHandleInfo->Handles[j + 1]));
            }
            i--;
        }
    }
}

void FilterHandleInfoEx(PSYSTEM_HANDLE_INFORMATION_EX pHandleInfoEx, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = (ULONG)pHandleInfoEx->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        if (IsProtectedProcess((HANDLE)pHandleInfoEx->Handles[i].UniqueProcessId))
        {
            pHandleInfoEx->NumberOfHandles--;
            *pReturnLengthAdjust += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                pHandleInfoEx->Handles[j] = pHandleInfoEx->Handles[j + 1];
                RtlZeroMemory(&pHandleInfoEx->Handles[j + 1], sizeof(pHandleInfoEx->Handles[j + 1]));
            }
            i--;
        }
    }
}

void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

    while (TRUE)
    {
        if (IsProtectedProcess(pInfo->UniqueProcessId))
        {
            if (pInfo->ImageName.Buffer)
            {
                RtlZeroMemory(pInfo->ImageName.Buffer, pInfo->ImageName.Length);
            }

            if (pInfo->NextEntryOffset == 0) // last element
            {
                pPrev->NextEntryOffset = 0;
            }
            else
            {
                pPrev->NextEntryOffset += pInfo->NextEntryOffset;
            }
        }
        else
        {
            pPrev = pInfo;
        }

        if (pInfo->NextEntryOffset == 0)
        {
            break;
        }
        else
        {
            pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
        }
    }
}

NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
                                          ULONG SystemInformationLength, PULONG ReturnLength)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtQuerySystemInformation"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    NTSTATUS status = reinterpret_cast<decltype(&hkNtQuerySystemInformation)>(hookEntry->OriginalFunc)(
        SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (NT_SUCCESS(status) &&
            (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtQuerySystemInformation)))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                __try
                {
                    ProbeForWrite(SystemInformation, SystemInformationLength, 1);

                    if (SystemInformationClass == SystemProcessInformation ||
                        SystemInformationClass == SystemSessionProcessInformation ||
                        SystemInformationClass == SystemExtendedProcessInformation)
                    {
                        BACKUP_RETURNLENGTH();

                        auto ProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
                        if (SystemInformationClass == SystemSessionProcessInformation)
                        {
                            ProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(
                                (static_cast<PSYSTEM_SESSION_PROCESS_INFORMATION>(SystemInformation))->Buffer);
                        }

                        FilterProcess(ProcessInfo);

                        for (PSYSTEM_PROCESS_INFORMATION entry = ProcessInfo; entry->NextEntryOffset != NULL;
                             entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PUCHAR>(entry) +
                                                                                   entry->NextEntryOffset))
                        {
                            PPROCESS_ENTRY processEntry2 = GetProcessEntry(entry->UniqueProcessId);

                            SCOPE_EXIT
                            {
                                if (processEntry2)
                                {
                                    object::DereferenceObject(processEntry2);
                                    processEntry2 = nullptr;
                                }
                            };

                            if (processEntry2 &&
                                BooleanFlagOn(processEntry2->PolicyFlags, ProcessPolicyFlagNtQuerySystemInformation))
                            {
                                if (BooleanFlagOn(processEntry2->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                                {
                                    PEPROCESS process = tools::GetProcessByName(processEntry2->FakeParentProcessName);
                                    if (process)
                                    {
                                        entry->InheritedFromUniqueProcessId = PsGetProcessId(process);
                                        ObDereferenceObject(process);
                                    }

                                    entry->OtherOperationCount.QuadPart = 1;

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                                  "Spoofed NtQuerySystemInformation(ProcessInformation) pid:%d",
                                                  HandleToUlong(processEntry->ProcessId));
                                }
                            }
                        }

                        RESTORE_RETURNLENGTH();
                    }
                    else if (SystemInformationClass == SystemHandleInformation)
                    {
                        BACKUP_RETURNLENGTH();
                        ULONG ReturnLengthAdjust = 0;

                        FilterHandleInfo(static_cast<PSYSTEM_HANDLE_INFORMATION>(SystemInformation),
                                         &ReturnLengthAdjust);

                        if (ReturnLengthAdjust <= TempReturnLength)
                        {
                            TempReturnLength -= ReturnLengthAdjust;
                        }

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtQuerySystemInformation(SystemHandleInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemExtendedHandleInformation)
                    {
                        BACKUP_RETURNLENGTH();
                        ULONG ReturnLengthAdjust = 0;

                        FilterHandleInfoEx(static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(SystemInformation),
                                           &ReturnLengthAdjust);

                        if (ReturnLengthAdjust <= TempReturnLength)
                        {
                            TempReturnLength -= ReturnLengthAdjust;
                        }

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtQuerySystemInformation(SystemExtendedHandleInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemCodeIntegrityInformation &&
                             BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideSystemCodeIntegrity))
                    {
                        BACKUP_RETURNLENGTH();

                        auto systemInformation = static_cast<PSYSTEM_CODEINTEGRITY_INFORMATION>(SystemInformation);

                        ULONG options = systemInformation->CodeIntegrityOptions;

                        options &= ~CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;
                        options &= ~CODEINTEGRITY_OPTION_TESTSIGN;
                        options |= CODEINTEGRITY_OPTION_ENABLED;

                        systemInformation->CodeIntegrityOptions = options;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtQuerySystemInformation(SystemCodeIntegrityInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemCodeIntegrityUnlockInformation &&
                             BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideSystemCodeIntegrity))
                    {
                        BACKUP_RETURNLENGTH();

                        // The size of the buffer for this class changed from 4 to 36, but the output should still
                        // be all zeroes
                        RtlSecureZeroMemory(SystemInformation, SystemInformationLength);

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtQuerySystemInformation(SystemCodeIntegrityUnlockInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemKernelDebuggerInformation)
                    {
                        auto debuggerInfo = static_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION>(SystemInformation);

                        BACKUP_RETURNLENGTH();

                        debuggerInfo->KernelDebuggerEnabled = 0;
                        debuggerInfo->KernelDebuggerNotPresent = 1;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtQuerySystemInformation(SystemKernelDebuggerInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
                    {
                        auto debuggerInfoEx = static_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX>(SystemInformation);

                        BACKUP_RETURNLENGTH();

                        debuggerInfoEx->DebuggerAllowed = FALSE;
                        debuggerInfoEx->DebuggerEnabled = FALSE;
                        debuggerInfoEx->DebuggerPresent = FALSE;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtQuerySystemInformation(SystemKernelDebuggerInformationEx) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemKernelDebuggerFlags)
                    {
                        BACKUP_RETURNLENGTH();

                        *reinterpret_cast<PUCHAR>(SystemInformation) = 0;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                      "Spoofed NtQuerySystemInformation(SystemKernelDebuggerFlags) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                }
            }

            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                              "NtQuerySystemInformation from pid %u SystemInformationClass = %u returned %!STATUS!\n",
                              HandleToUlong(PsGetCurrentProcessId()), SystemInformationClass, status);
            }
        }
    }
    return status;
}

HWND NTAPI hkNtUserWindowFromPoint(LONG x, LONG y)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtUserWindowFromPoint"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const HWND resultHwnd = reinterpret_cast<decltype(&hkNtUserWindowFromPoint)>(hookEntry->OriginalFunc)(x, y);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtUserWindowFromPoint))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                const HANDLE processId = reinterpret_cast<decltype(&hkNtUserQueryWindow)>(
                    FindHookEntry(FNV("NtUserQueryWindow"))->OriginalFunc)(resultHwnd, WindowProcess);
                if (IsProtectedProcess(processId))
                {
                    return reinterpret_cast<decltype(&NtUserGetThreadState)>(
                        FindHookEntry(FNV("NtUserGetThreadState"))->OriginalFunc)(THREADSTATE_ACTIVEWINDOW);
                }
            }
        }
    }
    return resultHwnd;
}

HANDLE NTAPI hkNtUserQueryWindow(HWND WindowHandle, WINDOWINFOCLASS WindowInfo)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtUserQueryWindow"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtUserQueryWindow))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                // Spoof result if trying to query protected process
                //
                const HANDLE processId = reinterpret_cast<decltype(&hkNtUserQueryWindow)>(hookEntry->OriginalFunc)(
                    WindowHandle, WindowProcess);
                if (IsProtectedProcess(processId))
                {
                    switch (WindowInfo)
                    {
                    case WindowProcess:
                        return PsGetCurrentProcessId();
                    case WindowThread:
                        return PsGetCurrentThreadId();

                    default:
                        break;
                    }
                }
            }
        }
    }
    return reinterpret_cast<decltype(&hkNtUserQueryWindow)>(hookEntry->OriginalFunc)(WindowHandle, WindowInfo);
}

HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass,
                                PUNICODE_STRING lpszWindow, DWORD dwType)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtUserFindWindowEx"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const HWND resultHwnd = reinterpret_cast<decltype(&hkNtUserFindWindowEx)>(hookEntry->OriginalFunc)(
        hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (resultHwnd &&
            (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtUserFindWindowEx)))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                // Spoof result if trying to query protected process
                //
                const HANDLE processId = reinterpret_cast<decltype(&hkNtUserQueryWindow)>(
                    FindHookEntry(FNV("NtUserQueryWindow"))->OriginalFunc)(resultHwnd, WindowProcess);
                if (IsProtectedProcess(processId))
                {
                    return 0;
                }
            }
        }
    }
    return resultHwnd;
}

void FilterHwndList(HWND *phwndFirst, PULONG pcHwndNeeded)
{
    for (UINT i = 0; i < *pcHwndNeeded; i++)
    {
        // Spoof result if trying to query protected process
        //
        HANDLE processId = reinterpret_cast<decltype(&hkNtUserQueryWindow)>(
            FindHookEntry(FNV("NtUserQueryWindow"))->OriginalFunc)(phwndFirst[i], WindowProcess);

        if (phwndFirst[i] != nullptr && IsProtectedProcess(processId))
        {
            if (i == 0)
            {
                // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                {
                    processId = reinterpret_cast<decltype(&hkNtUserQueryWindow)>(
                        FindHookEntry(FNV("NtUserQueryWindow"))->OriginalFunc)(phwndFirst[j], WindowProcess);

                    if (phwndFirst[j] != nullptr && !IsProtectedProcess(processId))
                    {
                        phwndFirst[i] = phwndFirst[j];
                        break;
                    }
                }
            }
            else
            {
                phwndFirst[i] = phwndFirst[i - 1]; // just override with previous
            }
        }
    }
}

NTSTATUS NTAPI hkNtUserBuildHwndList_Win7(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread,
                                          UINT cHwndMax, HWND *phwndFirst, ULONG *pcHwndNeeded)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtUserBuildHwndList"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const NTSTATUS status = reinterpret_cast<decltype(&hkNtUserBuildHwndList_Win7)>(hookEntry->OriginalFunc)(
        hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        if (NT_SUCCESS(status) && phwndFirst && pcHwndNeeded)
        {
            const HANDLE currentProcessId = PsGetCurrentProcessId();
            PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

            SCOPE_EXIT
            {
                if (processEntry)
                {
                    object::DereferenceObject(processEntry);
                    processEntry = nullptr;
                }
            };

            // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
            //
            if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtUserBuildHwndList))
            {
                if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                {
                    FilterHwndList(phwndFirst, pcHwndNeeded);
                }
            }
        }
    }
    return status;
}

NTSTATUS NTAPI hkNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag,
                                     ULONG dwThreadId, ULONG lParam, HWND *pWnd, PULONG pBufSize)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtUserBuildHwndList"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const NTSTATUS status = reinterpret_cast<decltype(&hkNtUserBuildHwndList)>(hookEntry->OriginalFunc)(
        hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        if (NT_SUCCESS(status) && pWnd && pBufSize)
        {
            const HANDLE currentProcessId = PsGetCurrentProcessId();
            PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

            SCOPE_EXIT
            {
                if (processEntry)
                {
                    object::DereferenceObject(processEntry);
                    processEntry = nullptr;
                }
            };

            // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
            //
            if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtUserBuildHwndList))
            {
                if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
                {
                    FilterHwndList(pWnd, pBufSize);
                }
            }
        }
    }
    return status;
}

HWND NTAPI hkNtUserGetForegroundWindow(VOID)
{
    PAGED_CODE();

    const PHOOK_ENTRY hookEntry = FindHookEntry(FNV("NtUserGetForegroundWindow"));
    const ScopedReferenceGuard lock(&hookEntry->RefCount);

    const HWND resultHwnd = reinterpret_cast<decltype(&hkNtUserGetForegroundWindow)>(hookEntry->OriginalFunc)();

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        PPROCESS_ENTRY processEntry = GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagNtUserGetForegroundWindow))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideFromDebugger))
            {
                // Spoof result if trying to query protected process
                //
                const HANDLE processId = reinterpret_cast<decltype(&hkNtUserQueryWindow)>(
                    FindHookEntry(FNV("NtUserQueryWindow"))->OriginalFunc)(resultHwnd, WindowProcess);
                if (IsProtectedProcess(processId))
                {
                    return reinterpret_cast<decltype(&NtUserGetThreadState)>(
                        FindHookEntry(FNV("NtUserGetThreadState"))->OriginalFunc)(THREADSTATE_ACTIVEWINDOW);
                }
            }
        }
    }
    return resultHwnd;
}
} // namespace hooks
} // namespace masterhide