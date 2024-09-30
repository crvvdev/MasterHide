#include "includes.hpp"

namespace masterhide
{
namespace hooks
{
CONST PKUSER_SHARED_DATA KuserSharedData = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_USERMODE;

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

[[nodiscard]] static NTSTATUS CreateHook(_In_ USHORT syscallNum, _In_ PVOID dst, _Out_ PVOID *org, _In_ bool shadow)
{
    PAGED_CODE();
    NT_ASSERT(dst);
    NT_ASSERT(org);

    auto hookEntry = tools::AllocatePoolZero<PHOOK_ENTRY>(NonPagedPool, sizeof(HOOK_ENTRY), tags::TAG_HOOK);
    if (!hookEntry)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

#ifdef USE_KASPERSKY
    if (shadow)
    {
        if (!kaspersky::hook_shadow_ssdt_routine(syscallNum, dst, org))
        {
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        if (!kaspersky::hook_ssdt_routine(syscallNum, dst, org))
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    hookEntry->SyscallNum = syscallNum;
    hookEntry->Original = *org;
    hookEntry->Current = dst;
    hookEntry->Shadow = shadow;
#else
    // TODO: implement
#endif

    InsertTailList(&g_hooksListHead, &hookEntry->ListEntry);

    return STATUS_SUCCESS;
}

static NTSTATUS RemoveHook(_In_ USHORT syscallNum, _Out_ PVOID org, _In_ bool shadow)
{
    PAGED_CODE();
    NT_ASSERT(org);

#ifdef USE_KASPERSKY
    if (shadow)
    {
        if (!kaspersky::unhook_shadow_ssdt_routine(syscallNum, org))
        {
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        if (!kaspersky::unhook_ssdt_routine(syscallNum, org))
        {
            return STATUS_UNSUCCESSFUL;
        }
    }
#else
    // TODO: implement
#endif

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

    InitializeListHead(&g_hooksListHead);
    KeInitializeMutex(&g_ntCloseMutex, 0);

#define HOOK_SYSTEM_ROUTINE(name, shadow)                                                                              \
    {                                                                                                                  \
        USHORT syscallNum = syscalls::GetSyscallIndexByName(#name);                                                    \
        if (syscallNum == MAXUSHORT)                                                                                   \
        {                                                                                                              \
            DBGPRINT(#name " index was not found!");                                                                   \
            return STATUS_UNSUCCESSFUL;                                                                                \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            status = CreateHook(shadow ? syscallNum + 0x1000 : syscallNum, hk##name,                                   \
                                reinterpret_cast<PVOID *>(&o##name), shadow);                                          \
            if (!NT_SUCCESS(status))                                                                                   \
            {                                                                                                          \
                DBGPRINT("Failed to hook " #name " 0x%08X", status);                                                   \
                return STATUS_UNSUCCESSFUL;                                                                            \
            }                                                                                                          \
            else                                                                                                       \
            {                                                                                                          \
                DBGPRINT(#name " hooked successfully!");                                                               \
            }                                                                                                          \
        }                                                                                                              \
    }

#define HOOK_SYSTEM_ROUTINE_PARAM(name, shadow, dst, src)                                                              \
    {                                                                                                                  \
        USHORT syscallNum = syscalls::GetSyscallIndexByName(#name);                                                    \
        if (syscallNum == MAXUSHORT)                                                                                   \
        {                                                                                                              \
            DBGPRINT(#name " index was not found!");                                                                   \
            return STATUS_UNSUCCESSFUL;                                                                                \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            status =                                                                                                   \
                CreateHook(shadow ? syscallNum + 0x1000 : syscallNum, dst, reinterpret_cast<PVOID *>(&src), shadow);   \
            if (!NT_SUCCESS(status))                                                                                   \
            {                                                                                                          \
                DBGPRINT("Failed to hook " #name " 0x%08X", status);                                                   \
                return STATUS_UNSUCCESSFUL;                                                                            \
            }                                                                                                          \
            else                                                                                                       \
            {                                                                                                          \
                DBGPRINT(#name " hooked successfully!");                                                               \
            }                                                                                                          \
        }                                                                                                              \
    }

#ifdef USE_KASPERSKY
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
#else
    WppTracePrint(
        TRACE_LEVEL_VERBOSE, GENERAL,
        "MasterHide is using odinary SSDT hooks, which means: It only can be used on PatchGuard disabled "
        "environment, such as kernel debugger attached or manually patching the kernel! The system WILL crash if "
        "PatchGuard is enabled.\n");
#endif

    HOOK_SYSTEM_ROUTINE(NtQuerySystemInformation, false);
    HOOK_SYSTEM_ROUTINE(NtQueryInformationProcess, false);
    HOOK_SYSTEM_ROUTINE(NtQueryInformationThread, false);
    // HOOK_SYSTEM_ROUTINE(NtQueryInformationJobObject, false);

    HOOK_SYSTEM_ROUTINE(NtQueryObject, false);
    // HOOK_SYSTEM_ROUTINE(NtQuerySystemTime, false);
    HOOK_SYSTEM_ROUTINE(NtQueryPerformanceCounter, false);
    HOOK_SYSTEM_ROUTINE(NtSetInformationProcess, false);
    HOOK_SYSTEM_ROUTINE(NtSetInformationThread, false);
    HOOK_SYSTEM_ROUTINE(NtSystemDebugControl, false);

    HOOK_SYSTEM_ROUTINE(NtClose, false);
    HOOK_SYSTEM_ROUTINE(NtCreateThreadEx, false);
    HOOK_SYSTEM_ROUTINE(NtGetContextThread, false);
    HOOK_SYSTEM_ROUTINE(NtSetContextThread, false);
    HOOK_SYSTEM_ROUTINE(NtLoadDriver, false);
    HOOK_SYSTEM_ROUTINE(NtYieldExecution, false);

    HOOK_SYSTEM_ROUTINE(NtOpenProcess, false);
    HOOK_SYSTEM_ROUTINE(NtOpenThread, false);
    HOOK_SYSTEM_ROUTINE(NtAllocateVirtualMemory, false);
    HOOK_SYSTEM_ROUTINE(NtFreeVirtualMemory, false);
    HOOK_SYSTEM_ROUTINE(NtWriteVirtualMemory, false);
    HOOK_SYSTEM_ROUTINE(NtDeviceIoControlFile, false);

    if (KERNEL_BUILD < WINDOWS_10_VERSION_20H1)
    {
        HOOK_SYSTEM_ROUTINE(NtContinue, false);
    }
    else
    {
        HOOK_SYSTEM_ROUTINE_PARAM(NtContinueEx, false, hkNtContinue, oNtContinue);
    }

    HOOK_SYSTEM_ROUTINE(NtUserWindowFromPoint, true);
    HOOK_SYSTEM_ROUTINE(NtUserQueryWindow, true);
    HOOK_SYSTEM_ROUTINE(NtUserFindWindowEx, true);
    HOOK_SYSTEM_ROUTINE(NtUserBuildHwndList, true);
    HOOK_SYSTEM_ROUTINE(NtUserGetForegroundWindow, true);

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

    // (1) (Try) Remove all active hooks
    //
    while (!IsListEmpty(&g_hooksListHead))
    {
        PLIST_ENTRY listEntry = RemoveHeadList(&g_hooksListHead);
        PHOOK_ENTRY hookEntry = CONTAINING_RECORD(listEntry, HOOK_ENTRY, ListEntry);

        const NTSTATUS status = RemoveHook(hookEntry->SyscallNum, hookEntry->Original, hookEntry->Shadow);
        if (!NT_SUCCESS(status))
        {
            // Honestly there's nothing we can do if the hook cannot be removed so just log it i guess?
            //
            WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to unhook syscallNum:%d org:0x%p new:0x%p %!STATUS!",
                          hookEntry->SyscallNum, hookEntry->Original, hookEntry->Current, status);
        }

        ExFreePool(hookEntry);
    }

    g_initialized = false;

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Waiting for all hooks to complete before proceeding...");

// (2) We have to wait for the gobal reference count to reach zero unless we wanna bugcheck the system :)
//
// !! BUG !! If one of the hooks cannot be removed this will hang the current thread indefinitively
//
#if 0
    while (LONG count = InterlockedCompareExchange(&g_refCount, 0, 0) != 0)
    {
        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "%d references left", count);

        YieldProcessor();
    }
#endif

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Successfully de-initialized hooks interface!");
    return;
}

NTSTATUS NTAPI hkNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtQuerySystemTime))
        {
            __try
            {
                ProbeForWrite(SystemTime, sizeof(ULONG64), 4);

                if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHideKUserSharedData))
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

                return STATUS_SUCCESS;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return GetExceptionCode();
            }
        }
    }
    return oNtQuerySystemTime(SystemTime);
}

NTSTATUS NTAPI hkNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtQueryPerformanceCounter))
        {
            __try
            {
                ProbeForWrite(PerformanceCounter, sizeof(ULONG64), 4);

                if (PerformanceFrequency != NULL)
                {
                    ProbeForWrite(PerformanceFrequency, sizeof(ULONG64), 4);
                }

                if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHideKUserSharedData))
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

                return STATUS_SUCCESS;
            }

            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return GetExceptionCode();
            }
        }
    }
    return oNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);
}

NTSTATUS NTAPI hkNtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength,
                                      PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtSystemDebugControl))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                if (Command != SysDbgGetTriageDump && Command != SysDbgGetLiveKernelDump)
                {
                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                  "Spoofed NtSystemDebugControl(commad:%d) anti-debug query!", Command);

                    return STATUS_DEBUGGER_INACTIVE;
                }
            }
        }
    }
    return oNtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength,
                                 ReturnLength);
}

NTSTATUS NTAPI hkNtClose(HANDLE Handle)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtClose))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                // If two or more threads were to simultaneously check and act on this information without
                // synchronization, it might lead to inconsistent states where a handle that is meant to be
                // protected gets closed, or an exception is raised improperly.
                KeWaitForSingleObject(&g_ntCloseMutex, Executive, KernelMode, FALSE, nullptr);

                OBJECT_HANDLE_ATTRIBUTE_INFORMATION handleAttribInfo{};

                const NTSTATUS status =
                    oNtQueryObject(Handle, OBJECT_INFORMATION_CLASS(4) /*ObjectDataInformation*/, &handleAttribInfo,
                                   sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION), nullptr);

                if (status == STATUS_INVALID_HANDLE)
                {
                    KeReleaseMutex(&g_ntCloseMutex, FALSE);

                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS, "Spoofed NtClose(Invalid Handle) anti-debug query!");

                    if (processEntry->Flags.ProcessHandleTracingEnabled)
                    {
                        return KeRaiseUserException(STATUS_INVALID_HANDLE);
                    }
                    return STATUS_INVALID_HANDLE;
                }

                if (NT_SUCCESS(status))
                {
                    if (handleAttribInfo.ProtectFromClose == TRUE)
                    {
                        KeReleaseMutex(&g_ntCloseMutex, FALSE);

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtClose(ProtectFromClose) anti-debug query!");

                        if (processEntry->Flags.ProcessHandleTracingEnabled)
                        {
                            return KeRaiseUserException(STATUS_HANDLE_NOT_CLOSABLE);
                        }

                        return STATUS_HANDLE_NOT_CLOSABLE;
                    }
                }

                KeReleaseMutex(&g_ntCloseMutex, FALSE);
            }
        }
    }
    return oNtClose(Handle);
}

NTSTATUS NTAPI hkNtYieldExecution()
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtYieldExecution))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS, "Spoofed NtYieldExecution anti-debug query!");

                oNtYieldExecution();
                return STATUS_SUCCESS;
            }
        }
    }
    return oNtYieldExecution();
}

NTSTATUS NTAPI hkNtContinue(PCONTEXT Context, ULONG64 TestAlert)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtContinue))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                __try
                {
                    ProbeForRead(Context, sizeof(*Context), __alignof(_CONTEXT));

                    rules::PTHREAD_ENTRY threadEntry = processEntry->AppendThreadList(PsGetCurrentThread());

                    if ((Context->Dr0 != __readdr(0) && Context->Dr1 != __readdr(1) && Context->Dr2 != __readdr(2) &&
                         Context->Dr3 != __readdr(3) && Context->ContextFlags & 0x10 && threadEntry))
                    {
                        RtlCopyMemory(&threadEntry->SavedDebugContext.Dr0, &Context->Dr0, sizeof(ULONG64) * 6);
                        RtlCopyMemory(&threadEntry->SavedDebugContext.DebugControl, &Context->DebugControl,
                                      sizeof(ULONG64) * 5);
                    }

                    Context->ContextFlags &= ~0x10;

                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS, "Spoofed NtContinue anti-debug query!");

                    return oNtContinue(Context, TestAlert);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return oNtContinue(Context, TestAlert);
}

NTSTATUS NTAPI hkNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                              PCLIENT_ID ClientId)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode && ProcessHandle != ZwCurrentProcess())
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        __try
        {
            ProbeForWrite(ProcessHandle, sizeof(*ProcessHandle), 1);
            ProbeForWrite(ObjectAttributes, sizeof(*ObjectAttributes), 1);

            if (ClientId != NULL)
            {
                ProbeForRead(ClientId, sizeof(*ClientId), __alignof(CLIENT_ID));

                // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
                //
                if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtOpenThread))
                {
                    if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
                    {
                        PETHREAD thread = nullptr;
                        NTSTATUS status = PsLookupThreadByThreadId(ClientId->UniqueThread, &thread);
                        if (NT_SUCCESS(status))
                        {
                            SCOPE_EXIT
                            {
                                ObDereferenceObject(thread);
                            };

                            const HANDLE threadProcessId = PsGetThreadProcessId(thread);

                            // Block access to any protected process.
                            //
                            if (rules::IsProtectedProcess(threadProcessId))
                            {
                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS, "Denying access from pid:%d to pid:%d\n",
                                              HandleToUlong(PsGetCurrentProcessId()), HandleToUlong(threadProcessId));

                                return STATUS_INVALID_CID;
                            }
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }
    return oNtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                               PCLIENT_ID ClientId)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode && ProcessHandle != ZwCurrentProcess())
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                object::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        __try
        {
            ProbeForRead(ClientId, sizeof(*ClientId), __alignof(CLIENT_ID));

            // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
            //
            if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtOpenProcess))
            {
                if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
                {
                    // Block access to any protected process.
                    //
                    if (rules::IsProtectedProcess(ClientId->UniqueProcess))
                    {
                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS, "Denying access from pid:%d to pid:%d\n",
                                      HandleToUlong(PsGetCurrentProcessId()), HandleToUlong(ClientId->UniqueProcess));

                        return STATUS_INVALID_CID;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }
    return oNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI hkNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                        PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS status;

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtSetInformationThread))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger) &&
                (ThreadInformationClass == ThreadHideFromDebugger || ThreadInformationClass == ThreadWow64Context ||
                 ThreadInformationClass == ThreadBreakOnTermination))
            {
                __try
                {
                    if (ThreadInformationLength != 0)
                    {
                        ProbeForRead(ThreadInformation, ThreadInformationLength, sizeof(ULONG));
                    }

                    PETHREAD thread = nullptr;
                    status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                       previousMode, reinterpret_cast<PVOID *>(&thread), nullptr);
                    if (NT_SUCCESS(status))
                    {
                        rules::PPROCESS_ENTRY threadProcessEntry = rules::GetProcessEntry(PsGetThreadProcessId(thread));

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(thread);

                            if (threadProcessEntry)
                            {
                                object::DereferenceObject(threadProcessEntry);
                                threadProcessEntry = nullptr;
                            }
                        };

                        if (ThreadInformationClass == ThreadHideFromDebugger)
                        {
                            if (ThreadInformationLength != 0)
                            {
                                return STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (threadProcessEntry && BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                                    rules::ProcessPolicyFlagNtSetInformationThread))
                            {
                                rules::PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    threadEntry->Flags.IsThreadHidden = TRUE;

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                                  "Spoofed NtSetInformationThread(ThreadHideFromDebugger) tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }

                                return STATUS_SUCCESS;
                            }
                        }
                        else if (ThreadInformationClass == ThreadWow64Context)
                        {
                            if (threadProcessEntry && BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                                    rules::ProcessPolicyFlagNtSetInformationThread))
                            {
                                if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
                                {
                                    return STATUS_INFO_LENGTH_MISMATCH;
                                }

                                PVOID WoW64Process = PsGetCurrentProcessWow64Process();
                                if (WoW64Process == 0)
                                {
                                    return STATUS_INVALID_PARAMETER;
                                }

                                PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
                                ULONG OriginalFlags = Wow64Context->ContextFlags;

                                Wow64Context->ContextFlags &= ~0x10;

                                status = oNtSetInformationThread(ThreadHandle, ThreadInformationClass,
                                                                 ThreadInformation, ThreadInformationLength);

                                if (OriginalFlags & 0x10)
                                {
                                    Wow64Context->ContextFlags |= 0x10;

                                    rules::PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                    if (threadEntry)
                                    {
                                        RtlCopyMemory(&threadEntry->SavedWow64DebugContext, &Wow64Context->Dr0,
                                                      sizeof(ULONG) * 6);

                                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                                      "Spoofed NtSetInformationThread(ThreadWow64Context) tid:%d",
                                                      HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                    }
                                    return status;
                                }
                            }
                        }
                        else if (ThreadInformationClass == ThreadBreakOnTermination)
                        {
                            if (ThreadInformationLength != sizeof(ULONG))
                            {
                                return STATUS_INFO_LENGTH_MISMATCH;
                            }

                            volatile ULONG Touch = *(ULONG *)ThreadInformation;
                            UNREFERENCED_PARAMETER(Touch);

                            if (!tools::HasDebugPrivilege())
                            {
                                return STATUS_PRIVILEGE_NOT_HELD;
                            }

                            if (threadProcessEntry && BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                                    rules::ProcessPolicyFlagNtSetInformationThread))
                            {
                                rules::PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    threadEntry->Flags.BreakOnTermination = *(ULONG *)ThreadInformation ? TRUE : FALSE;

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                                  "Spoofed NtSetInformationThread(ThreadBreakOnTermination) tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }
                                return STATUS_SUCCESS;
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return oNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI hkNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                          PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtQueryInformationThread))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                if (ThreadInformation && (ThreadInformationClass == ThreadHideFromDebugger ||
                                          ThreadInformationClass == ThreadBreakOnTermination ||
                                          ThreadInformationClass == ThreadWow64Context))
                {
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
                        NTSTATUS status =
                            ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                      previousMode, reinterpret_cast<PVOID *>(&thread), nullptr);
                        if (NT_SUCCESS(status))
                        {
                            rules::PPROCESS_ENTRY threadProcessEntry =
                                rules::GetProcessEntry(PsGetThreadProcessId(thread));

                            SCOPE_EXIT
                            {
                                ObDereferenceObject(thread);

                                if (threadProcessEntry)
                                {
                                    object::DereferenceObject(threadProcessEntry);
                                    threadProcessEntry = nullptr;
                                }
                            };

                            // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
                            //
                            if (threadProcessEntry && BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                                    rules::ProcessPolicyFlagNtQueryInformationThread))
                            {
                                if (BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                  rules::ProcessPolicyFlagHiddenFromDebugger))
                                {
                                    rules::PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                    if (threadEntry)
                                    {
                                        if (ThreadInformationClass == ThreadHideFromDebugger)
                                        {
                                            if (ThreadInformationLength != 1)
                                            {
                                                return STATUS_INFO_LENGTH_MISMATCH;
                                            }

                                            *(BOOLEAN *)ThreadInformation = threadEntry->Flags.IsThreadHidden;

                                            if (ReturnLength != 0)
                                            {
                                                *ReturnLength = 1;
                                            }

                                            WppTracePrint(
                                                TRACE_LEVEL_VERBOSE, HOOKS,
                                                "Spoofed NtQueryInformationThread(ThreadHideFromDebugger) tid:%d",
                                                HandleToUlong(PsGetThreadId(threadEntry->Thread)));

                                            return STATUS_SUCCESS;
                                        }
                                        else if (ThreadInformationClass == ThreadBreakOnTermination)
                                        {
                                            if (ThreadInformationLength != 4)
                                            {
                                                return STATUS_INFO_LENGTH_MISMATCH;
                                            }

                                            *(ULONG *)ThreadInformation = threadEntry->Flags.BreakOnTermination;

                                            if (ReturnLength != NULL)
                                            {
                                                *ReturnLength = 4;
                                            }

                                            WppTracePrint(
                                                TRACE_LEVEL_VERBOSE, HOOKS,
                                                "Spoofed NtQueryInformationThread(ThreadBreakOnTermination) tid:%d",
                                                HandleToUlong(PsGetThreadId(threadEntry->Thread)));

                                            return STATUS_SUCCESS;
                                        }
                                        else if (ThreadInformationClass == ThreadWow64Context)
                                        {
                                            if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
                                            {
                                                return STATUS_INFO_LENGTH_MISMATCH;
                                            }

                                            PWOW64_CONTEXT Context = PWOW64_CONTEXT(ThreadInformation);
                                            ULONG OriginalFlags = Context->ContextFlags;

                                            Context->ContextFlags &= ~0x10;

                                            status = oNtQueryInformationThread(ThreadHandle, ThreadInformationClass,
                                                                               ThreadInformation,
                                                                               ThreadInformationLength, ReturnLength);

                                            if (NT_SUCCESS(status) && OriginalFlags & 0x10)
                                            {
                                                Context->ContextFlags |= 0x10;

                                                RtlCopyMemory(&Context->Dr0, &threadEntry->SavedWow64DebugContext,
                                                              sizeof(ULONG) * 6);

                                                WppTracePrint(
                                                    TRACE_LEVEL_VERBOSE, HOOKS,
                                                    "Spoofed NtQueryInformationThread(ThreadWow64Context) tid:%d",
                                                    HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                            }

                                            return status;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        return GetExceptionCode();
                    }
                }
            }
        }
    }
    return oNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength,
                                     ReturnLength);
}

NTSTATUS NTAPI hkNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                           PVOID ProcessInformation, ULONG ProcessInformationLength,
                                           PULONG ReturnLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS status;

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtQueryInformationProcess))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger) &&
                (ProcessInformationClass == ProcessDebugObjectHandle || ProcessInformationClass == ProcessDebugPort ||
                 ProcessInformationClass == ProcessDebugFlags || ProcessInformationClass == ProcessBreakOnTermination ||
                 ProcessInformationClass == ProcessBasicInformation || ProcessInformationClass == ProcessIoCounters ||
                 ProcessInformationClass == ProcessHandleTracing))
            {
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
                    status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType,
                                                       previousMode, reinterpret_cast<PVOID *>(&process), nullptr);
                    if (NT_SUCCESS(status))
                    {
                        rules::PPROCESS_ENTRY threadProcessEntry = rules::GetProcessEntry(PsGetProcessId(process));

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(process);

                            if (threadProcessEntry)
                            {
                                object::DereferenceObject(threadProcessEntry);
                                threadProcessEntry = nullptr;
                            }
                        };

                        if (threadProcessEntry && BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                                rules::ProcessPolicyFlagNtQueryInformationProcess))
                        {
                            if (ProcessInformationClass == ProcessDebugObjectHandle)
                            {
                                *(PHANDLE)ProcessInformation = nullptr;

                                if (ReturnLength != nullptr)
                                {
                                    *ReturnLength = sizeof(HANDLE);
                                }

                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                              "Spoofed NtQueryInformationProcess(ProcessDebugObjectHandle) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                return STATUS_PORT_NOT_SET;
                            }
                            else if (ProcessInformationClass == ProcessDebugPort)
                            {
                                BACKUP_RETURNLENGTH();

                                *((HANDLE *)ProcessInformation) = nullptr;

                                if (ReturnLength != nullptr)
                                {
                                    *ReturnLength = sizeof(HANDLE);
                                }

                                RESTORE_RETURNLENGTH();

                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                              "Spoofed NtQueryInformationProcess(ProcessDebugPort) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                return STATUS_SUCCESS;
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

                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                              "Spoofed NtQueryInformationProcess(ProcessDebugFlags) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                return STATUS_SUCCESS;
                            }
                            else if (ProcessInformationClass == ProcessBreakOnTermination)
                            {
                                BACKUP_RETURNLENGTH();

                                *((ULONG *)ProcessInformation) =
                                    threadProcessEntry->Flags.ValueProcessBreakOnTermination;

                                RESTORE_RETURNLENGTH();

                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                              "Spoofed NtQueryInformationProcess(ProcessBreakOnTermination) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                return STATUS_SUCCESS;
                            }

                            status =
                                oNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                                           ProcessInformationLength, ReturnLength);

                            if (NT_SUCCESS(status))
                            {
                                if (ProcessInformationClass == ProcessBasicInformation) // Fake parent
                                {
                                    BACKUP_RETURNLENGTH();

                                    PEPROCESS parentProcess =
                                        tools::GetProcessByName(threadProcessEntry->FakeParentProcessName);
                                    if (parentProcess)
                                    {
                                        ((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId =
                                            HandleToUlong(PsGetProcessId(parentProcess));

                                        ObDereferenceObject(parentProcess);
                                    }

                                    RESTORE_RETURNLENGTH();

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                                  "Spoofed NtQueryInformationProcess(ProcessBasicInformation) tid:%d",
                                                  HandleToUlong(threadProcessEntry->ProcessId));

                                    return STATUS_SUCCESS;
                                }

                                else if (ProcessInformationClass == ProcessHandleTracing)
                                {
                                    BACKUP_RETURNLENGTH();
                                    RESTORE_RETURNLENGTH(); // Trigger any possible exceptions caused by messing
                                                            // with the output buffer before changing the final
                                                            // return status

                                    return threadProcessEntry->Flags.ProcessHandleTracingEnabled
                                               ? STATUS_SUCCESS
                                               : STATUS_INVALID_PARAMETER;
                                }
                                else if (ProcessInformationClass == ProcessIoCounters)
                                {
                                    BACKUP_RETURNLENGTH();

                                    ((PIO_COUNTERS)ProcessInformation)->OtherOperationCount = 1;

                                    RESTORE_RETURNLENGTH();

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                                  "Spoofed NtQueryInformationProcess(ProcessIoCounters) tid:%d",
                                                  HandleToUlong(threadProcessEntry->ProcessId));

                                    return STATUS_SUCCESS;
                                }
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return oNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                      ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI hkNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                         PVOID ProcessInformation, ULONG ProcessInformationLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS status;

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtSetInformationProcess))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger) &&
                (ProcessInformationClass == ProcessBreakOnTermination || ProcessInformationClass == ProcessDebugFlags ||
                 ProcessInformationClass == ProcessHandleTracing))
            {
                __try
                {
                    if (ProcessInformationLength != 0)
                    {
                        ProbeForRead(ProcessInformation, ProcessInformationLength, 4);
                    }

                    PEPROCESS process = nullptr;
                    status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType,
                                                       previousMode, reinterpret_cast<PVOID *>(&process), nullptr);
                    if (NT_SUCCESS(status))
                    {
                        rules::PPROCESS_ENTRY threadProcessEntry = rules::GetProcessEntry(PsGetProcessId(process));

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(process);

                            if (threadProcessEntry)
                            {
                                object::DereferenceObject(threadProcessEntry);
                                threadProcessEntry = nullptr;
                            }
                        };

                        if (threadProcessEntry && BooleanFlagOn(threadProcessEntry->PolicyFlags,
                                                                rules::ProcessPolicyFlagNtSetInformationProcess))
                        {
                            if (ProcessInformationClass == ProcessBreakOnTermination)
                            {
                                if (ProcessInformationLength != sizeof(ULONG))
                                {
                                    return STATUS_INFO_LENGTH_MISMATCH;
                                }

                                volatile ULONG Touch = *(ULONG *)ProcessInformation;
                                UNREFERENCED_PARAMETER(Touch);

                                // A process must have debug privileges enabled to set the ProcessBreakOnTermination
                                // flag
                                if (!tools::HasDebugPrivilege())
                                {
                                    return STATUS_PRIVILEGE_NOT_HELD;
                                }

                                threadProcessEntry->Flags.ValueProcessBreakOnTermination =
                                    *(ULONG *)ProcessInformation & 1;

                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                              "Spoofed NtSetInformationProcess(ProcessBreakOnTermination) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                return STATUS_SUCCESS;
                            }
                            else if (ProcessInformationClass == ProcessDebugFlags)
                            {
                                if (ProcessInformationLength != sizeof(ULONG))
                                {
                                    return STATUS_INFO_LENGTH_MISMATCH;
                                }

                                ULONG Flags = *(ULONG *)ProcessInformation;
                                if ((Flags & ~PROCESS_DEBUG_INHERIT) != 0)
                                {
                                    return STATUS_INVALID_PARAMETER;
                                }

                                if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
                                {
                                    threadProcessEntry->Flags.ValueProcessDebugFlags = 0;
                                }
                                else
                                {
                                    threadProcessEntry->Flags.ValueProcessDebugFlags = TRUE;
                                }

                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                              "Spoofed NtSetInformationProcess(ProcessDebugFlags) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                return STATUS_SUCCESS;
                            }
                            else if (ProcessInformationClass == ProcessHandleTracing)
                            {
                                const bool enable = ProcessInformationLength != 0;
                                if (enable)
                                {
                                    if (ProcessInformationLength != sizeof(ULONG) &&
                                        ProcessInformationLength != (sizeof(ULONG64)))
                                    {
                                        return STATUS_INFO_LENGTH_MISMATCH;
                                    }

                                    PPROCESS_HANDLE_TRACING_ENABLE_EX phtEx =
                                        (PPROCESS_HANDLE_TRACING_ENABLE_EX)ProcessInformation;

                                    if (phtEx->Flags != 0)
                                    {
                                        return STATUS_INVALID_PARAMETER;
                                    }
                                }

                                processEntry->Flags.ProcessHandleTracingEnabled = enable;

                                WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                              "Spoofed NtSetInformationProcess(ProcessHandleTracing) tid:%d",
                                              HandleToUlong(threadProcessEntry->ProcessId));

                                return STATUS_SUCCESS;
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return oNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                    ProcessInformationLength);
}

void FilterObject(POBJECT_TYPE_INFORMATION pObject)
{
    UNICODE_STRING debugObjectName = RTL_CONSTANT_STRING(L"DebugObject");
    if (RtlEqualUnicodeString(&debugObjectName, &pObject->TypeName, FALSE))
    {
        // Subtract just one from both counts for our debugger, unless the query was a generic one for all object
        // types
        pObject->TotalNumberOfObjects = 0;
        pObject->TotalNumberOfHandles = 0;
    }
}

void FilterObjects(POBJECT_ALL_INFORMATION pObjectAllInformation)
{
    auto pObject = pObjectAllInformation->ObjectInformation;

    for (ULONG i = 0; i < pObjectAllInformation->NumberOfObjectsTypes; i++)
    {
        FilterObject(pObject);

        pObject =
            (POBJECT_TYPE_INFORMATION)(((PCHAR)(pObject + 1) + ALIGN_UP(pObject->TypeName.MaximumLength, ULONG_PTR)));
    }
}

NTSTATUS NTAPI hkNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation,
                               ULONG ObjectInformationLength, PULONG ReturnLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status =
        oNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode && ObjectInformation)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtQueryObject))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                __try
                {
                    if ((ObjectInformationClass == ObjectTypesInformation ||
                         ObjectInformationClass == ObjectTypeInformation) &&
                        (NT_SUCCESS(status) && ObjectInformation))
                    {
                        // Probe usermode buffer
                        ProbeForWrite(ObjectInformation, ObjectInformationLength, 1);

                        if (ObjectInformationClass == ObjectTypesInformation)
                        {
                            BACKUP_RETURNLENGTH();

                            FilterObjects((POBJECT_ALL_INFORMATION)ObjectInformation);

                            RESTORE_RETURNLENGTH();

                            WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                          "Spoofed NtQueryObject(ObjectTypesInformation) tid:%d",
                                          HandleToUlong(processEntry->ProcessId));
                        }
                        else if (ObjectInformationClass == ObjectTypeInformation)
                        {
                            BACKUP_RETURNLENGTH();

                            FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation);

                            RESTORE_RETURNLENGTH();

                            WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                          "Spoofed NtQueryObject(ObjectTypeInformation) tid:%d",
                                          HandleToUlong(processEntry->ProcessId));
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
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

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode && (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER ||
                                     CreateFlags & THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE))
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtCreateThreadEx))
        {
            NTSTATUS status;
            ULONG OriginalFlags = CreateFlags;

            if (KERNEL_BUILD >= WINDOWS_10_VERSION_19H1)
            {
                status = oNtCreateThreadEx(
                    ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument,
                    CreateFlags & ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE),
                    ZeroBits, StackSize, MaximumStackSize, AttributeList);
            }
            else
            {
                status = oNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine,
                                           Argument, CreateFlags & ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER), ZeroBits,
                                           StackSize, MaximumStackSize, AttributeList);
            }

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
                    if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType,
                                                             previousMode, reinterpret_cast<PVOID *>(&process), NULL)))
                    {
                        rules::PPROCESS_ENTRY processEntry2 = rules::GetProcessEntry(process);

                        SCOPE_EXIT
                        {
                            ObDereferenceObject(process);

                            if (processEntry2)
                            {
                                object::DereferenceObject(processEntry2);
                                processEntry2 = nullptr;
                            }
                        };

                        // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
                        //
                        if (processEntry2 &&
                            BooleanFlagOn(processEntry2->PolicyFlags, rules::ProcessPolicyFlagNtCreateThreadEx))
                        {
                            if (BooleanFlagOn(processEntry2->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
                            {
                                rules::PTHREAD_ENTRY threadEntry = processEntry2->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    threadEntry->Flags.IsThreadHidden =
                                        OriginalFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
                                }
                            }
                        }
                    }
                }
            }

            return status;
        }
    }

    return oNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument,
                             CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NTAPI hkNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS status;

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtGetContextThread))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                __try
                {
                    ProbeForWrite(ThreadContext, sizeof(*ThreadContext), __alignof(CONTEXT));

                    PETHREAD thread = nullptr;
                    status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                       previousMode, reinterpret_cast<PVOID *>(&thread), nullptr);
                    if (NT_SUCCESS(status))
                    {
                        rules::PPROCESS_ENTRY threadProcessEntry = rules::GetProcessEntry(PsGetThreadProcessId(thread));

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
                            BooleanFlagOn(threadProcessEntry->PolicyFlags, rules::ProcessPolicyFlagNtGetContextThread))
                        {
                            ULONG OriginalFlags = ThreadContext->ContextFlags;
                            ThreadContext->ContextFlags &= ~0x10;

                            status = oNtGetContextThread(ThreadHandle, ThreadContext);

                            if (OriginalFlags & 0x10)
                            {
                                ThreadContext->ContextFlags |= 0x10;

                                rules::PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    RtlCopyMemory(&ThreadContext->Dr0, &threadEntry->SavedDebugContext.Dr0,
                                                  sizeof(ULONG64) * 6);
                                    RtlCopyMemory(&ThreadContext->DebugControl,
                                                  &threadEntry->SavedDebugContext.DebugControl, sizeof(ULONG64) * 5);

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS, "Spoofed NtGetContextThread tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }
                                else
                                {
                                    RtlSecureZeroMemory(&ThreadContext->Dr0, sizeof(ULONG64) * 6);
                                    RtlSecureZeroMemory(&ThreadContext->DebugControl, sizeof(ULONG64) * 5);
                                }
                            }
                            return status;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return oNtGetContextThread(ThreadHandle, ThreadContext);
}

NTSTATUS NTAPI hkNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS status;

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtSetContextThread))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                __try
                {
                    ProbeForWrite(ThreadContext, sizeof(*ThreadContext), __alignof(CONTEXT));

                    PETHREAD thread = nullptr;
                    status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                       previousMode, reinterpret_cast<PVOID *>(&thread), nullptr);
                    if (NT_SUCCESS(status))
                    {
                        rules::PPROCESS_ENTRY threadProcessEntry = rules::GetProcessEntry(PsGetThreadProcessId(thread));

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
                            BooleanFlagOn(threadProcessEntry->PolicyFlags, rules::ProcessPolicyFlagNtSetContextThread))
                        {
                            ULONG OriginalFlags = ThreadContext->ContextFlags;
                            ThreadContext->ContextFlags &= ~0x10;

                            status = oNtSetContextThread(ThreadHandle, ThreadContext);

                            if (OriginalFlags & 0x10)
                            {
                                ThreadContext->ContextFlags |= 0x10;

                                rules::PTHREAD_ENTRY threadEntry = threadProcessEntry->AppendThreadList(thread);
                                if (threadEntry)
                                {
                                    RtlCopyMemory(&threadEntry->SavedDebugContext.Dr0, &ThreadContext->Dr0,
                                                  sizeof(ULONG64) * 6);
                                    RtlCopyMemory(&threadEntry->SavedDebugContext.DebugControl,
                                                  &ThreadContext->DebugControl, sizeof(ULONG64) * 5);

                                    WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS, "Spoofed NtSetContextThread tid:%d",
                                                  HandleToUlong(PsGetThreadId(threadEntry->Thread)));
                                }
                            }
                            return status;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return oNtSetContextThread(ThreadHandle, ThreadContext);
}

NTSTATUS NTAPI hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,
                                      PULONG NumberOfBytesWritten)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status =
        oNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

    // TODO: implement

    return status;
}

NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                         PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status =
        oNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    // TODO: implement

    return status;
}

NTSTATUS NTAPI hkNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status = oNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);

    // TODO: implement

    return status;
}

NTSTATUS NTAPI hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                       PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
                                       ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS status = oNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
                                             InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtDeviceIoControlFile))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                const LPWSTR moduleName = wcsrchr(processEntry->ImageFileName.Buffer, '\\') + 1;

                //
                // Hardware Spoofing
                //
                if (NT_SUCCESS(status))
                {
                    __try
                    {
                        static constexpr char newSerialNumber[] = "XKH2A83XVALP766";
                        static constexpr char newModelNumber[] = "Kingston";
                        static constexpr UCHAR newMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

                        switch (IoControlCode)
                        {

                        case IOCTL_STORAGE_QUERY_PROPERTY: {
                            PSTORAGE_PROPERTY_QUERY Query = PSTORAGE_PROPERTY_QUERY(InputBuffer);
                            if (Query && Query->PropertyId == StorageDeviceProperty)
                            {
                                if (OutputBufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
                                {
                                    PSTORAGE_DEVICE_DESCRIPTOR Desc = PSTORAGE_DEVICE_DESCRIPTOR(OutputBuffer);
                                    if (Desc)
                                    {
                                        if (Desc->SerialNumberOffset)
                                        {
                                            auto serialNumber = PCHAR(Desc) + Desc->SerialNumberOffset;
                                            const size_t serialNumberLen = strlen(serialNumber);

                                            if (serialNumberLen > 0)
                                            {
                                                DBGPRINT("[Process: %ls] [IOCTL_STORAGE_QUERY_PROPERTY] spoofing "
                                                         "serial %s "
                                                         "to %s\n",
                                                         moduleName, serialNumber, newSerialNumber);

                                                RtlZeroMemory(serialNumber, serialNumberLen);
                                                strcpy(serialNumber, newSerialNumber);
                                            }
                                        }

                                        if (Desc->ProductIdOffset)
                                        {
                                            auto modelNumber = PCHAR(Desc) + Desc->ProductIdOffset;
                                            const size_t modelNumberLen = strlen(modelNumber);

                                            if (modelNumberLen > 0)
                                            {
                                                DBGPRINT("[Process: %ls] [IOCTL_STORAGE_QUERY_PROPERTY] spoofing "
                                                         "model %s "
                                                         "to %s\n",
                                                         moduleName, modelNumber, newModelNumber);

                                                RtlZeroMemory(modelNumber, modelNumberLen);
                                                strcpy(modelNumber, newModelNumber);
                                            }
                                        }
                                    }
                                }
                            }
                            break;
                        }

                        case IOCTL_ATA_PASS_THROUGH: {
                            if (OutputBufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))
                            {
                                PATA_PASS_THROUGH_EX Ata = PATA_PASS_THROUGH_EX(OutputBuffer);
                                if (Ata && Ata->DataBufferOffset)
                                {
                                    PIDENTIFY_DEVICE_DATA Identify =
                                        PIDENTIFY_DEVICE_DATA(PCHAR(OutputBuffer) + Ata->DataBufferOffset);
                                    if (Identify)
                                    {
                                        auto Serial = PCHAR(Identify->SerialNumber);
                                        if (strlen(Serial) > 0)
                                        {
                                            tools::SwapEndianness(Serial, sizeof(Identify->SerialNumber));

                                            DBGPRINT("%ls Spoofing Serial ( 0x%X ) Old: %s New: %s\n", moduleName,
                                                     IoControlCode, Serial, newSerialNumber);

                                            RtlZeroMemory(Serial, strlen(Serial));
                                            strcpy(Serial, newSerialNumber);

                                            tools::SwapEndianness(Serial, sizeof(Identify->SerialNumber));
                                        }

                                        auto Model = PCHAR(Identify->ModelNumber);
                                        if (strlen(Model) > 0)
                                        {
                                            // Fix invalid characters.
                                            Model[sizeof(Identify->ModelNumber) - 1] = 0;
                                            Model[sizeof(Identify->ModelNumber) - 2] = 0;

                                            tools::SwapEndianness(Model, sizeof(Identify->ModelNumber) - 2);

                                            DBGPRINT("$ls Spoofing Model ( 0x%X ) Old: %s New: %s\n", moduleName,
                                                     IoControlCode, Model, newModelNumber);

                                            RtlZeroMemory(Model, strlen(Model));
                                            strcpy(Model, newModelNumber);

                                            tools::SwapEndianness(Model, sizeof(Identify->ModelNumber) - 2);
                                        }
                                    }
                                }
                            }
                            break;
                        }

                        case SMART_RCV_DRIVE_DATA: {
                            if (OutputBufferLength >= sizeof(SENDCMDOUTPARAMS))
                            {
                                PSENDCMDOUTPARAMS sendCmdOutParams = PSENDCMDOUTPARAMS(OutputBuffer);
                                if (sendCmdOutParams)
                                {
                                    PIDSECTOR sector = PIDSECTOR(sendCmdOutParams->bBuffer);
                                    if (sector)
                                    {
                                        auto serialNumber = PCHAR(sector->sSerialNumber);
                                        const size_t serialNumberLen = strlen(serialNumber);

                                        if (serialNumberLen > 0)
                                        {
                                            tools::SwapEndianness(serialNumber, sizeof(sector->sSerialNumber));

                                            DBGPRINT("[Process: %ls] [SMART_RCV_DRIVE_DATA] spoofing serial %s to %s\n",
                                                     moduleName, serialNumber, newSerialNumber);

                                            RtlZeroMemory(serialNumber, serialNumberLen);
                                            strcpy(serialNumber, newSerialNumber);

                                            tools::SwapEndianness(serialNumber, sizeof(sector->sSerialNumber));
                                        }

                                        auto moduleNumber = reinterpret_cast<PCHAR>(sector->sModelNumber);
                                        const size_t moduleNumberLen = strlen(moduleNumber);

                                        if (moduleNumberLen > 0)
                                        {
                                            // Fix invalid characters.
                                            moduleNumber[sizeof(sector->sModelNumber) - 1] = 0;
                                            moduleNumber[sizeof(sector->sModelNumber) - 2] = 0;

                                            tools::SwapEndianness(moduleNumber, sizeof(sector->sModelNumber) - 2);

                                            DBGPRINT("[Process: %ls] [SMART_RCV_DRIVE_DATA] spoofing model %s to %s\n",
                                                     moduleName, moduleNumber, newModelNumber);

                                            RtlZeroMemory(moduleNumber, moduleNumberLen);
                                            strcpy(moduleNumber, newModelNumber);

                                            tools::SwapEndianness(moduleNumber, sizeof(sector->sModelNumber) - 2);
                                        }
                                    }
                                }
                            }
                            break;
                        }

                        case IOCTL_DISK_GET_PARTITION_INFO_EX: {
                            if (OutputBufferLength >= sizeof(PARTITION_INFORMATION_EX))
                            {
                                PPARTITION_INFORMATION_EX PartInfo = PPARTITION_INFORMATION_EX(OutputBuffer);
                                if (PartInfo && PartInfo->PartitionStyle == PARTITION_STYLE_GPT)
                                {
                                    DBGPRINT("%ls Zero'ing partition GUID (EX)\n", moduleName);
                                    memset(&PartInfo->Gpt.PartitionId, 0, sizeof(GUID));
                                }
                            }
                            break;
                        }

                        case IOCTL_DISK_GET_DRIVE_LAYOUT_EX: {
                            if (OutputBufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX))
                            {
                                PDRIVE_LAYOUT_INFORMATION_EX LayoutInfo = PDRIVE_LAYOUT_INFORMATION_EX(OutputBuffer);
                                if (LayoutInfo && LayoutInfo->PartitionStyle == PARTITION_STYLE_GPT)
                                {
                                    DBGPRINT("%ls Zero'ing partition GUID\n", moduleName);
                                    memset(&LayoutInfo->Gpt.DiskId, 0, sizeof(GUID));
                                }
                            }
                            break;
                        }

                        case IOCTL_MOUNTMGR_QUERY_POINTS: {
                            if (OutputBufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS))
                            {
                                PMOUNTMGR_MOUNT_POINTS Points = PMOUNTMGR_MOUNT_POINTS(OutputBuffer);
                                if (Points)
                                {
                                    DBGPRINT("%ls Spoofing mounted points\n", moduleName);
                                    for (unsigned i = 0; i < Points->NumberOfMountPoints; ++i)
                                    {
                                        auto Point = &Points->MountPoints[i];

                                        if (Point->UniqueIdOffset)
                                            Point->UniqueIdLength = 0;

                                        if (Point->SymbolicLinkNameOffset)
                                            Point->SymbolicLinkNameLength = 0;
                                    }
                                }
                            }
                            break;
                        }

                        case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID: {
                            if (OutputBufferLength >= sizeof(MOUNTDEV_UNIQUE_ID))
                            {
                                PMOUNTDEV_UNIQUE_ID UniqueId = PMOUNTDEV_UNIQUE_ID(OutputBuffer);
                                if (UniqueId)
                                {
                                    DBGPRINT("%ls Spoofing mounted unique id\n", moduleName);
                                    UniqueId->UniqueIdLength = 0;
                                }
                            }
                            break;
                        }

                        case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
                            switch (*(PDWORD)InputBuffer)
                            {
                            case OID_802_3_PERMANENT_ADDRESS:
                            case OID_802_3_CURRENT_ADDRESS:
                            case OID_802_5_PERMANENT_ADDRESS:
                            case OID_802_5_CURRENT_ADDRESS:
                                DBGPRINT("%ls Spoofing permanent MAC\n", moduleName);

                                RtlCopyMemory(OutputBuffer, newMac, sizeof(newMac));
                                break;
                            }
                        }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        return GetExceptionCode();
                    }
                }
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
        if (rules::IsProtectedProcess((HANDLE)pHandleInfo->Handles[i].UniqueProcessId))
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
        if (rules::IsProtectedProcess((HANDLE)pHandleInfoEx->Handles[i].UniqueProcessId))
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

void FilterModuleInfoEx(PRTL_PROCESS_MODULES pModules, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = (ULONG)pModules->NumberOfModules;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        if (rules::IsWhitelistedDriver((PCHAR)pModules->Modules[i].FullPathName))
        {
            pModules->NumberOfModules--;
            *pReturnLengthAdjust += sizeof(RTL_PROCESS_MODULES);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                pModules->Modules[j] = pModules->Modules[j + 1];
                RtlZeroMemory(&pModules->Modules[j + 1], sizeof(pModules->Modules[j + 1]));
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
        if (rules::IsProtectedProcess(pInfo->UniqueProcessId))
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

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status =
        oNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (NT_SUCCESS(status) && (processEntry && BooleanFlagOn(processEntry->PolicyFlags,
                                                                 rules::ProcessPolicyFlagNtQuerySystemInformation)))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                __try
                {
                    ProbeForWrite(SystemInformation, SystemInformationLength, 1);

                    //
                    // Hide from Driver list
                    //
                    if (SystemInformationClass == SystemModuleInformation)
                    {
                        BACKUP_RETURNLENGTH();
                        ULONG ReturnLengthAdjust = 0;

                        FilterModuleInfoEx(PRTL_PROCESS_MODULES(SystemInformation), &ReturnLengthAdjust);

                        if (ReturnLengthAdjust <= TempReturnLength)
                            TempReturnLength -= ReturnLengthAdjust;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemModuleInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    //
                    // Hide from Process list
                    //
                    else if (SystemInformationClass == SystemProcessInformation ||
                             SystemInformationClass == SystemSessionProcessInformation ||
                             SystemInformationClass == SystemExtendedProcessInformation)
                    {
                        BACKUP_RETURNLENGTH();

                        PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
                        if (SystemInformationClass == SystemSessionProcessInformation)
                        {
                            ProcessInfo =
                                (PSYSTEM_PROCESS_INFORMATION)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)
                                    ->Buffer;
                        }

                        FilterProcess(ProcessInfo);

                        for (PSYSTEM_PROCESS_INFORMATION entry = ProcessInfo; entry->NextEntryOffset != NULL;
                             entry = (PSYSTEM_PROCESS_INFORMATION)((UCHAR *)entry + entry->NextEntryOffset))
                        {
                            rules::PPROCESS_ENTRY processEntry2 = rules::GetProcessEntry(entry->UniqueProcessId);

                            SCOPE_EXIT
                            {
                                if (processEntry2)
                                {
                                    object::DereferenceObject(processEntry2);
                                    processEntry2 = nullptr;
                                }
                            };

                            if (processEntry2 && BooleanFlagOn(processEntry2->PolicyFlags,
                                                               rules::ProcessPolicyFlagNtQuerySystemInformation))
                            {
                                PEPROCESS process = tools::GetProcessByName(processEntry2->FakeParentProcessName);
                                if (process)
                                {
                                    entry->InheritedFromUniqueProcessId = PsGetProcessId(process);
                                    ObDereferenceObject(process);
                                }

                                entry->OtherOperationCount.QuadPart = 1;
                            }
                        }

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(ProcessInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    //
                    // Hide from handle list
                    //
                    else if (SystemInformationClass == SystemHandleInformation)
                    {
                        BACKUP_RETURNLENGTH();
                        ULONG ReturnLengthAdjust = 0;

                        FilterHandleInfo((PSYSTEM_HANDLE_INFORMATION)SystemInformation, &ReturnLengthAdjust);

                        if (ReturnLengthAdjust <= TempReturnLength)
                            TempReturnLength -= ReturnLengthAdjust;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemHandleInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemExtendedHandleInformation)
                    {
                        BACKUP_RETURNLENGTH();
                        ULONG ReturnLengthAdjust = 0;

                        FilterHandleInfoEx((PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation, &ReturnLengthAdjust);

                        if (ReturnLengthAdjust <= TempReturnLength)
                            TempReturnLength -= ReturnLengthAdjust;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemExtendedHandleInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    //
                    // Spoof code integrity status
                    //
                    else if (SystemInformationClass == SystemCodeIntegrityInformation)
                    {
                        BACKUP_RETURNLENGTH();

                        auto systemInformation = PSYSTEM_CODEINTEGRITY_INFORMATION(SystemInformation);

                        ULONG options = systemInformation->CodeIntegrityOptions;

                        // fix flags
                        options &= ~CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;
                        options &= ~CODEINTEGRITY_OPTION_TESTSIGN;
                        options |= CODEINTEGRITY_OPTION_ENABLED;

                        systemInformation->CodeIntegrityOptions = options;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemCodeIntegrityInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemCodeIntegrityUnlockInformation)
                    {
                        BACKUP_RETURNLENGTH();

                        // The size of the buffer for this class changed from 4 to 36, but the output should still
                        // be all zeroes
                        RtlSecureZeroMemory(SystemInformation, SystemInformationLength);

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemCodeIntegrityUnlockInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemKernelDebuggerInformation)
                    {
                        PSYSTEM_KERNEL_DEBUGGER_INFORMATION debuggerInfo =
                            (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

                        BACKUP_RETURNLENGTH();

                        debuggerInfo->KernelDebuggerEnabled = 0;
                        debuggerInfo->KernelDebuggerNotPresent = 1;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemKernelDebuggerInformation) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
                    {
                        auto debuggerInfoEx = PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX(SystemInformation);

                        BACKUP_RETURNLENGTH();

                        debuggerInfoEx->DebuggerAllowed = FALSE;
                        debuggerInfoEx->DebuggerEnabled = FALSE;
                        debuggerInfoEx->DebuggerPresent = FALSE;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemKernelDebuggerInformationEx) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                    else if (SystemInformationClass == SystemKernelDebuggerFlags)
                    {
                        BACKUP_RETURNLENGTH();

                        *(PUCHAR)SystemInformation = 0;

                        RESTORE_RETURNLENGTH();

                        WppTracePrint(TRACE_LEVEL_VERBOSE, HOOKS,
                                      "Spoofed NtQuerySystemInformation(SystemKernelDebuggerFlags) pid:%d",
                                      HandleToUlong(processEntry->ProcessId));
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return status;
}

NTSTATUS NTAPI hkNtLoadDriver(PUNICODE_STRING DriverServiceName)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtLoadDriver))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                // (3) Block loading of driver
                //
                __try
                {
                    if (DriverServiceName)
                    {
                        ProbeForRead(DriverServiceName, sizeof(*DriverServiceName), 1);
                        ProbeForRead(DriverServiceName->Buffer, DriverServiceName->Length, 1);

                        static constexpr LPCWSTR g_driverBlockList[] = {L"fltmgr.sys"};

                        LPCWSTR fileName = wcsrchr(DriverServiceName->Buffer, L'\\') + 1;

                        for (auto name : g_driverBlockList)
                        {
                            if (!_wcsicmp(fileName, name))
                            {
                                WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Blocked driver %wZ from loading",
                                              DriverServiceName);

                                return STATUS_UNSUCCESSFUL;
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return GetExceptionCode();
                }
            }
        }
    }
    return oNtLoadDriver(DriverServiceName);
}

HWND NTAPI hkNtUserWindowFromPoint(LONG x, LONG y)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const HWND resultHwnd = oNtUserWindowFromPoint(x, y);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtUserWindowFromPoint))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                const HANDLE processId = oNtUserQueryWindow(resultHwnd, WindowProcess);
                if (rules::IsProtectedProcess(processId))
                {
                    return NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
                }
            }
        }
    }
    return resultHwnd;
}

HANDLE NTAPI hkNtUserQueryWindow(HWND WindowHandle, WINDOWINFOCLASS WindowInfo)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtUserQueryWindow))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                // Spoof result if trying to query protected process
                //
                const HANDLE processId = oNtUserQueryWindow(WindowHandle, WindowProcess);
                if (rules::IsProtectedProcess(processId))
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
    return oNtUserQueryWindow(WindowHandle, WindowInfo);
}

HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass,
                                PUNICODE_STRING lpszWindow, DWORD dwType)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const HWND resultHwnd = oNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
            (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtUserFindWindowEx)))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                // Spoof result if trying to query protected process
                //
                const HANDLE processId = oNtUserQueryWindow(resultHwnd, WindowProcess);
                if (rules::IsProtectedProcess(processId))
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
        HANDLE processId = oNtUserQueryWindow(phwndFirst[i], WindowProcess);

        if (phwndFirst[i] != nullptr && rules::IsProtectedProcess(processId))
        {
            if (i == 0)
            {
                // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                {
                    processId = oNtUserQueryWindow(phwndFirst[j], WindowProcess);

                    if (phwndFirst[j] != nullptr && !rules::IsProtectedProcess(processId))
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

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status =
        oNtUserBuildHwndList_Win7(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        if (NT_SUCCESS(status) && phwndFirst && pcHwndNeeded)
        {
            const HANDLE currentProcessId = PsGetCurrentProcessId();
            rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
            if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtUserBuildHwndList))
            {
                if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
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

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status =
        oNtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        if (NT_SUCCESS(status) && pWnd && pBufSize)
        {
            const HANDLE currentProcessId = PsGetCurrentProcessId();
            rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
            if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtUserBuildHwndList))
            {
                if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
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

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const HWND resultHwnd = oNtUserGetForegroundWindow();

    const KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    if (previousMode == UserMode)
    {
        const HANDLE currentProcessId = PsGetCurrentProcessId();
        rules::PPROCESS_ENTRY processEntry = rules::GetProcessEntry(currentProcessId);

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
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagNtUserGetForegroundWindow))
        {
            if (BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHiddenFromDebugger))
            {
                // Spoof result if trying to query protected process
                //
                const HANDLE processId = oNtUserQueryWindow(resultHwnd, WindowProcess);
                if (rules::IsProtectedProcess(processId))
                {
                    return NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
                }
            }
        }
    }
    return resultHwnd;
}
} // namespace hooks
} // namespace masterhide