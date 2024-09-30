#include "includes.hpp"

#pragma once

namespace masterhide
{
namespace rules
{
DECLARE_GLOBAL_CONST_UNICODE_STRING(g_processEntryObjectName, L"ProcessEntryObject");
DECLARE_GLOBAL_CONST_UNICODE_STRING(g_processRuleEntryObjectName, L"ProcessRuleEntryObject");

object::POBJECT_TYPE g_objTypeProcessEntry = nullptr;
object::POBJECT_TYPE g_objTypeProcessRuleEntry = nullptr;

bool g_stopCounterThread = false;
HANDLE g_counterThreadHandle = nullptr;

/*

    Process entry object Allocate, Delete and Free.

*/
PVOID AllocateProcessEntry(_In_ SIZE_T size)
{
    PAGED_CODE();

    return tools::AllocatePoolZero(NonPagedPool, size, tags::TAG_PROCESS_ENTRY);
}

void FreeProcessEntry(_In_ PVOID object)
{
    PAGED_CODE();

    ExFreePool(object);
}

void DeleteProcessEntry(_In_ PVOID object)
{
    NT_ASSERT(object);

    PPROCESS_ENTRY processEntry = static_cast<PPROCESS_ENTRY>(object);

    // Delete thread objects
    //
    if (processEntry->ThreadsResource.LockExclusive())
    {
        while (!IsListEmpty(&processEntry->Threads.ListEntry))
        {
            PLIST_ENTRY listEntry = RemoveHeadList(&processEntry->Threads.ListEntry);
            PTHREAD_ENTRY threadEntry = CONTAINING_RECORD(listEntry, THREAD_ENTRY, ListEntry);

            ObDereferenceObject(threadEntry->Thread);
            ExFreePool(threadEntry);
        }

        processEntry->ThreadsResource.Unlock();
    }

    processEntry->ThreadsResource.Deinitialize();

    // Delete process objects
    //
    if (processEntry->Kusd.KuserSharedData != NULL)
    {
        process::UnHookKuserSharedData(processEntry);
    }

    if (processEntry->ImageFileName.Buffer)
    {
        RtlFreeUnicodeString(&processEntry->ImageFileName);
    }

    ObDereferenceObject(processEntry->Process);
}

/*

    Process rules object Allocate, Delete and Free.

*/
void FreeProcessRuleEntry(_In_ PVOID object)
{
    PAGED_CODE();

    ExFreePool(object);
}

PVOID AllocateProcessRuleEntry(_In_ SIZE_T size)
{
    PAGED_CODE();

    return tools::AllocatePoolZero(NonPagedPool, size, tags::TAG_PROCESS_RULE_ENTRY);
}

void DeleteProcessRuleEntry(_In_ PVOID object)
{
    NT_ASSERT(object);

    auto processRuleEntry = static_cast<PPROCESS_RULE_ENTRY>(object);

    if (processRuleEntry->ImageFileName.Buffer)
    {
        RtlFreeUnicodeString(&processRuleEntry->ImageFileName);
    }
}

NTSTATUS Initialize()
{
    NT_ASSERT(!g_initialized);

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    InitializeListHead(&g_processRuleListHead);
    InitializeListHead(&g_processListHead);

    NTSTATUS status = g_processRuleResource.Initialize();
    if (!NT_SUCCESS(status))
    {
        g_processResource.Deinitialize();

        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Failed to initialize processes rules resource %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = g_processResource.Initialize();
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Failed to initialize processes resource %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    status = PsCreateSystemThread(&g_counterThreadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, CounterUpdater,
                                  nullptr);
    if (!NT_SUCCESS(status))
    {
        g_processRuleResource.Deinitialize();
        g_processResource.Deinitialize();

        WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "PsCreateSystemThread returned %!STATUS!", status);

        return status;
    }

    // Create object types
    //
    {
        object::OBJECT_TYPE_INFO typeInfo{};
        typeInfo.Allocate = AllocateProcessRuleEntry;
        typeInfo.Initialize = NULL;
        typeInfo.Delete = DeleteProcessRuleEntry;
        typeInfo.Free = FreeProcessRuleEntry;

        object::CreateObjectType(&g_processRuleEntryObjectName, &typeInfo, &g_objTypeProcessRuleEntry);

        NT_ASSERT(g_objTypeProcessRuleEntry);
    }
    {
        object::OBJECT_TYPE_INFO typeInfo{};
        typeInfo.Allocate = AllocateProcessEntry;
        typeInfo.Initialize = NULL;
        typeInfo.Delete = DeleteProcessEntry;
        typeInfo.Free = FreeProcessEntry;

        object::CreateObjectType(&g_processEntryObjectName, &typeInfo, &g_objTypeProcessEntry);

        NT_ASSERT(g_objTypeProcessEntry);
    }

    g_initialized = true;

    return STATUS_SUCCESS;
}

void Deinitialize()
{
    PAGED_CODE();

    if (!g_initialized)
    {
        return;
    }

    // Tell counter thread to stop.
    //
    g_stopCounterThread = true;

    ZwWaitForSingleObject(g_counterThreadHandle, FALSE, nullptr);
    ZwClose(g_counterThreadHandle);

    // (1) Obtain lock and free all list objects recursively
    //
    if (g_processResource.LockExclusive())
    {
        while (!IsListEmpty(&g_processListHead))
        {
            PLIST_ENTRY listEntry = RemoveHeadList(&g_processListHead);
            PPROCESS_ENTRY processEntry = CONTAINING_RECORD(listEntry, PROCESS_ENTRY, ListEntry);

            object::DereferenceObject(processEntry);
        }

        g_processResource.Unlock();
    }

    if (g_processRuleResource.LockExclusive())
    {
        while (!IsListEmpty(&g_processRuleListHead))
        {
            PLIST_ENTRY listEntry = RemoveHeadList(&g_processRuleListHead);
            PPROCESS_RULE_ENTRY processRuleEntry = CONTAINING_RECORD(listEntry, PROCESS_RULE_ENTRY, ListEntry);

            object::DereferenceObject(processRuleEntry);
        }

        g_processRuleResource.Unlock();
    }

    // (2) De-initialize the resource
    //
    g_processResource.Deinitialize();
    g_processRuleResource.Deinitialize();

    g_initialized = false;

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Successfully de-initialized rules interface!");
    return;
}

bool IsWhitelistedDriver(_In_ LPCSTR driverName)
{
    UNREFERENCED_PARAMETER(driverName);
    // TODO: implement
    return false;
}

PPROCESS_ENTRY GetProcessEntry(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);

    PPROCESS_ENTRY resultProcessEntry = nullptr;

    if (g_processResource.LockShared())
    {
        EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
            if (processEntry->ProcessId == processId)
            {
                object::ReferenceObject(processEntry);
                resultProcessEntry = processEntry;
                return true;
            }
            return false;
        });

        g_processResource.Unlock();
    }

    return resultProcessEntry;
}

PPROCESS_ENTRY GetProcessEntry(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    return GetProcessEntry(PsGetProcessId(process));
}

bool IsProtectedProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);

    bool result = false;

    if (g_processResource.LockShared())
    {
        result = EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
            return (processEntry->ProcessId == processId &&
                    BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagProtected));
        });

        g_processResource.Unlock();
    }

    return result;
}

bool IsProtectedProcess(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    return IsProtectedProcess(PsGetProcessId(process));
}

bool IsProtectedProcess(_In_ PUNICODE_STRING imageFileName)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(imageFileName);

    bool result = false;

    if (g_processResource.LockShared())
    {
        result = EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
            return (!RtlCompareUnicodeString(&processEntry->ImageFileName, imageFileName, TRUE) &&
                    BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagProtected));
        });

        g_processResource.Unlock();
    }

    return result;
}

bool IsMonitoredProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);

    bool result = false;

    if (g_processResource.LockShared())
    {
        result = EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
            return (processEntry->ProcessId == processId &&
                    BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagMonitored));
        });

        g_processResource.Unlock();
    }

    return result;
}

bool IsMonitoredProcess(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    return IsMonitoredProcess(PsGetProcessId(process));
}

bool IsHiddenFromDebugProcess(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(processId);

    bool result = false;

    if (g_processResource.LockShared())
    {
        result = EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
            return (processEntry->ProcessId == processId &&
                    BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHiddenFromDebugger));
        });

        g_processResource.Unlock();
    }

    return result;
}

bool IsHideDebugProcess(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    return IsHiddenFromDebugProcess(PsGetProcessId(process));
}

PPROCESS_RULE_ENTRY GetProcessRuleEntry(_In_ PCUNICODE_STRING imageFileName)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(imageFileName);

    PPROCESS_RULE_ENTRY resultProcessRuleEntry = nullptr;

    if (g_processRuleResource.LockShared())
    {
        EnumRuleProcessesUnsafe([&](PPROCESS_RULE_ENTRY processRuleEntry) -> bool {
            if (!RtlCompareUnicodeString(&processRuleEntry->ImageFileName, imageFileName, TRUE))
            {
                object::ReferenceObject(processRuleEntry);
                resultProcessRuleEntry = processRuleEntry;
                return true;
            }
            return false;
        });

        g_processRuleResource.Unlock();
    }

    return resultProcessRuleEntry;
}

NTSTATUS AddProcessRuleEntry(_In_ PUNICODE_STRING imageFileName, _In_ ProcessPolicyFlag_t flags)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(imageFileName);

    auto ExistsProcessRuleEntry = [&]() -> bool {
        return EnumRuleProcessesUnsafe([&](PPROCESS_RULE_ENTRY processRuleEntry) -> bool {
            return !RtlCompareUnicodeString(&processRuleEntry->ImageFileName, imageFileName, TRUE);
        });
    };

    if (!g_processRuleResource.LockExclusive())
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to obtain process rule entry resource lock!");

        return STATUS_LOCK_NOT_GRANTED;
    }

    SCOPE_EXIT
    {
        g_processRuleResource.Unlock();
    };

    if (ExistsProcessRuleEntry())
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "image:%wZ already exists in process rule list!", imageFileName);

        return STATUS_ALREADY_REGISTERED;
    }

    PPROCESS_RULE_ENTRY processRuleEntry = nullptr;

    NTSTATUS status = object::CreateObject(g_objTypeProcessRuleEntry, sizeof(PROCESS_RULE_ENTRY),
                                           reinterpret_cast<PVOID *>(&processRuleEntry), nullptr);
    if (!NT_SUCCESS(status))
    {

        return STATUS_UNSUCCESSFUL;
    }

    processRuleEntry->PolicyFlags = flags;
    processRuleEntry->ImageFileName.Length = 0;
    processRuleEntry->ImageFileName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
    processRuleEntry->ImageFileName.Buffer =
        tools::AllocatePoolZero<PWCH>(NonPagedPool, processRuleEntry->ImageFileName.MaximumLength, tags::TAG_STRING);
    if (!processRuleEntry->ImageFileName.Buffer)
    {
        object::DereferenceObject(processRuleEntry);

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate image file name!");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlUnicodeStringCopy(&processRuleEntry->ImageFileName, imageFileName);
    if (!NT_SUCCESS(status))
    {
        object::DereferenceObject(processRuleEntry);

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "RtlUnicodeStringCopy returned %!STATUS!", status);

        return STATUS_INVALID_PARAMETER;
    }

    InsertTailList(&g_processRuleListHead, &processRuleEntry->ListEntry);

    return STATUS_SUCCESS;
}

void UpdateProcessEntryFlags(_In_ PPROCESS_ENTRY processEntry, _In_ ProcessPolicyFlag_t newFlags)
{
    // Check if any flag was changed
    //
    if (BooleanFlagOn(newFlags, ProcessPolicyFlagHideKUserSharedData) &&
        !BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideKUserSharedData))
    {
        process::HookKuserSharedData(processEntry);
    }
    else if (!BooleanFlagOn(newFlags, ProcessPolicyFlagHideKUserSharedData) &&
             BooleanFlagOn(processEntry->PolicyFlags, ProcessPolicyFlagHideKUserSharedData))
    {
        process::UnHookKuserSharedData(processEntry);
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearThreadHideFromDebuggerFlag) &&
        processEntry->Flags.HideFromDebuggerFlagCleared == FALSE)
    {
        process::ClearThreadHideFromDebuggerFlag(processEntry);
        processEntry->Flags.HideFromDebuggerFlagCleared = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearBypassProcessFreeze) &&
        processEntry->Flags.BypassProcessFreezeFlagCleared == FALSE)
    {
        process::ClearBypassProcessFreezeFlag(processEntry);
        processEntry->Flags.BypassProcessFreezeFlagCleared = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearPebBeingDebugged) &&
        processEntry->Flags.PebBeingDebuggedCleared == FALSE)
    {
        process::SetPebDeuggerFlag(processEntry->Process, FALSE);
        processEntry->Flags.PebBeingDebuggedCleared = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearPebNtGlobalFlag) &&
        processEntry->Flags.PebNtGlobalFlagCleared == FALSE)
    {
        process::ClearPebNtGlobalFlag(processEntry->Process);
        processEntry->Flags.PebNtGlobalFlagCleared = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearHeapFlags) && processEntry->Flags.HeapFlagsCleared == FALSE)
    {
        process::ClearHeapFlags(processEntry->Process);
        processEntry->Flags.HeapFlagsCleared = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearKUserSharedData) &&
        processEntry->Flags.KUserSharedDataCleared == FALSE)
    {
        if (processEntry->Kusd.KuserSharedData != NULL)
        {
            processEntry->Kusd.KuserSharedData->KdDebuggerEnabled = 0;
            processEntry->Flags.KUserSharedDataCleared = TRUE;
        }
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearProcessBreakOnTerminationFlag) &&
        processEntry->Flags.ProcessBreakOnTerminationCleared == FALSE)
    {
        process::ClearProcessBreakOnTerminationFlag(processEntry);
        processEntry->Flags.ProcessBreakOnTerminationCleared = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagClearThreadBreakOnTerminationFlag) &&
        processEntry->Flags.ThreadBreakOnTerminationCleared == FALSE)
    {
        process::ClearThreadBreakOnTerminationFlags(processEntry);
        processEntry->Flags.ThreadBreakOnTerminationCleared = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagSaveProcessDebugFlags) &&
        processEntry->Flags.ProcessDebugFlagsSaved == FALSE)
    {
        process::SaveProcessDebugFlags(processEntry);
        processEntry->Flags.ProcessDebugFlagsSaved = TRUE;
    }

    if (BooleanFlagOn(newFlags, ProcessPolicyFlagSaveProcessHandleTracing) &&
        processEntry->Flags.ProcessHandleTracingSaved == FALSE)
    {
        process::SaveProcessHandleTracing(processEntry);
        processEntry->Flags.ProcessHandleTracingSaved = TRUE;
    }

    // Finally set the policy flags
    //
    InterlockedExchange64(&processEntry->PolicyFlags, newFlags);
}

NTSTATUS UpdateProcessEntry(_In_ HANDLE processId, _In_ ProcessPolicyFlag_t flags)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);

    PPROCESS_ENTRY processEntry = GetProcessEntry(processId);
    if (!processEntry)
    {
        return STATUS_NOT_FOUND;
    }

    SCOPE_EXIT
    {
        object::DereferenceObject(processEntry);
    };

    if (!g_processResource.LockExclusive())
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to obtain process resource lock!");
        return STATUS_LOCK_NOT_GRANTED;
    }

    SCOPE_EXIT
    {
        g_processResource.Unlock();
    };

    UpdateProcessEntryFlags(processEntry, flags);

    return STATUS_SUCCESS;
}

NTSTATUS UpdateProcessEntry(_In_ PEPROCESS process, _In_ ProcessPolicyFlag_t flags)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    return UpdateProcessEntry(PsGetProcessId(process), flags);
}

NTSTATUS AddProcessEntry(_In_ PEPROCESS process, _In_ ProcessPolicyFlag_t flags)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    auto ExistsProcessEntry = [&]() -> bool {
        return EnumProcessesUnsafe(
            [&](PPROCESS_ENTRY processEntry) -> bool { return (processEntry->Process == process); });
    };

    UNICODE_STRING imageFileName{};

    // We have to obtain file name first because acquiring lock will disable kernel APCs
    //
    if (!tools::GetProcessFileName(process, &imageFileName))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to obtain pid:%d file name!",
                      HandleToUlong(PsGetProcessId(process)));

        return STATUS_UNSUCCESSFUL;
    }

    if (!g_processResource.LockExclusive())
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to obtain process resource lock!");
        return STATUS_LOCK_NOT_GRANTED;
    }

    SCOPE_EXIT
    {
        g_processResource.Unlock();
    };

    if (ExistsProcessEntry())
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to add process entry, pid:%d already exists in list!",
                      HandleToUlong(PsGetProcessId(process)));

        return STATUS_ALREADY_REGISTERED;
    }

    PPROCESS_ENTRY processEntry = nullptr;

    NTSTATUS status = object::CreateObject(g_objTypeProcessEntry, sizeof(PROCESS_ENTRY),
                                           reinterpret_cast<PVOID *>(&processEntry), nullptr);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to create process entry object %!STATUS!", status);

        return STATUS_UNSUCCESSFUL;
    }

    status = processEntry->ThreadsResource.Initialize();
    if (!NT_SUCCESS(status))
    {
        object::DereferenceObject(processEntry);

        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to initialize threads list resource!");

        return STATUS_UNSUCCESSFUL;
    }

    ObReferenceObject(process);
    processEntry->Process = process;
    processEntry->ProcessId = PsGetProcessId(process);
    processEntry->ImageFileName = imageFileName;
    RtlStringCchCopyW(processEntry->FakeParentProcessName, ARRAYSIZE(processEntry->FakeParentProcessName) - 1,
                      L"explorer.exe");

    UpdateProcessEntryFlags(processEntry, flags);

    InitializeListHead(&processEntry->Threads.ListEntry);
    InsertTailList(&g_processListHead, &processEntry->ListEntry);

    return STATUS_SUCCESS;
}

NTSTATUS RemoveProcessEntry(_In_ HANDLE processId)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);

    NTSTATUS status = STATUS_NOT_CAPABLE;

    if (g_processResource.LockExclusive())
    {
        if (EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
                if (processEntry->ProcessId == processId)
                {
                    if (processEntry->Kusd.KuserSharedData != NULL)
                    {
                        process::UnHookKuserSharedData(processEntry);
                    }

                    RemoveEntryList(&processEntry->ListEntry);
                    object::DereferenceObject(processEntry);

                    return true;
                }
                return false;
            }))
        {
            status = STATUS_SUCCESS;
        }

        g_processResource.Unlock();
    }
    return status;
}

NTSTATUS RemoveProcessEntry(_In_ PEPROCESS process)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    return RemoveProcessEntry(PsGetProcessId(process));
}

void CounterUpdater(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER TimeToWait = {0};
    TimeToWait.QuadPart = -10000LL; // relative 1ms

    while (!g_stopCounterThread)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &TimeToWait);

        if (rules::g_processResource.LockExclusive())
        {
            rules::EnumProcessesUnsafe([](_In_ rules::PPROCESS_ENTRY processEntry) -> bool {
                if (!processEntry->Flags.ProcessPaused && processEntry->Kusd.KuserSharedData &&
                    BooleanFlagOn(processEntry->PolicyFlags, rules::ProcessPolicyFlagHideKUserSharedData))
                {
                    *(ULONG64 *)&processEntry->Kusd.KuserSharedData->InterruptTime =
                        *(ULONG64 *)&KernelKuserSharedData->InterruptTime.LowPart -
                        processEntry->Kusd.DeltaInterruptTime;
                    processEntry->Kusd.KuserSharedData->InterruptTime.High2Time =
                        processEntry->Kusd.KuserSharedData->InterruptTime.High1Time;

                    *(ULONG64 *)&processEntry->Kusd.KuserSharedData->SystemTime =
                        *(ULONG64 *)&KernelKuserSharedData->SystemTime.LowPart - processEntry->Kusd.DeltaSystemTime;
                    processEntry->Kusd.KuserSharedData->SystemTime.High2Time =
                        processEntry->Kusd.KuserSharedData->SystemTime.High1Time;

                    processEntry->Kusd.KuserSharedData->LastSystemRITEventTickCount =
                        KernelKuserSharedData->LastSystemRITEventTickCount -
                        processEntry->Kusd.DeltaLastSystemRITEventTickCount;

                    *(ULONG64 *)&processEntry->Kusd.KuserSharedData->TickCount =
                        *(ULONG64 *)&KernelKuserSharedData->TickCount.LowPart - processEntry->Kusd.DeltaTickCount;
                    processEntry->Kusd.KuserSharedData->TickCount.High2Time =
                        processEntry->Kusd.KuserSharedData->TickCount.High1Time;

                    processEntry->Kusd.KuserSharedData->TimeUpdateLock =
                        KernelKuserSharedData->TimeUpdateLock - processEntry->Kusd.DeltaTimeUpdateLock;

                    processEntry->Kusd.KuserSharedData->BaselineSystemTimeQpc =
                        KernelKuserSharedData->BaselineSystemTimeQpc - processEntry->Kusd.DeltaBaselineSystemQpc;
                    processEntry->Kusd.KuserSharedData->BaselineInterruptTimeQpc =
                        processEntry->Kusd.KuserSharedData->BaselineSystemTimeQpc;
                }

                return false;
            });

            rules::g_processResource.Unlock();
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

void GetBegin(_In_ PEPROCESS process)
{
    if (rules::g_processResource.LockExclusive())
    {
        rules::EnumProcessesUnsafe([&](_In_ rules::PPROCESS_ENTRY processEntry) -> bool {
            if (processEntry->Process == process && processEntry->Kusd.BeginInterruptTime == NULL)
            {
                processEntry->Kusd.BeginInterruptTime = *(ULONG64 *)&KernelKuserSharedData->InterruptTime;
                processEntry->Kusd.BeginSystemTime = *(ULONG64 *)&KernelKuserSharedData->SystemTime;
                processEntry->Kusd.BeginLastSystemRITEventTickCount =
                    KernelKuserSharedData->LastSystemRITEventTickCount;
                processEntry->Kusd.BeginTickCount = *(ULONG64 *)&KernelKuserSharedData->TickCount;
                processEntry->Kusd.BeginTimeUpdateLock = KernelKuserSharedData->TimeUpdateLock;
                processEntry->Kusd.BeginBaselineSystemQpc = KernelKuserSharedData->BaselineSystemTimeQpc;
            }

            return false;
        });

        rules::g_processResource.Unlock();
    }
}

void UpdateDelta(_In_ PEPROCESS process)
{
    if (rules::g_processResource.LockExclusive())
    {
        rules::EnumProcessesUnsafe([&](_In_ rules::PPROCESS_ENTRY processEntry) -> bool {
            if (processEntry->Process == process && processEntry->Kusd.BeginInterruptTime != NULL)
            {
                processEntry->Kusd.DeltaInterruptTime +=
                    *(ULONG64 *)&KernelKuserSharedData->InterruptTime - processEntry->Kusd.BeginInterruptTime;
                processEntry->Kusd.DeltaSystemTime +=
                    *(ULONG64 *)&KernelKuserSharedData->SystemTime - processEntry->Kusd.BeginSystemTime;
                processEntry->Kusd.DeltaLastSystemRITEventTickCount +=
                    KernelKuserSharedData->LastSystemRITEventTickCount -
                    processEntry->Kusd.BeginLastSystemRITEventTickCount;
                processEntry->Kusd.DeltaTickCount +=
                    *(ULONG64 *)&KernelKuserSharedData->TickCount - processEntry->Kusd.BeginTickCount;
                processEntry->Kusd.DeltaTimeUpdateLock +=
                    KernelKuserSharedData->TimeUpdateLock - processEntry->Kusd.BeginTimeUpdateLock;
                processEntry->Kusd.DeltaBaselineSystemQpc +=
                    KernelKuserSharedData->BaselineSystemTimeQpc - processEntry->Kusd.BeginBaselineSystemQpc;

                RtlZeroMemory(&processEntry->Kusd.BeginInterruptTime, sizeof(ULONG64) * 5 + 4);
            }

            return false;
        });

        rules::g_processResource.Unlock();
    }
}

NTSTATUS ModifyCounterForProcess(_In_ PEPROCESS process, _In_ BOOLEAN value)
{
    PAGED_CODE();
    NT_ASSERT(g_initialized);
    NT_ASSERT(process);

    NTSTATUS status = STATUS_NOT_CAPABLE;

    if (g_processResource.LockExclusive())
    {
        if (EnumProcessesUnsafe([&](PPROCESS_ENTRY processEntry) -> bool {
                if (processEntry->Process == process)
                {
                    processEntry->Flags.ProcessPaused = value;

                    return true;
                }
                return false;
            }))
        {
            status = STATUS_SUCCESS;
        }

        g_processResource.Unlock();
    }

    return status;
}

PTHREAD_ENTRY PROCESS_ENTRY::AppendThreadList(_In_ PETHREAD thread)
{
    const NTSTATUS status = ThreadsResource.LockExclusive();
    if (!NT_SUCCESS(status))
    {
        return nullptr;
    }

    SCOPE_EXIT
    {
        ThreadsResource.Unlock();
    };

    // First search thread in list
    //
    PLIST_ENTRY listEntry = Threads.ListEntry.Flink;
    PTHREAD_ENTRY threadEntry = nullptr;

    while (listEntry != &Threads.ListEntry)
    {
        threadEntry = CONTAINING_RECORD(listEntry, THREAD_ENTRY, ListEntry);
        listEntry = listEntry->Flink;

        if (threadEntry->Thread == thread)
        {
            return threadEntry;
        }
    }

    // If not found then proceed to insert to list
    //
    threadEntry = tools::AllocatePoolZero<PTHREAD_ENTRY>(NonPagedPool, sizeof(THREAD_ENTRY), tags::TAG_THREAD_ENTRY);
    if (!threadEntry)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate thread entry!");
        return nullptr;
    }

    ObReferenceObject(thread);
    threadEntry->Thread = thread;

    InsertTailList(&Threads.ListEntry, &threadEntry->ListEntry);

    return threadEntry;
}

} // namespace rules

namespace process
{
bool ClearHeapFlags(PEPROCESS process)
{
    PPEB Peb = (PPEB)PsGetProcessPeb(process);
    PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(process);

    KAPC_STATE apcState{};

    // https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/heap-flags/
    // In all versions of Windows, the value of the Flags
    // field is normally set to HEAP_GROWABLE(2),
    // and the ForceFlags field is normally set to 0

    // 32-bit process.Both of these default values depend on the[subsystem] of its host process
    if (Peb32)
    {
        __try
        {
            KeStackAttachProcess(process, &apcState);

            for (size_t i = 0; i < Peb32->NumberOfHeaps; i++)
            {
                ULONG Heap = *(ULONG *)(Peb32->ProcessHeaps + 4 * i);

                // Heap Flags
                *(ULONG *)(Heap + 0x40) &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED |
                                             HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED);

                // Heap Force Flags
                *(ULONG *)(Heap + 0x44) &=
                    ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED);
            }
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }
    if (Peb != NULL)
    {
        __try
        {
            KeStackAttachProcess(process, &apcState);

            for (size_t i = 0; i < Peb->NumberOfHeaps; i++)
            {
                PHEAP Heap = (PHEAP)Peb->ProcessHeaps[i];
                Heap->Flags &= ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS |
                                 HEAP_VALIDATE_PARAMETERS_ENABLED);
                Heap->ForceFlags &=
                    ~(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED);
            }
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }
    else
    {
        return false;
    }
    return true;
}

bool SetPebDeuggerFlag(PEPROCESS process, BOOLEAN value)
{
    PPEB Peb = PsGetProcessPeb(process);
    PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(process);

    KAPC_STATE apcState{};

    if (Peb32)
    {
        __try
        {
            KeStackAttachProcess(process, &apcState);
            Peb32->BeingDebugged = value;
            Peb->BeingDebugged = value;
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }
    else if (Peb)
    {
        __try
        {
            KeStackAttachProcess(process, &apcState);
            Peb->BeingDebugged = value;
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }
    else
    {
        return false;
    }
    return true;
}

bool ClearPebNtGlobalFlag(PEPROCESS process)
{
    PPEB Peb = PsGetProcessPeb(process);
    PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(process);

    KAPC_STATE apcState{};

    if (Peb32)
    {
        __try
        {
            KeStackAttachProcess(process, &apcState);
            Peb32->NtGlobalFlag &= ~0x70;
            Peb->NtGlobalFlag &= ~0x70;
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }
    else if (Peb)
    {
        __try
        {
            KeStackAttachProcess(process, &apcState);
            Peb->NtGlobalFlag &= ~0x70;
        }
        __finally
        {
            KeUnstackDetachProcess(&apcState);
        }
    }
    else
    {
        return false;
    }
    return true;
}

bool ClearBypassProcessFreezeFlag(_In_ rules::PPROCESS_ENTRY processEntry)
{
    NTSTATUS status;

    if (KERNEL_BUILD < WINDOWS_10_VERSION_19H1)
    {
        return true;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = nullptr;

    status = tools::QuerySystemInformation(SystemProcessInformation, reinterpret_cast<PVOID *>(&processInfo));
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(processInfo);
    };

    for (PSYSTEM_PROCESS_INFORMATION entry = processInfo; entry->NextEntryOffset != NULL;
         entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)entry + entry->NextEntryOffset))
    {
        if (processEntry->ProcessId == entry->UniqueProcessId)
        {
            for (ULONG i = 0ul; i < entry->NumberOfThreads; i++)
            {
                PETHREAD thread = nullptr;
                if (NT_SUCCESS(PsLookupThreadByThreadId(entry->Threads[i].ClientId.UniqueThread, &thread)))
                {
                    *(ULONG *)((ULONG64)thread + dyn::DynCtx.Offsets.BypassProcessFreezeFlagOffset) &= ~(1 << 21);

                    ObDereferenceObject(thread);
                }
            }
            return true;
        }
    }
    return false;
}

bool ClearThreadHideFromDebuggerFlag(_In_ rules::PPROCESS_ENTRY processEntry)
{
    NTSTATUS status;

    PSYSTEM_PROCESS_INFORMATION processInfo = nullptr;

    status = tools::QuerySystemInformation(SystemProcessInformation, reinterpret_cast<PVOID *>(&processInfo));
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(processInfo);
    };

    for (PSYSTEM_PROCESS_INFORMATION entry = processInfo; entry->NextEntryOffset != NULL;
         entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)entry + entry->NextEntryOffset))
    {
        if (processEntry->ProcessId == entry->UniqueProcessId)
        {
            for (ULONG i = 0ul; i < entry->NumberOfThreads; i++)
            {
                PETHREAD thread = nullptr;
                if (NT_SUCCESS(PsLookupThreadByThreadId(entry->Threads[i].ClientId.UniqueThread, &thread)))
                {
                    if (*(ULONG *)((ULONG64)thread + dyn::DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset) & 0x4)
                    {
                        rules::PTHREAD_ENTRY threadEntry = processEntry->AppendThreadList(thread);
                        if (threadEntry)
                        {
                            threadEntry->Flags.IsThreadHidden = TRUE;
                        }

                        *(ULONG *)((ULONG64)thread + dyn::DynCtx.Offsets.ThreadHideFromDebuggerFlagOffset) &= ~0x4LU;
                    }
                    ObDereferenceObject(thread);
                }
            }
            return true;
        }
    }
    return false;
}

bool ClearProcessBreakOnTerminationFlag(_In_ rules::PPROCESS_ENTRY processEntry)
{
    HANDLE processHandle = nullptr;

    if (NT_SUCCESS(ObOpenObjectByPointer(processEntry->Process, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType,
                                         KernelMode, &processHandle)))
    {
        SCOPE_EXIT
        {
            ObCloseHandle(processHandle, KernelMode);
        };

        ULONG BreakOnTermination;
        if (NT_SUCCESS(ZwQueryInformationProcess(processHandle, ProcessBreakOnTermination, &BreakOnTermination,
                                                 sizeof(ULONG), NULL)))
        {
            processEntry->Flags.ValueProcessBreakOnTermination = BreakOnTermination & 1;
            BreakOnTermination = 0;

            if (NT_SUCCESS(ZwSetInformationProcess(processHandle, ProcessBreakOnTermination, &BreakOnTermination,
                                                   sizeof(ULONG))))
            {
                return true;
            }
        }
    }
    return false;
}

void SaveProcessDebugFlags(_In_ rules::PPROCESS_ENTRY processEntry)
{
    HANDLE processHandle = nullptr;

    if (NT_SUCCESS(ObOpenObjectByPointer(processEntry->Process, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType,
                                         KernelMode, &processHandle)))
    {
        SCOPE_EXIT
        {
            ObCloseHandle(processHandle, KernelMode);
        };

        ULONG DebugFlags;
        if (NT_SUCCESS(ZwQueryInformationProcess(processHandle, ProcessDebugFlags, &DebugFlags, sizeof(ULONG), NULL)) &&
            PsIsProcessBeingDebugged(processEntry->Process) == FALSE)
        {
            processEntry->Flags.ValueProcessDebugFlags = !DebugFlags;
        }
    }
}

void SaveProcessHandleTracing(_In_ rules::PPROCESS_ENTRY processEntry)
{
    HANDLE processHandle = nullptr;

    if (NT_SUCCESS(ObOpenObjectByPointer(processEntry->Process, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType,
                                         KernelMode, &processHandle)))
    {
        SCOPE_EXIT
        {
            ObCloseHandle(processHandle, KernelMode);
        };

        ULONG64 ProcessInformationBuffer[2] = {0};

        NTSTATUS Status =
            ZwQueryInformationProcess(processHandle, ProcessHandleTracing, &ProcessInformationBuffer[0], 16, NULL);
        if (Status == STATUS_SUCCESS)
        {
            processEntry->Flags.ProcessHandleTracingEnabled = 1;
        }
        else if (Status == STATUS_INVALID_PARAMETER)
        {
            processEntry->Flags.ProcessHandleTracingEnabled = 0;
        }
    }
}

bool ClearThreadBreakOnTerminationFlags(_In_ rules::PPROCESS_ENTRY processEntry)
{
    NTSTATUS status;
    PSYSTEM_PROCESS_INFORMATION processInfo = nullptr;

    status = tools::QuerySystemInformation(SystemProcessInformation, reinterpret_cast<PVOID *>(&processInfo));
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return false;
    }

    SCOPE_EXIT
    {
        ExFreePool(processInfo);
    };

    for (PSYSTEM_PROCESS_INFORMATION entry = processInfo; entry->NextEntryOffset != NULL;
         entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)entry + entry->NextEntryOffset))
    {
        if (processEntry->ProcessId == entry->UniqueProcessId)
        {
            for (size_t i = 0; i < entry->NumberOfThreads; i++)
            {
                PETHREAD thread;
                if (NT_SUCCESS(PsLookupThreadByThreadId(entry->Threads[i].ClientId.UniqueThread, &thread)))
                {
                    SCOPE_EXIT
                    {
                        ObDereferenceObject(thread);
                    };

                    if (*(ULONG *)((ULONG64)thread + dyn::DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset) & 0x20)
                    {
                        rules::PTHREAD_ENTRY threadEntry = processEntry->AppendThreadList(thread);
                        if (threadEntry)
                        {
                            threadEntry->Flags.BreakOnTermination = TRUE;
                            *(ULONG *)((ULONG64)thread + dyn::DynCtx.Offsets.ThreadBreakOnTerminationFlagOffset) &=
                                ~0x20;

                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

static ULONG_PTR IpiFlushTbCallback(ULONG_PTR argument)
{
    UNREFERENCED_PARAMETER(argument);

    KeFlushCurrentTbImmediately();

    return 0;
};

void HookKuserSharedData(_In_ rules::PPROCESS_ENTRY processEntry)
{
    PAGED_CODE();
    NT_ASSERT(processEntry);

    PHYSICAL_ADDRESS PhysicalMax;
    PhysicalMax.QuadPart = ~0ULL;

    PVOID NewKuserSharedData = MmAllocateContiguousMemory(sizeof(KUSER_SHARED_DATA), PhysicalMax);
    if (!NewKuserSharedData)
    {
        return;
    }

    ULONG64 PfnNewKuserSharedData = MmGetPhysicalAddress(NewKuserSharedData).QuadPart >> PAGE_SHIFT;

    KAPC_STATE apcState{};
    KeStackAttachProcess(processEntry->Process, &apcState);
    {
        PMMPFN FakeKUSDMmpfn = (PMMPFN)(MmPfnDatabase + PfnNewKuserSharedData);

        FakeKUSDMmpfn->u4.EntireField |= 0x200000000000000;

        RtlCopyMemory(NewKuserSharedData, (PVOID)KUSER_SHARED_DATA_USERMODE, sizeof(KUSER_SHARED_DATA));

        processEntry->Kusd.PteKuserSharedData = MiGetPteAddress((PVOID)KUSER_SHARED_DATA_USERMODE);
        processEntry->Kusd.OriginalKuserSharedDataPfn = processEntry->Kusd.PteKuserSharedData->u.Hard.PageFrameNumber;
        processEntry->Kusd.PteKuserSharedData->u.Hard.PageFrameNumber = PfnNewKuserSharedData;
        processEntry->Kusd.KuserSharedData = (PKUSER_SHARED_DATA)NewKuserSharedData;

        // issue IPI to flush tb on all cores
        //
        KeIpiGenericCall(IpiFlushTbCallback, NULL);
        KeInvalidateAllCaches();

        KeUnstackDetachProcess(&apcState);
    }
}

void UnHookKuserSharedData(rules::PPROCESS_ENTRY processEntry)
{
    PAGED_CODE();
    NT_ASSERT(processEntry);

    ClearFlag(processEntry->PolicyFlags, rules::ProcessPolicyFlagHideKUserSharedData);

    KAPC_STATE apcState{};
    KeStackAttachProcess(processEntry->Process, &apcState);
    {
        PMMPFN FakeKUSDMmpfn = (PMMPFN)(MmPfnDatabase + processEntry->Kusd.PteKuserSharedData->u.Hard.PageFrameNumber);
        FakeKUSDMmpfn->u4.EntireField &= ~0x200000000000000;

        MmFreeContiguousMemory(processEntry->Kusd.KuserSharedData);

        processEntry->Kusd.KuserSharedData = NULL;
        processEntry->Kusd.PteKuserSharedData->u.Hard.PageFrameNumber = processEntry->Kusd.OriginalKuserSharedDataPfn;

        // issue IPI to flush tb on all cores
        //
        KeIpiGenericCall(IpiFlushTbCallback, NULL);
        KeInvalidateAllCaches();

        KeUnstackDetachProcess(&apcState);
    }
}

} // namespace process
} // namespace masterhide