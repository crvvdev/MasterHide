#include "includes.hpp"

namespace masterhide
{
namespace hooks
{
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

volatile LONG g_refCount = 0;

void WaitForHooksCompletion()
{
    DBGPRINT("%d ref counts", g_refCount);

    while (InterlockedCompareExchange(&g_refCount, 0, 0) != 0)
    {
        DBGPRINT("%d references left", g_refCount);
        YieldProcessor();
    }
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

    const PEPROCESS currentProcess = PsGetCurrentProcess();

    __try
    {
        process::PPROCESS_ENTRY processEntry = process::GetBlacklistedProcess(currentProcess);

        SCOPE_EXIT
        {
            if (processEntry)
            {
                process::DereferenceObject(processEntry);
                processEntry = nullptr;
            }
        };

        // If (1) it's a blacklisted process and (2) current hook is meant to be intercepted
        //
        if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, process::ProcessPolicyFlagNtOpenProcess))
        {
            // Then (3) proceed to block opening any protected process
            //
            if (process::IsProtectedProcess(ClientId->UniqueProcess))
            {
                DBGPRINT("Denying access from PID %d to PID %d\n", PsGetCurrentProcessId(), ClientId->UniqueProcess);

                return STATUS_ACCESS_VIOLATION;
            }
        }
        // If (1) it's a monitored process then WIP
        //
        else if (process::IsMonitoredProcess(currentProcess))
        {
            // TODO: implement
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // ADD verbose log
    }
    return oNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI hkNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                        PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    process::PPROCESS_ENTRY processEntry = process::GetBlacklistedProcess(PsGetCurrentProcessId());

    SCOPE_EXIT
    {
        if (processEntry)
        {
            process::DereferenceObject(processEntry);
            processEntry = nullptr;
        }
    };

    if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, process::ProcessPolicyFlagNtSetInformationThread))
    {
        if (ThreadInformationClass == ThreadHideFromDebugger && ThreadInformationLength == 0)
        {
            // Prevent any threads from the process to be hidden from debugger.
            if (ThreadHandle == ZwCurrentThread() ||
                tools::GetProcessIdFromThreadHandle(ThreadHandle) == PsGetCurrentProcessId())
            {
                return STATUS_SUCCESS;
            }
        }
    }
    return oNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI hkNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                           PVOID ProcessInformation, ULONG ProcessInformationLength,
                                           PULONG ReturnLength)
{
    NTSTATUS Status;

    const HANDLE currentProcessId = PsGetCurrentProcessId();

    process::PPROCESS_ENTRY processEntry = process::GetBlacklistedProcess(currentProcessId);

    SCOPE_EXIT
    {
        if (processEntry)
        {
            process::DereferenceObject(processEntry);
            processEntry = nullptr;
        }
    };

    // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
    //
    if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, process::ProcessPolicyFlagNtQueryInformationProcess))
    {
        // (3) proceed to perform anti-anti-debug
        //
        __try
        {
            if (ProcessInformationClass == ProcessDebugObjectHandle && // Handle ProcessDebugObjectHandle early
                ProcessInformation != nullptr && ProcessInformationLength == sizeof(HANDLE) &&
                (ProcessHandle == ZwCurrentProcess() ||
                 currentProcessId == tools::GetProcessIdFromProcessHandle(ProcessHandle)))
            {

                // Verify (1) that the handle has PROCESS_QUERY_INFORMATION access, and (2) that writing
                // to ProcessInformation and/or ReturnLength does not cause any access or alignment violations
                Status = oNtQueryInformationProcess(ProcessHandle,
                                                    ProcessDebugPort, // Note: not ProcessDebugObjectHandle
                                                    ProcessInformation, sizeof(HANDLE), ReturnLength);
                if (!NT_SUCCESS(Status))
                {
                    return Status;
                }

                // The kernel calls DbgkOpenProcessDebugPort here
                if (ReturnLength != nullptr)
                {
                    ProbeForWrite(ReturnLength, sizeof(*ReturnLength), 1);
                }

                ProbeForWrite(ProcessInformation, ProcessInformationLength, 1);

                *(PHANDLE)ProcessInformation = nullptr;

                if (ReturnLength != nullptr)
                {
                    *ReturnLength = sizeof(HANDLE);
                }

                return STATUS_PORT_NOT_SET;
            }

            if ((ProcessInformationClass == ProcessDebugFlags || ProcessInformationClass == ProcessDebugPort ||
                 ProcessInformationClass == ProcessBasicInformation ||
                 ProcessInformationClass == ProcessBreakOnTermination ||
                 ProcessInformationClass == ProcessHandleTracing || ProcessInformationClass == ProcessIoCounters) &&
                (ProcessHandle == ZwCurrentProcess() ||
                 currentProcessId == tools::GetProcessIdFromProcessHandle(ProcessHandle)))
            {
                Status = oNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                                    ProcessInformationLength, ReturnLength);

                if (NT_SUCCESS(Status) && ProcessInformation != nullptr && ProcessInformationLength != 0)
                {
                    // Probe usermode buffer
                    ProbeForWrite(ProcessInformation, ProcessInformationLength, 1);

                    if (ProcessInformationClass == ProcessDebugFlags)
                    {
                        BACKUP_RETURNLENGTH();

                        *((ULONG *)ProcessInformation) =
                            ((processEntry->Flags.ValueProcessDebugFlags & PROCESS_NO_DEBUG_INHERIT) != 0)
                                ? 0
                                : PROCESS_DEBUG_INHERIT;

                        RESTORE_RETURNLENGTH();
                    }
                    else if (ProcessInformationClass == ProcessDebugPort)
                    {
                        BACKUP_RETURNLENGTH();

                        *((HANDLE *)ProcessInformation) = nullptr;

                        RESTORE_RETURNLENGTH();
                    }
                    else if (ProcessInformationClass == ProcessBasicInformation) // Fake parent
                    {
                        BACKUP_RETURNLENGTH();

                        PEPROCESS process = tools::GetProcessByName(processEntry->FakeParentProcessName);
                        if (process)
                        {
                            ((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId =
                                HandleToUlong(PsGetProcessId(process));

                            ObDereferenceObject(process);
                        }

                        RESTORE_RETURNLENGTH();
                    }
                    else if (ProcessInformationClass == ProcessBreakOnTermination)
                    {
                        BACKUP_RETURNLENGTH();

                        *((ULONG *)ProcessInformation) = processEntry->Flags.ValueProcessBreakOnTermination;

                        RESTORE_RETURNLENGTH();
                    }
                    else if (ProcessInformationClass == ProcessHandleTracing)
                    {
                        BACKUP_RETURNLENGTH();
                        RESTORE_RETURNLENGTH(); // Trigger any possible exceptions caused by messing with the output
                                                // buffer before changing the final return status

                        Status =
                            processEntry->Flags.ProcessHandleTracingEnabled ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
                    }
                    else if (ProcessInformationClass == ProcessIoCounters)
                    {
                        BACKUP_RETURNLENGTH();

                        ((PIO_COUNTERS)ProcessInformation)->OtherOperationCount = 1;

                        RESTORE_RETURNLENGTH();
                    }
                }

                return Status;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINT("Exception handled 0x%08X", GetExceptionCode());
            return GetExceptionCode();
        }
    }
    return oNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                      ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI hkNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                         PVOID ProcessInformation, ULONG ProcessInformationLength)
{
    const HANDLE currentProcessId = PsGetCurrentProcessId();

    process::PPROCESS_ENTRY processEntry = process::GetBlacklistedProcess(currentProcessId);

    SCOPE_EXIT
    {
        if (processEntry)
        {
            process::DereferenceObject(processEntry);
            processEntry = nullptr;
        }
    };

    // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
    //
    if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, process::ProcessPolicyFlagNtSetInformationProcess))
    {
        // (3) proceed to perform anti-anti-debug
        //
        __try
        {
            if (ProcessHandle == ZwCurrentProcess() ||
                currentProcessId == tools::GetProcessIdFromProcessHandle(ProcessHandle))
            {
                if (ProcessInformationClass == ProcessBreakOnTermination)
                {
                    if (ProcessInformationLength != sizeof(ULONG))
                    {
                        return STATUS_INFO_LENGTH_MISMATCH;
                    }

                    // NtSetInformationProcess will happily dereference this pointer
                    if (ProcessInformation == NULL)
                    {
                        return STATUS_ACCESS_VIOLATION;
                    }

                    // A process must have debug privileges enabled to set the ProcessBreakOnTermination flag
                    if (!tools::HasDebugPrivilege())
                    {
                        return STATUS_PRIVILEGE_NOT_HELD;
                    }

                    ProbeForWrite(ProcessInformation, ProcessInformationLength, 1);
                    processEntry->Flags.ValueProcessBreakOnTermination = *((ULONG *)ProcessInformation);

                    return STATUS_SUCCESS;
                }

                // Don't allow changing the debug inherit flag, and keep track of the new value to report in NtQIP
                if (ProcessInformationClass == ProcessDebugFlags)
                {
                    if (ProcessInformationLength != sizeof(ULONG))
                    {
                        return STATUS_INFO_LENGTH_MISMATCH;
                    }

                    if (ProcessInformation == NULL)
                    {
                        return STATUS_ACCESS_VIOLATION;
                    }

                    ProbeForWrite(ProcessInformation, ProcessInformationLength, 1);

                    ULONG Flags = *(ULONG *)ProcessInformation;

                    if ((Flags & ~PROCESS_DEBUG_INHERIT) != 0)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
                    {
                        processEntry->Flags.ValueProcessDebugFlags &= ~PROCESS_NO_DEBUG_INHERIT;
                    }
                    else
                    {
                        processEntry->Flags.ValueProcessDebugFlags |= PROCESS_NO_DEBUG_INHERIT;
                    }

                    return STATUS_SUCCESS;
                }

                // PROCESS_HANDLE_TRACING_ENABLE -> ULONG, PROCESS_HANDLE_TRACING_ENABLE_EX -> ULONG,ULONG
                if (ProcessInformationClass == ProcessHandleTracing)
                {
                    bool enable =
                        ProcessInformationLength != 0; // A length of 0 is valid and indicates we should disable tracing
                    if (enable)
                    {
                        if (ProcessInformationLength != sizeof(ULONG) &&
                            ProcessInformationLength != (sizeof(ULONG) * 2))
                        {
                            return STATUS_INFO_LENGTH_MISMATCH;
                        }

                        // NtSetInformationProcess will happily dereference this pointer
                        if (ProcessInformation == NULL)
                        {
                            return STATUS_ACCESS_VIOLATION;
                        }

                        ProbeForRead(ProcessInformation, ProcessInformationLength, 1);

                        PPROCESS_HANDLE_TRACING_ENABLE_EX phtEx = (PPROCESS_HANDLE_TRACING_ENABLE_EX)ProcessInformation;
                        if (phtEx->Flags != 0)
                        {
                            return STATUS_INVALID_PARAMETER;
                        }
                    }

                    processEntry->Flags.ProcessHandleTracingEnabled = enable;
                    return STATUS_SUCCESS;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINT("Exception handled 0x%08X", GetExceptionCode());
            return GetExceptionCode();
        }
    }
    return oNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                    ProcessInformationLength);
}

NTSTATUS NTAPI hkNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation,
                               ULONG ObjectInformationLength, PULONG ReturnLength)
{
    const NTSTATUS status =
        oNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    const HANDLE currentProcessId = PsGetCurrentProcessId();

    process::PPROCESS_ENTRY processEntry = process::GetBlacklistedProcess(currentProcessId);

    SCOPE_EXIT
    {
        if (processEntry)
        {
            process::DereferenceObject(processEntry);
            processEntry = nullptr;
        }
    };

    // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
    //
    if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, process::ProcessPolicyFlagNtQueryObject))
    {
        // (3) proceed to perform anti-anti-debug
        //
        __try
        {
            if ((ObjectInformationClass == ObjectTypesInformation || ObjectInformationClass == ObjectTypeInformation) &&
                (NT_SUCCESS(status) && ObjectInformation))
            {
                // Probe usermode buffer
                ProbeForWrite(ObjectInformation, ObjectInformationLength, 1);

                if (ObjectInformationClass == ObjectTypesInformation)
                {
                    BACKUP_RETURNLENGTH();

                    FilterObjects((POBJECT_TYPES_INFORMATION)ObjectInformation);

                    RESTORE_RETURNLENGTH();
                }
                else if (ObjectInformationClass == ObjectTypeInformation)
                {
                    BACKUP_RETURNLENGTH();

                    FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation, false);

                    RESTORE_RETURNLENGTH();
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINT("Exception handled 0x%08X", GetExceptionCode());
            return GetExceptionCode();
        }
    }
    return status;
}

NTSTATUS NTAPI hkNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    const HANDLE currentProcessId = PsGetCurrentProcessId();

    process::PPROCESS_ENTRY processEntry = process::GetBlacklistedProcess(currentProcessId);

    SCOPE_EXIT
    {
        if (processEntry)
        {
            process::DereferenceObject(processEntry);
            processEntry = nullptr;
        }
    };

    // (1) check if the process is blacklisted (2) check if hook is meant to be intercepted
    //
    if (processEntry && BooleanFlagOn(processEntry->PolicyFlags, process::ProcessPolicyFlagNtGetContextThread))
    {
        // (3) proceed to perform anti-anti-debug
        //
        DWORD ContextBackup = 0;
        BOOLEAN DebugRegistersRequested = FALSE;

        if (ThreadHandle == ZwCurrentThread() || currentProcessId == tools::GetProcessIdFromThreadHandle(ThreadHandle))
        {
            if (ThreadContext)
            {
                ContextBackup = ThreadContext->ContextFlags;
                ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
                DebugRegistersRequested = ThreadContext->ContextFlags != ContextBackup;
            }
        }

        NTSTATUS status = oNtGetContextThread(ThreadHandle, ThreadContext);

        if (ContextBackup)
        {
            ThreadContext->ContextFlags = ContextBackup;
            if (DebugRegistersRequested)
            {
                ThreadContext->Dr0 = 0;
                ThreadContext->Dr1 = 0;
                ThreadContext->Dr2 = 0;
                ThreadContext->Dr3 = 0;
                ThreadContext->Dr6 = 0;
                ThreadContext->Dr7 = 0;
#ifdef _WIN64
                ThreadContext->LastBranchToRip = 0;
                ThreadContext->LastBranchFromRip = 0;
                ThreadContext->LastExceptionToRip = 0;
                ThreadContext->LastExceptionFromRip = 0;
#endif
            }
        }

        return status;
    }
    return oNtGetContextThread(ThreadHandle, ThreadContext);
}

NTSTATUS NTAPI hkNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    DWORD ContextBackup = 0;
    if (ThreadHandle == ZwCurrentThread() ||
        PsGetCurrentProcessId() == tools::GetProcessIdFromThreadHandle(ThreadHandle)) // thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        }
    }

    NTSTATUS ntStat = oNtSetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
    }

    return ntStat;
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

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    if (!process::IsBlacklistedProcess(currentProcess))
    {
        // Process is not meant to be monitored.
        return oNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }

    const NTSTATUS status =
        oNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    if (NT_SUCCESS(status))
    {
        PEPROCESS Process = nullptr;
        auto ret = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&Process,
                                             nullptr);
        if (!NT_SUCCESS(ret))
        {
            return status;
        }

        if (process::IsMonitoredProcess(Process))
        {
            // TODO: implement
        }

        ObDereferenceObject(Process);
    }
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

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    if (!process::IsBlacklistedProcess(currentProcess))
    {
        // Process is not meant to be monitored.
        return oNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }

    const NTSTATUS status =
        oNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    if (NT_SUCCESS(status) && BaseAddress && RegionSize && *RegionSize >= 0x1000)
    {
        //
        // Get Name from handle
        //
        PEPROCESS Process = nullptr;
        auto ret = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&Process,
                                             nullptr);
        if (!NT_SUCCESS(ret))
            return status;

        if (process::IsMonitoredProcess(Process))
        {
            // TODO: implement
        }

        ObDereferenceObject(Process);
    }
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

    const auto res = oNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);

    // TODO: move this check to a function
    if (process::IsBlacklistedProcess(PsGetCurrentProcessId()))
    {
        return res;
    }

    if (NT_SUCCESS(res) && BaseAddress && RegionSize && *RegionSize >= 0x1000)
    {
        //
        // Get Name from handle
        //
        PEPROCESS Process = nullptr;
        auto ret = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&Process,
                                             nullptr);
        if (!NT_SUCCESS(ret))
            return res;

        if (process::IsMonitoredProcess(Process))
        {
            // TODO: implement
        }

        ObDereferenceObject(Process);
    }
    return res;
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

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    const HANDLE currentPid = PsGetCurrentProcessId();

    //
    // perform actions in case it's a blacklisted process.
    //
    if (process::IsBlacklistedProcess(currentPid))
    {
        UNICODE_STRING processImageName{};
        if (!tools::GetProcessFileName(currentProcess, &processImageName))
        {
            DBGPRINT("Failed to get process %d file name\n", HandleToUlong(currentPid));
            goto Exit;
        }

        SCOPE_EXIT
        {
            RtlFreeUnicodeString(&processImageName);
        };

        // This is safe because GetProcessFileName gives us a null terminated string.
        LPWSTR moduleName = wcsrchr(processImageName.Buffer, '\\');

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
                                        DBGPRINT("[Process: %ls] [IOCTL_STORAGE_QUERY_PROPERTY] spoofing serial %s "
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
                                        DBGPRINT("[Process: %ls] [IOCTL_STORAGE_QUERY_PROPERTY] spoofing model %s "
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

                                    DBGPRINT("$ls Spoofing Model ( 0x%X ) Old: %s New: %s\n", moduleName, IoControlCode,
                                             Model, newModelNumber);

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
                DBGPRINT("Exception handled 0x%08X", GetExceptionCode());
                return GetExceptionCode();
            }
        }
    }
Exit:
    return status;
}

void FilterHandleInfo(PSYSTEM_HANDLE_INFORMATION pHandleInfo, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = pHandleInfo->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        if ((/*HookDllData.EnableProtectProcessId == TRUE &&*/
             process::IsProtectedProcess((HANDLE)pHandleInfo->Handles[i].UniqueProcessId)))
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
        if (/*(HookDllData.EnableProtectProcessId == TRUE &&*/
            process::IsProtectedProcess((HANDLE)pHandleInfoEx->Handles[i].UniqueProcessId))
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
        if (/*(HookDllData.EnableProtectProcessId == TRUE &&*/
            process::IsWhitelistedDriver((PCHAR)pModules->Modules[i].FullPathName))
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

void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    while (true)
    {
        if (pInfo->UniqueProcessId == PsGetCurrentProcessId())
        {
            PEPROCESS explorer = tools::GetProcessByName(L"explorer.exe");
            if (explorer)
            {
                // Fake parent process to explorer.exe
                pInfo->InheritedFromUniqueProcessId = PsGetProcessId(explorer);
                ObDereferenceObject(explorer);

                break;
            }
        }

        if (pInfo->NextEntryOffset == 0)
        {
            break;
        }

        pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
    }
}

void FakeCurrentOtherOperationCount(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    while (true)
    {
        if (pInfo->UniqueProcessId == PTEB(PsGetCurrentThreadTeb())->ClientId.UniqueProcess)
        {
            LARGE_INTEGER one;
            one.QuadPart = 1;
            pInfo->OtherOperationCount = one;
            break;
        }

        if (pInfo->NextEntryOffset == 0)
        {
            break;
        }

        pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
    }
}

void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

    while (TRUE)
    {
        if (/*HookDllData.EnableProtectProcessId == TRUE &&*/
            process::IsProtectedProcess(pInfo->UniqueProcessId))
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

NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length,
                                          PULONG ReturnLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const NTSTATUS status = oNtQuerySystemInformation(SystemInformationClass, Buffer, Length, ReturnLength);

    if (!process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        return status;
    }

    if (NT_SUCCESS(status))
    {
        __try
        {
            //
            // Hide from Driver list
            //
            if (SystemInformationClass == SystemModuleInformation)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterModuleInfoEx(PRTL_PROCESS_MODULES(Buffer), &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
                    TempReturnLength -= ReturnLengthAdjust;
                RESTORE_RETURNLENGTH();
            }
            //
            // Hide from Process list
            //
            else if (SystemInformationClass == SystemProcessInformation ||
                     SystemInformationClass == SystemSessionProcessInformation ||
                     SystemInformationClass == SystemExtendedProcessInformation)
            {
                BACKUP_RETURNLENGTH();

                PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
                if (SystemInformationClass == SystemSessionProcessInformation)
                    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PSYSTEM_SESSION_PROCESS_INFORMATION)Buffer)->Buffer;

                FilterProcess(ProcessInfo);
                FakeCurrentParentProcessId(ProcessInfo);
                FakeCurrentOtherOperationCount(ProcessInfo);

                RESTORE_RETURNLENGTH();
            }
            //
            // Hide from handle list
            //
            else if (SystemInformationClass == SystemHandleInformation)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterHandleInfo((PSYSTEM_HANDLE_INFORMATION)Buffer, &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
                    TempReturnLength -= ReturnLengthAdjust;
                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemExtendedHandleInformation)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterHandleInfoEx((PSYSTEM_HANDLE_INFORMATION_EX)Buffer, &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
                    TempReturnLength -= ReturnLengthAdjust;
                RESTORE_RETURNLENGTH();
            }
            //
            // Spoof code integrity status
            //
            else if (SystemInformationClass == SystemCodeIntegrityInformation)
            {
                auto systemInformation = PSYSTEM_CODEINTEGRITY_INFORMATION(Buffer);

                BACKUP_RETURNLENGTH();

                ULONG options = systemInformation->CodeIntegrityOptions;

                // fix flags
                options &= ~CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;
                options &= ~CODEINTEGRITY_OPTION_TESTSIGN;
                options |= CODEINTEGRITY_OPTION_ENABLED;

                systemInformation->CodeIntegrityOptions = options;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemCodeIntegrityUnlockInformation)
            {
                BACKUP_RETURNLENGTH();

                // The size of the buffer for this class changed from 4 to 36, but the output should still be all
                // zeroes
                RtlZeroMemory(Buffer, Length);

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
            {
                BACKUP_RETURNLENGTH();

                auto systemInformation = PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX(Buffer);

                systemInformation->DebuggerAllowed = FALSE;
                systemInformation->DebuggerEnabled = FALSE;
                systemInformation->DebuggerPresent = FALSE;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemKernelDebuggerFlags)
            {
                BACKUP_RETURNLENGTH();

                *(PUCHAR)Buffer = 0;

                RESTORE_RETURNLENGTH();
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBGPRINT("Exception handled 0x%08X", GetExceptionCode());
            return GetExceptionCode();
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

    if (DriverServiceName && DriverServiceName->Buffer)
    {
        static constexpr LPCWSTR g_driverBlockList[] = {L"fltmgr.sys"};

        LPCWSTR fileName = wcsrchr(DriverServiceName->Buffer, L'\\') + 1;

        for (auto name : g_driverBlockList)
        {
            if (!wcscmp(fileName, name))
            {
                DBGPRINT("Blocked driver %wZ from loading\n", DriverServiceName);
                return STATUS_UNSUCCESSFUL;
            }
        }
    }

    const NTSTATUS status = oNtLoadDriver(DriverServiceName);
    if (NT_SUCCESS(status))
    {
        DBGPRINT("Loading Driver: %wZ\n", DriverServiceName);
    }
    return status;
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
    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        const HANDLE processId = oNtUserQueryWindow(resultHwnd, WindowProcess);
        if (process::IsProtectedProcess(processId))
        {
            // Spoof the HWND result in case it's one of the protected processes.
            return NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
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

    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        const HANDLE processId = oNtUserQueryWindow(WindowHandle, WindowProcess);
        if (process::IsProtectedProcess(processId))
        {
            // Spoof the HWND result in case it's one of the protected processes.
            return 0;
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
    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        const HANDLE processId = oNtUserQueryWindow(resultHwnd, WindowProcess);
        if (process::IsProtectedProcess(processId))
        {
            // Spoof the HWND result in case it's one of the protected processes.
            return 0;
        }
    }
    return resultHwnd;
}

void FilterHwndList(HWND *phwndFirst, PULONG pcHwndNeeded)
{
    for (UINT i = 0; i < *pcHwndNeeded; i++)
    {
        HANDLE processId = oNtUserQueryWindow(phwndFirst[i], WindowProcess);

        if (phwndFirst[i] != nullptr && process::IsProtectedProcess(processId))
        {
            if (i == 0)
            {
                // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                {
                    processId = oNtUserQueryWindow(phwndFirst[j], WindowProcess);

                    if (phwndFirst[j] != nullptr && !process::IsProtectedProcess(processId))
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
    const NTSTATUS status =
        oNtUserBuildHwndList_Win7(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        if (NT_SUCCESS(status) && phwndFirst && pcHwndNeeded)
        {
            //
            // Erase protected window HWND from list
            //
            FilterHwndList(phwndFirst, pcHwndNeeded);
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

    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        if (NT_SUCCESS(status) && pWnd && pBufSize)
        {
            //
            // Erase protected window HWND from list
            //
            FilterHwndList(pWnd, pBufSize);
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

    const HWND result = oNtUserGetForegroundWindow();

    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        //
        // Hide protected process window from blacklisted process
        //
        const HANDLE processId = oNtUserQueryWindow(result, WindowProcess);

        static HWND lastHwnd = nullptr;

        if (process::IsProtectedProcess(processId))
        {
            return lastHwnd;
        }
        else
        {
            // store a copy of the last HWND
            lastHwnd = result;
        }
    }

    return result;
}
} // namespace hooks
} // namespace masterhide