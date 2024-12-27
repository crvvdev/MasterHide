#include "includes.hpp"

UNICODE_STRING g_deviceName = RTL_CONSTANT_STRING(L"\\Device\\" MASTERHIDE_GUID);
UNICODE_STRING g_symbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\" MASTERHIDE_GUID);
PDEVICE_OBJECT g_deviceObject = nullptr;

static void OnDriverUnload()
{
    // (1) De-initialize hooks
    //
    hooks::Deinitialize();

    // (2) De-initialize tables and lists
    //
    syscalls::Deinitialize();
    callbacks::Deinitialize();
    process::rules::Deinitialize();
    process::Deinitialize();

    // (3) Delete driver device
    //
    if (g_deviceObject)
    {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
    }

    IoDeleteSymbolicLink(&g_symbolicLinkName);

    WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "MasterHide successfully unloaded!");
}

void DriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "MasterHide is unloading");

    OnDriverUnload();
    WPP_CLEANUP(driverObject);
}

static NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
    const ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS status = STATUS_SUCCESS;

    __try
    {
        switch (controlCode)
        {
        case IOCTL_MASTERHIDE_ADD_RULE: {

            auto processRule = static_cast<PPROCESS_RULE>(irp->AssociatedIrp.SystemBuffer);

            if (processRule->UseProcessId)
            {
                if (!NT_SUCCESS(
                        process::AddProcessEntry(UlongToHandle(processRule->ProcessId), processRule->PolicyFlags)))
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to add process entry");
                    status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Successfully created rule for pid %u",
                                  processRule->ProcessId);
                }
            }
            else
            {
                if (!NT_SUCCESS(
                        process::rules::AddProcessRuleEntry(&processRule->ImageFileName, processRule->PolicyFlags)))
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to add process rule entry");
                    status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Successfully created rule for image %wZ",
                                  &processRule->ImageFileName);
                }
            }

            break;
        }
        case IOCTL_MASTERHIDE_UPDATE_RULE: {

            auto processRule = static_cast<PPROCESS_RULE>(irp->AssociatedIrp.SystemBuffer);

            if (processRule->UseProcessId)
            {
                if (!NT_SUCCESS(
                        process::UpdateProcessEntry(UlongToHandle(processRule->ProcessId), processRule->PolicyFlags)))
                {
                    status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Successfully update rule for pid %u",
                                  processRule->ProcessId);
                }
            }
            else
            {
                if (!NT_SUCCESS(
                        process::rules::UpdateProcessRuleEntry(&processRule->ImageFileName, processRule->PolicyFlags)))
                {
                    status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Successfully update rule for image %wZ",
                                  &processRule->ImageFileName);
                }
            }

            break;
        }
        case IOCTL_MASTERHIDE_REMOVE_RULE: {

            auto processRule = static_cast<PPROCESS_RULE>(irp->AssociatedIrp.SystemBuffer);

            if (processRule->UseProcessId)
            {
                if (!NT_SUCCESS(process::RemoveProcessEntry(UlongToHandle(processRule->ProcessId))))
                {
                    status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Successfully removed rule for pid %u",
                                  processRule->ProcessId);
                }
            }
            else
            {
                if (!NT_SUCCESS(process::rules::RemoveProcessRuleEntry(&processRule->ImageFileName)))
                {
                    status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Successfully removed rule for image %wZ",
                                  &processRule->ImageFileName);
                }
            }

            break;
        }
        case IOCTL_MASTERHIDE_PROCESS_RESUME: {

            auto processId = static_cast<PULONG>(irp->AssociatedIrp.SystemBuffer);

            PEPROCESS process = nullptr;
            if (NT_SUCCESS(PsLookupProcessByProcessId(UlongToHandle(*processId), &process)))
            {
                process::UpdateDelta(process);

                if (process::ResumeCounterForProcess(process) == FALSE)
                {
                    status = STATUS_UNSUCCESSFUL;
                }

                ObDereferenceObject(process);
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        case IOCTL_MASTERHIDE_PROCESS_STOP: {

            auto processId = static_cast<PULONG>(irp->AssociatedIrp.SystemBuffer);

            PEPROCESS process = nullptr;
            if (NT_SUCCESS(PsLookupProcessByProcessId(UlongToHandle(*processId), &process)))
            {
                process::GetBegin(process);

                if (process::StopCounterForProcess(process) == FALSE)
                {
                    status = STATUS_UNSUCCESSFUL;
                }

                ObDereferenceObject(process);
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Unrecognized IOCTL request 0x%08X", status);
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Exception in dispatch handler %!STATUS!", status);
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static ULONG QueryHookType(_In_ PUNICODE_STRING registryPath)
{
    PAGED_CODE();
    NT_ASSERT(registryPath);

    ULONG hookType = HookTypeInfinityHook;

    NTSTATUS status;

    UNICODE_STRING registryPathParameters{};
    registryPathParameters.Length = 0;
    registryPathParameters.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH;
    registryPathParameters.Buffer = tools::AllocatePoolZero<PWCH>(
        NonPagedPool, registryPathParameters.MaximumLength * sizeof(WCHAR), tags::TAG_STRING);
    if (!registryPathParameters.Buffer)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for registry path");
        return hookType;
    }

    SCOPE_EXIT
    {
        RtlFreeUnicodeString(&registryPathParameters);
    };

    RtlCopyUnicodeString(&registryPathParameters, registryPath);

    status = RtlAppendUnicodeToString(&registryPathParameters, L"\\Parameters");
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "RtlAppendUnicodeToString returned %!STATUS!", status);
        return hookType;
    }

    RTL_QUERY_REGISTRY_TABLE query[2]{};
    query[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    query[0].Name = (PWSTR)L"HookType";
    query[0].EntryContext = &hookType;
    query[0].DefaultType = REG_DWORD;
    query[0].DefaultData = &hookType;
    query[0].DefaultLength = sizeof(ULONG);

    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, registryPathParameters.Buffer, query, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "RtlQueryRegistryValues returned %!STATUS!", status);
    }

    return hookType;
}

extern "C" NTSTATUS NTAPI DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS winlogon = nullptr;

    WPP_INIT_TRACING(driverObject, registryPath);
    WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "MasterHide driver is loading");

    DBGPRINT("RegistryPath %wZ", registryPath);

    // (1) Setup driver object
    //
    status = IoCreateDevice(driverObject, 0, &g_deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                            &g_deviceObject);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "IoCreateDevice returned %!STATUS!", status);
        goto Exit;
    }

    status = IoCreateSymbolicLink(&g_symbolicLinkName, &g_deviceName);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "IoCreateSymbolicLink returned %!STATUS!", status);
        goto Exit;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    driverObject->DriverUnload = &DriverUnload;
    driverObject->Flags |= DO_BUFFERED_IO;

    // Query the type of hook that should be used
    //
    MASTERHIDE_HOOK_TYPE = QueryHookType(registryPath);

    if (MASTERHIDE_HOOK_TYPE <= HookTypeInvalid || MASTERHIDE_HOOK_TYPE >= HookTypeMax)
    {
        MASTERHIDE_HOOK_TYPE = HookTypeInfinityHook;

        WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL,
                      "Hook type was not set or invalid, defaulting to infinityhook.");
    }

    // (2) Attach to Win32K process memory space
    //
    winlogon = tools::GetProcessByName(L"winlogon.exe");
    if (!winlogon)
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "winlogon.exe not found!");
        goto Exit;
    }

    KeAttachProcess(winlogon);

#define INITIALIZE_INTERFACE(name)                                                                                     \
    status = name::Initialize();                                                                                       \
    if (!NT_SUCCESS(status))                                                                                           \
    {                                                                                                                  \
        DBGPRINT(#name " initialize returned 0x%08X", status);                                                         \
        goto Exit;                                                                                                     \
    }

    // (3) Initialize all interfaces
    //
    INITIALIZE_INTERFACE(dyn);
    INITIALIZE_INTERFACE(process);
    INITIALIZE_INTERFACE(process::rules);
    INITIALIZE_INTERFACE(callbacks);
    INITIALIZE_INTERFACE(syscalls);
    INITIALIZE_INTERFACE(hooks);

#undef INITIALIZE_INTERFACE

    WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "MasterHide successfully loaded!");

Exit:
    if (winlogon)
    {
        KeDetachProcess();
        ObDereferenceObject(winlogon);
    }

    if (!NT_SUCCESS(status))
    {
        OnDriverUnload();
        WPP_CLEANUP(driverObject);

        status = STATUS_FAILED_DRIVER_ENTRY;
    }

    return status;
}