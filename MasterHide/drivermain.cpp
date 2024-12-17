#include "includes.hpp"

#define MASTERHIDE_GUID L"{EDC00A52-CBB9-490E-89A3-69E3FFF137BA}"

static UNICODE_STRING g_deviceName = RTL_CONSTANT_STRING(L"\\Device\\" MASTERHIDE_GUID);
static UNICODE_STRING g_symbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\" MASTERHIDE_GUID);
static PDEVICE_OBJECT g_deviceObject = nullptr;

#define IOCTL_MASTERHIDE_ADD_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_REMOVE_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_UPDATE_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_PROCESS_RESUME CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MASTERHIDE_PROCESS_STOP CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

void Test()
{
    {
        UNICODE_STRING imageFileName =
            RTL_CONSTANT_STRING(L"\\??\\C:\\Users\\LAPTOP\\Desktop\\x64dbg\\release\\x64\\x64dbg.exe");

        if (!NT_SUCCESS(process::rules::AddProcessRuleEntry(&imageFileName, PROCESS_POLICY_PROTECTED)))
        {
            return;
        }

        WppTracePrint(TRACE_LEVEL_VERBOSE, DEBUG, "Created protected policy rule %wZ", &imageFileName);
    }
    /*{
        UNICODE_STRING imageFileName =
            RTL_CONSTANT_STRING(L"\\??\\C:\\Program Files\\Cheat Engine 7.5\\cheatengine-x86_64.exe");

        if (!NT_SUCCESS(process::rules::AddProcessRuleEntry(&imageFileName, PROCESS_POLICY_HIDE_FROM_DEBUGGER)))
        {
            return;
        }

        WppTracePrint(TRACE_LEVEL_VERBOSE, DEBUG, "Created hidden from debugger rule for %wZ", &imageFileName);
    }*/
    {
        UNICODE_STRING imageFileName =
            RTL_CONSTANT_STRING(L"\\??\\C:\\Users\\LAPTOP\\Desktop\\History Reborn 3.0\\Ragnarok.exe");

        if (!NT_SUCCESS(process::rules::AddProcessRuleEntry(&imageFileName, PROCESS_POLICY_HIDE_FROM_DEBUGGER |
                                                                                PROCESS_POLICY_FLAG_MONITORED)))
        {
            return;
        }

        WppTracePrint(TRACE_LEVEL_VERBOSE, DEBUG, "Created hidden from debugger rule for %wZ", &imageFileName);
    }
    //
}

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

typedef struct _PROCESS_RULE
{
    UNICODE_STRING ImageFileName;
    ULONG ProcessId;
    BOOLEAN UseProcessId;
    LONG64 PolicyFlags;

} PROCESS_RULE, *PPROCESS_RULE;

static NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
    ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

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
                    status = STATUS_UNSUCCESSFUL;
                }
            }
            else
            {
                if (!NT_SUCCESS(
                        process::rules::AddProcessRuleEntry(&processRule->ImageFileName, processRule->PolicyFlags)))
                {
                    status = STATUS_UNSUCCESSFUL;
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
            }
            else
            {
                if (!NT_SUCCESS(
                        process::rules::UpdateProcessRuleEntry(&processRule->ImageFileName, processRule->PolicyFlags)))
                {
                    status = STATUS_UNSUCCESSFUL;
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
            }
            else
            {
                if (!NT_SUCCESS(process::rules::RemoveProcessRuleEntry(&processRule->ImageFileName)))
                {
                    status = STATUS_UNSUCCESSFUL;
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

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS winlogon = nullptr;

    WPP_INIT_TRACING(driverObject, registryPath);
    WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "MasterHide driver is loading");

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

#if DBG
    Test();
#endif

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