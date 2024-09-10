#include "includes.hpp"

#define MASTERHIDE_GUID L"{EDC00A52-CBB9-490E-89A3-69E3FFF137BA}"

static UNICODE_STRING g_deviceName = RTL_CONSTANT_STRING(L"\\Device\\" MASTERHIDE_GUID);
static UNICODE_STRING g_symbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\" MASTERHIDE_GUID);
static PDEVICE_OBJECT g_deviceObject = nullptr;

#if 0
enum EProcessRuleType : int
{
    ProcessRuleTypeInvalid = 0,
    ProcessRuleTypeProcessId = 1,
    ProcessRuleTypeProcessImageName = 2
};

typedef struct _RULE_ENTRY
{
    EProcessRuleType ProcessRuleType;
    ULONG ProcessPolicyFlags;
    UCHAR Opaque[MAX_PATH];

} RULE_ENTRY, *PRULE_ENTRY;

void CreateProcessRuleByProcessName(_In_ PUNICODE_STRING imageFileName)
{
    const NTSTATUS status = rules::AddProcessRuleEntry(imageFileName, PROCESS_POLICY_HIDE_FROM_DEBUGGER_FULL);
    if (!NT_SUCCESS(status))
    {
        return;
    }
}
#endif

void Test()
{
    {
        UNICODE_STRING imageFileName = RTL_CONSTANT_STRING(L"\\??\\C:\\Users\\Jonathan\\Desktop\\al-khaser.exe");

        if (!NT_SUCCESS(rules::AddProcessRuleEntry(&imageFileName, PROCESS_POLICY_HIDE_FROM_DEBUGGER_FULL)))
        {
            return;
        }

        WppTracePrint(TRACE_LEVEL_VERBOSE, DEBUG, "Added %wZ to hidden from debugger list!", &imageFileName);
    }
    {
        UNICODE_STRING imageFileName =
            RTL_CONSTANT_STRING(L"\\??\\C:\\Users\\Jonathan\\Desktop\\x64dbg_clean\\x64\\x64dbg.exe");

        if (!NT_SUCCESS(rules::AddProcessRuleEntry(&imageFileName, PROCESS_POLICY_PROTECTED_FULL)))
        {
            return;
        }

        WppTracePrint(TRACE_LEVEL_VERBOSE, DEBUG, "Added %wZ to protected list!", &imageFileName);
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
    rules::Deinitialize();

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

    NTSTATUS status = STATUS_NOT_IMPLEMENTED;

    // TODO: implement
#if 0
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);
    ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode)
    {
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
#endif

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

    *(PULONG)((PCHAR)driverObject->DriverSection + 13 * sizeof(void *)) |= 0x20;

    // (1) Setup driver object
    //
    status = IoCreateDevice(driverObject, 0, &g_deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_deviceObject);
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
    INITIALIZE_INTERFACE(rules);
    INITIALIZE_INTERFACE(callbacks);
    INITIALIZE_INTERFACE(syscalls);
    INITIALIZE_INTERFACE(hooks);

#undef INITIALIZE_INTERFACE

    KeDetachProcess();
    ObDereferenceObject(winlogon);

#if DBG
    Test();
#endif

    WppTracePrint(TRACE_LEVEL_INFORMATION, GENERAL, "MasterHide successfully loaded!");

Exit:
    if (!NT_SUCCESS(status))
    {
        OnDriverUnload();
        WPP_CLEANUP(driverObject);

        status = STATUS_FAILED_DRIVER_ENTRY;
    }

    return status;
}