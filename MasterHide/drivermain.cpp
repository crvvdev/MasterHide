#include "includes.hpp"

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNREFERENCED_PARAMETER(pDriverObject);

    DBGPRINT("Unload called\n");

    ssdt::Destroy();
    sssdt::Destroy();
    syscalls::Destroy();

    DBGPRINT("Waiting for hooks to complete!");

    hooks::WaitForHooksCompletion();

    DBGPRINT("MasterHide unloaded!");
}

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);

    NTSTATUS status = STATUS_SUCCESS;

    DBGPRINT("MasterHide is loading!");

    RTL_OSVERSIONINFOW os{};
    os.dwOSVersionInfoSize = sizeof(os);

    status = RtlGetVersion(&os);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: RtlGetVersion returned 0x%08X", status);
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    const ULONG majorVersion = os.dwMajorVersion;
    const ULONG minorVersion = os.dwMinorVersion;

    if (!((majorVersion == 10 && minorVersion == 1) || // Windows 11
          (majorVersion == 10 && minorVersion == 0) || // Windows 10
          (majorVersion == 6 && minorVersion == 3) ||  // Windows 8.1
          (majorVersion == 6 && minorVersion == 2) ||  // Windows 8
          (majorVersion == 6 && minorVersion == 1)))   // Windows 7
    {
        DBGPRINT("Err: Unsupported Windows version. Major = %d Minor = %d", majorVersion, minorVersion);
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    DBGPRINT("Windows Major = %d Minor = %d Build = %d", majorVersion, minorVersion, os.dwBuildNumber);

#ifdef USE_KASPERSKY
    DBGPRINT("Using kaspersky hook.");

    if (!::utils::init())
    {
        DBGPRINT("Err: utils not initialized!");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    if (!kaspersky::is_klhk_loaded() || !kaspersky::initialize())
    {
        DBGPRINT("Err: Failed to setup kaspersky!");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    status = kaspersky::hvm_init();
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: hvm_init returned 0x%08X", status);
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    DBGPRINT("Kaspersky hypervisor loaded!");
#else
    DBGPRINT("MasterHide is using odinary SSDT hooks, which means: It only can be used on PatchGuard disabled "
             "environment, such as kernel debugger attached or manually patching the kernel! The system WILL crash if "
             "PatchGuard is enabled.\n");
#endif

    pDriverObject->DriverUnload = &DriverUnload;

    // attach to win32k process first please.

    PEPROCESS winlogon = tools::GetProcessByName(L"winlogon.exe");
    if (!winlogon)
    {
        DBGPRINT("Err: winlogon.exe process not found!");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    KeAttachProcess(winlogon);

    syscalls::Init();
    ssdt::Init();
    sssdt::Init();

    KeDetachProcess();

    DBGPRINT("MasterHide loaded!");

    return STATUS_SUCCESS;
}