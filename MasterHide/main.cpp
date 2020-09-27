#include "stdafx.h"

void OnDriverUnload( PDRIVER_OBJECT pDriverObject )
{
	UNREFERENCED_PARAMETER( pDriverObject );

	ssdt::Destroy();
	sssdt::Destroy();

	//
	// Delay the execution for a second to make sure no thread is executing the hooked function
	//
	LARGE_INTEGER LargeInteger{ };
	LargeInteger.QuadPart = -11000000;

	KeDelayExecutionThread( KernelMode, FALSE, &LargeInteger );
	tools::UnloadImages();

	DBGPRINT( "Driver unload routine triggered!\n" );
}

extern "C" NTSTATUS NTAPI DriverEntry( PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath )
{
	UNREFERENCED_PARAMETER( pRegistryPath );

	if ( !pDriverObject )
	{
		DBGPRINT( "Err: No driver object!\n" );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	RTL_OSVERSIONINFOW os{ };
	os.dwOSVersionInfoSize = sizeof( os );

	if ( !NT_SUCCESS( RtlGetVersion( &os ) ) )
	{
		DBGPRINT( "Err: RtlGetVersion failed!\n" );
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	pDriverObject->DriverUnload = &OnDriverUnload;
	DBGPRINT( "Driver loaded!\n" );

	//
	// If the OS is either Windows 10, 8/8.1 those are the only supported OS
	//
	bool bIsWin7 = ( os.dwMajorVersion == 6 && os.dwMinorVersion == 1 );

	if ( os.dwMajorVersion == 10 || ( bIsWin7 || ( os.dwMajorVersion == 6 && os.dwMinorVersion == 2 ) || ( os.dwMajorVersion == 6 && os.dwMinorVersion == 3 ) ) )
	{
		// This special API only works in Win8+ and it basically allows you to set no executable flag in NonPagedPools
		ExInitializeDriverRuntime( DrvRtPoolNxOptIn );

		//
		// Sycalls numbers are OS based, since user32.dll doesnt export them in early Windows versions ( Win7 for example ) we hardcode them and extract them on newer 
		// systems that export it ( Win8+ for example in win32u.dll )
		//
		if ( !bIsWin7 )
		{
			SYSCALL_NTUSERQUERYWND = tools::GetWin32Syscall( "NtUserQueryWindow" );
			SYSCALL_NTUSERFINDWNDEX = tools::GetWin32Syscall( "NtUserFindWindowEx" );
			SYSCALL_NTUSERWNDFROMPOINT = tools::GetWin32Syscall( "NtUserWindowFromPoint" );
			SYSCALL_NTUSERBUILDWNDLIST = tools::GetWin32Syscall( "NtUserBuildHwndList" );
			SYSCALL_NTGETFOREGROUNDWND = tools::GetWin32Syscall( "NtUserGetForegroundWindow" );

			SYSCALL_NTOPENPROCESS = tools::GetNtSyscall( "NtOpenProcess" );
			SYSCALL_NTDEVICEIOCTRLFILE = tools::GetNtSyscall( "NtDeviceIoControlFile" );
			SYSCALL_NTQUERYSYSINFO = tools::GetNtSyscall( "NtQuerySystemInformation" );
			SYSCALL_NTALLOCVIRTUALMEM = tools::GetNtSyscall( "NtAllocateVirtualMemory" );
			SYSCALL_NTFREEVIRTUALMEM = tools::GetNtSyscall( "NtFreeVirtualMemory" );
			SYSCALL_NTWRITEVIRTUALMEM = tools::GetNtSyscall( "NtWriteVirtualMemory" );
			SYSCALL_NTLOADDRIVER = tools::GetNtSyscall( "NtLoadDriver" );
		}

#ifndef USE_KASPERSKY
		//
		// (S)SSDT Hooks are only Win7 compatible ( hardcoded )
		//
		DBGPRINT( "Not using Kaspersky to hook, Shadow SSDT is unstable!\n" );
#else
		DBGPRINT( "Using Kaspersky!\n" );

		if ( !kaspersky::is_klhk_loaded() )
		{
			tools::UnloadImages();
			DBGPRINT( "Kaspersky not loaded!\n" );
			return STATUS_UNSUCCESSFUL;
		}

		if ( !kaspersky::initialize() )
		{
			tools::UnloadImages();
			DBGPRINT( "Kaspersky init failed!\n" );
			return STATUS_UNSUCCESSFUL;
		}

		DBGPRINT( "Using Kaspersky hypervisor!\n" );

		if ( !kaspersky::hvm_init() )
		{
			tools::UnloadImages();
			DBGPRINT( "Hypervisor not loaded!\n" );
			return STATUS_UNSUCCESSFUL;
		}

		DBGPRINT( "Hypervisor loaded!\n" );
#endif
		ssdt::Init();
		sssdt::Init();
	}
	else
		// No support for other OS
		return STATUS_NOT_SUPPORTED;

	return STATUS_SUCCESS;
}