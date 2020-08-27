#include "stdafx.h"

using namespace Tools;

void OnDriverUnload( PDRIVER_OBJECT pDriverObject )
{
	UNREFERENCED_PARAMETER( pDriverObject );

#ifndef USE_KASPERSKY
	DestroySSDT();
	DestroyShadowSSDT();
#else
	if ( kaspersky::is_klhk_loaded() )
	{
		if ( !kaspersky::unhook_shadow_ssdt_routine( SYSCALL_NTUSERBUILDWNDLIST, oNtUserBuildHwndList ) )
			DBGPRINT( "Failed to unhook NtUserBuildHwndList" );

		if ( !kaspersky::unhook_shadow_ssdt_routine( SYSCALL_NTUSERWNDFROMPOINT, oNtUserWindowFromPoint ) )
			DBGPRINT( "Failed to unhook NtUserWindowFromPoint" );

		if ( !kaspersky::unhook_shadow_ssdt_routine( SYSCALL_NTUSERFINDWNDEX, oNtUserFindWindowEx ) )
			DBGPRINT( "Failed to unhook NtUserFindWindowEx" );

		if ( !kaspersky::unhook_shadow_ssdt_routine( SYSCALL_NTGETFOREGROUNDWND, oNtUserGetForegroundWindow ) )
			DBGPRINT( "Failed to unhook NtUserGetForegroundWindow" );

		if ( !kaspersky::unhook_shadow_ssdt_routine( SYSCALL_NTUSERQUERYWND, oNtUserQueryWindow ) )
			DBGPRINT( "Failed to unhook NtUserQueryWindow" );

		if ( !kaspersky::unhook_ssdt_routine( SYSCALL_NTQUERYSYSINFO, oNtQuerySystemInformation ) )
			DBGPRINT( "Failed to unhook NtQuerySystemInformation" );

		if ( !kaspersky::unhook_ssdt_routine( SYSCALL_NTOPENPROCESS, oNtOpenProcess ) )
			DBGPRINT( "Failed to unhook NtOpenProcess" );

		if ( !kaspersky::unhook_ssdt_routine( SYSCALL_NTALLOCVIRTUALMEM, oNtAllocateVirtualMemory ) )
			DBGPRINT( "Failed to unhook NtAllocateVirtualMemory" );

		if ( !kaspersky::unhook_ssdt_routine( SYSCALL_NTFREEVIRTUALMEM, oNtFreeVirtualMemory ) )
			DBGPRINT( "Failed to unhook NtFreeVirtualMemory" );

		if ( !kaspersky::unhook_ssdt_routine( SYSCALL_NTWRITEVIRTUALMEM, oNtWriteVirtualMemory ) )
			DBGPRINT( "Failed to unhook NtWriteVirtualMemory" );

		if ( !kaspersky::unhook_ssdt_routine( SYSCALL_NTDEVICEIOCTRLFILE, oNtDeviceIoControlFile ) )
			DBGPRINT( "Failed to unhook NtDeviceIoControlFile" );

		if ( !kaspersky::unhook_ssdt_routine( SYSCALL_NTLOADDRIVER, oNtLoadDriver ) )
			DBGPRINT( "Failed to unhook NtLoadDriver" );
	}
#endif

	//
	// Delay the execution for a second to make sure no thread is executing the hooked function
	//
	LARGE_INTEGER LargeInteger{ };
	LargeInteger.QuadPart = -11000000;

	KeDelayExecutionThread( KernelMode, FALSE, &LargeInteger );
	UnloadImages();

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
			SYSCALL_NTUSERQUERYWND = Tools::GetWin32Syscall( "NtUserQueryWindow" );
			SYSCALL_NTUSERFINDWNDEX = Tools::GetWin32Syscall( "NtUserFindWindowEx" );
			SYSCALL_NTUSERWNDFROMPOINT = Tools::GetWin32Syscall( "NtUserWindowFromPoint" );
			SYSCALL_NTUSERBUILDWNDLIST = Tools::GetWin32Syscall( "NtUserBuildHwndList" );
			SYSCALL_NTGETFOREGROUNDWND = Tools::GetWin32Syscall( "NtUserGetForegroundWindow" );

			SYSCALL_NTOPENPROCESS = Tools::GetNtSyscall( "NtOpenProcess" );
			SYSCALL_NTDEVICEIOCTRLFILE = Tools::GetNtSyscall( "NtDeviceIoControlFile" );
			SYSCALL_NTQUERYSYSINFO = Tools::GetNtSyscall( "NtQuerySystemInformation" );
			SYSCALL_NTALLOCVIRTUALMEM = Tools::GetNtSyscall( "NtAllocateVirtualMemory" );
			SYSCALL_NTFREEVIRTUALMEM = Tools::GetNtSyscall( "NtFreeVirtualMemory" );
			SYSCALL_NTWRITEVIRTUALMEM = Tools::GetNtSyscall( "NtWriteVirtualMemory" );
			SYSCALL_NTLOADDRIVER = Tools::GetNtSyscall( "NtLoadDriver" );
		}

#ifndef USE_KASPERSKY
		//
		// (S)SSDT Hooks are only Win7 compatible ( hardcoded )
		//
		if ( bIsWin7 )
		{
			DBGPRINT( "Using normal SSDT Hooking!\n" );
			InitializeSSDT();
			InitializeShadowSSDT();
		}
		else
		{
			DBGPRINT( "Not using kaspersky but (S)SSDT is not supported!\n" );
			return STATUS_NOT_SUPPORTED;
		}
#else
		DBGPRINT( "Using kaspersky!\n" );

		if ( !kaspersky::is_klhk_loaded() )
		{
			UnloadImages();
			DBGPRINT( "Kaspersky not loaded!\n" );
			return STATUS_UNSUCCESSFUL;
		}

		if ( !kaspersky::initialize() )
		{
			UnloadImages();
			DBGPRINT( "Kaspersky init failed!\n" );
			return STATUS_UNSUCCESSFUL;
		}

		DBGPRINT( "Using Kaspersky hypervisor!\n" );

		if ( !kaspersky::hvm_init() )
		{
			UnloadImages();
			DBGPRINT( "Hypervisor not loaded!\n" );
			return STATUS_UNSUCCESSFUL;
		}

		DBGPRINT( "Hypervisor loaded!\n" );

		//
		// SSDT
		//
		if ( kaspersky::hook_ssdt_routine( SYSCALL_NTOPENPROCESS, hkNtOpenProcess, reinterpret_cast< PVOID* >( &oNtOpenProcess ) ) )
		{
			DBGPRINT( "NtOpenProcess ( 0x%X ) hooked successfully!\n", SYSCALL_NTOPENPROCESS );
		}
		else
			DBGPRINT( "Failed to hook NtOpenProcess!\n" );

		if ( kaspersky::hook_ssdt_routine( SYSCALL_NTDEVICEIOCTRLFILE, hkNtDeviceIoControlFile, reinterpret_cast< PVOID* >( &oNtDeviceIoControlFile ) ) )
		{
			DBGPRINT( "NtDeviceIoControlFile ( 0x%X ) hooked successfully!\n", SYSCALL_NTDEVICEIOCTRLFILE );
		}
		else
			DBGPRINT( "Failed to hook NtDeviceIoControlFile!\n" );

		if ( kaspersky::hook_ssdt_routine( SYSCALL_NTQUERYSYSINFO, hkNtQuerySystemInformation, reinterpret_cast< PVOID* >( &oNtQuerySystemInformation ) ) )
		{
			DBGPRINT( "NtQuerySystemInformation ( 0x%X ) hooked successfully!\n", SYSCALL_NTQUERYSYSINFO );
		}
		else
			DBGPRINT( "Failed to hook NtQuerySystemInformation!\n" );

		if ( kaspersky::hook_ssdt_routine( SYSCALL_NTALLOCVIRTUALMEM, hkNtAllocateVirtualMemory, reinterpret_cast< PVOID* >( &oNtAllocateVirtualMemory ) ) )
		{
			DBGPRINT( "NtAllocateVirtualMemory ( 0x%X ) hooked successfully!\n", SYSCALL_NTALLOCVIRTUALMEM );
		}
		else
			DBGPRINT( "Failed to hook NtAllocateVirtualMemory!\n" );

		if ( kaspersky::hook_ssdt_routine( SYSCALL_NTFREEVIRTUALMEM, hkNtFreeVirtualMemory, reinterpret_cast< PVOID* >( &oNtFreeVirtualMemory ) ) )
		{
			DBGPRINT( "NtFreeVirtualMemory ( 0x%X ) hooked successfully!\n", SYSCALL_NTFREEVIRTUALMEM );
		}
		else
			DBGPRINT( "Failed to hook NtFreeVirtualMemory!\n" );

		if ( kaspersky::hook_ssdt_routine( SYSCALL_NTWRITEVIRTUALMEM, hkNtWriteVirtualMemory, reinterpret_cast< PVOID* >( &oNtWriteVirtualMemory ) ) )
		{
			DBGPRINT( "NtWriteVirtualMemory ( 0x%X ) hooked successfully!\n", SYSCALL_NTWRITEVIRTUALMEM );
		}
		else
			DBGPRINT( "Failed to hook NtWriteVirtualMemory!\n" );

		if ( kaspersky::hook_ssdt_routine( SYSCALL_NTLOADDRIVER, hkNtLoadDriver, reinterpret_cast< PVOID* >( &oNtLoadDriver ) ) )
		{
			DBGPRINT( "NtLoadDriver ( 0x%X ) hooked successfully!\n", SYSCALL_NTLOADDRIVER );
		}
		else
			DBGPRINT( "Failed to hook NtLoadDriver!\n" );

		//
		// Shadow SSDT
		//
		if ( kaspersky::hook_shadow_ssdt_routine( SYSCALL_NTUSERQUERYWND, hkNtUserQueryWindow, reinterpret_cast< PVOID* >( &oNtUserQueryWindow ) ) )
		{
			DBGPRINT( "NtUserQueryWindow ( 0x%X ) hooked successfully!\n", SYSCALL_NTUSERQUERYWND );
		}
		else
			DBGPRINT( "Failed to hook NtUserQueryWindow!\n" );

		if ( kaspersky::hook_shadow_ssdt_routine( SYSCALL_NTUSERFINDWNDEX, hkNtUserFindWindowEx, reinterpret_cast< PVOID* >( &oNtUserFindWindowEx ) ) )
		{
			DBGPRINT( "NtUserFindWindowEx ( 0x%X ) hooked successfully!\n", SYSCALL_NTUSERFINDWNDEX );
		}
		else
			DBGPRINT( "Failed to hook NtUserFindWindowEx!\n" );

		if ( kaspersky::hook_shadow_ssdt_routine( SYSCALL_NTUSERWNDFROMPOINT, hkNtUserWindowFromPoint, reinterpret_cast< PVOID* >( &oNtUserWindowFromPoint ) ) )
		{
			DBGPRINT( "NtUserWindowFromPoint ( 0x%X ) hooked successfully!\n", SYSCALL_NTUSERWNDFROMPOINT );
		}
		else
			DBGPRINT( "Failed to hook NtUserWindowFromPoint!\n" );

		if ( kaspersky::hook_shadow_ssdt_routine( SYSCALL_NTUSERBUILDWNDLIST, hkNtUserBuildHwndList, reinterpret_cast< PVOID* >( &oNtUserBuildHwndList ) ) )
		{
			DBGPRINT( "NtUserBuildHwndList ( 0x%X ) hooked successfully!\n", SYSCALL_NTUSERBUILDWNDLIST );
		}
		else
			DBGPRINT( "Failed to hook NtUserBuildHwndList!\n" );

		if ( kaspersky::hook_shadow_ssdt_routine( SYSCALL_NTGETFOREGROUNDWND, hkNtUserGetForegroundWindow, reinterpret_cast< PVOID* >( &oNtUserGetForegroundWindow ) ) )
		{
			DBGPRINT( "NtUserGetForegroundWindow ( 0x%X ) hooked successfully!\n", SYSCALL_NTGETFOREGROUNDWND );
		}
		else
			DBGPRINT( "Failed to hook NtUserGetForegroundWindow!\n" );
#endif
	}
	else
		// No support for other OS
		return STATUS_NOT_SUPPORTED;

	return STATUS_SUCCESS;
}