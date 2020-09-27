#include "stdafx.h"

PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable = NULL;

ULONGLONG GetKeServiceDescriptorTable64()
{
	PUCHAR      pStartSearchAddress = ( PUCHAR )__readmsr( 0xC0000082 );
	PUCHAR      pEndSearchAddress = ( PUCHAR )( ( ( ULONG_PTR )pStartSearchAddress + PAGE_SIZE ) & ( ~0x0FFF ) );
	PULONG      pFindCodeAddress = NULL;

	while ( ++pStartSearchAddress < pEndSearchAddress )
	{
		if ( ( *( PULONG )pStartSearchAddress & 0xFFFFFF00 ) == 0x83f70000 )
		{
			pFindCodeAddress = ( PULONG )( pStartSearchAddress - 12 );
			return ( ULONG_PTR )pFindCodeAddress + ( ( ( *( PULONG )pFindCodeAddress ) >> 24 ) + 7 ) + ( ULONG_PTR )( ( ( *( PULONG )( pFindCodeAddress + 1 ) ) & 0x0FFFF ) << 8 );
		}
	}
	return 0;
}

ULONGLONG GetSSDTFuncCurAddr64( ULONG id )
{
	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = ( PULONG )g_KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[ id ];
	dwtmp = dwtmp >> 4;
	return ( LONGLONG )dwtmp + ( ULONGLONG )ServiceTableBase;
}

ULONG GetOffsetAddress( ULONGLONG FuncAddr )
{
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = ( PULONG )g_KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ( ULONG )( FuncAddr - ( ULONGLONG )ServiceTableBase );
	dwtmp = dwtmp << 4;
	return dwtmp;
}

bool HookSSDT( PUCHAR pCode, ULONG ulCodeSize, PVOID pNewFunction, PVOID* pOldFunction, ULONG SyscallNum )
{
	if ( !pNewFunction || !pOldFunction || SyscallNum <= 0 )
		return false;

	//
	// Log the Syscall number that we're hooking
	//
	DBGPRINT( "[ HookSSDT ] Syscall: 0x%X\n", SyscallNum );

	//
	// Log the Original function address
	//
	*pOldFunction = PVOID( GetSSDTFuncCurAddr64( SyscallNum ) );
	DBGPRINT( "[ HookSSDT ] Original: 0x%p\n", *pOldFunction );

	*( PULONG64 )( jmp_trampoline + 3 ) = ULONG64( pNewFunction );

	//
	// Find a suitable code cave inside the module .text section that we can use to trampoline to our hook
	//
	auto pCodeCave = utils::FindCodeCave( pCode, ulCodeSize, sizeof( jmp_trampoline ) );
	if ( !pCodeCave )
	{
		DBGPRINT( "[ HookSSDT ] Failed to find a suitable code cave.\n" );
		return false;
	}

	DBGPRINT( "[ HookSSDT ] Code Cave: 0x%p\n", pCodeCave );

	//
	// Change page protection
	//
	auto Mdl = IoAllocateMdl( pCodeCave, sizeof( jmp_trampoline ), 0, 0, NULL );
	if ( Mdl == NULL )
	{
		DBGPRINT( "[ HookSSDT ] IoAllocateMdl failed!\n" );
		return false;
	}

	MmProbeAndLockPages( Mdl, KernelMode, IoWriteAccess );

	auto Mapping = MmMapLockedPagesSpecifyCache( Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority );
	if ( Mapping == NULL )
	{
		MmUnlockPages( Mdl );
		IoFreeMdl( Mdl );
		DBGPRINT( "[ HookSSDT ] MmMapLockedPagesSpecifyCache failed!\n" );
		return false;
	}

	//
	// Modify SSDT table
	//
	auto ServiceTableBase = ( PULONG )g_KeServiceDescriptorTable->ServiceTableBase;

	auto irql = utils::WPOFF();

	RtlCopyMemory( Mapping, jmp_trampoline, sizeof( jmp_trampoline ) );

	auto SsdtEntry = GetOffsetAddress( ULONG64( pCodeCave ) );
	SsdtEntry &= 0xFFFFFFF0;
	SsdtEntry += ServiceTableBase[ SyscallNum ] & 0x0F;
	ServiceTableBase[ SyscallNum ] = SsdtEntry;

	utils::WPON( irql );

	//
	// Restore protection
	//
	MmUnmapLockedPages( Mapping, Mdl );
	MmUnlockPages( Mdl );
	IoFreeMdl( Mdl );

	return true;
}

bool UnhookSSDT( PVOID pFunction, ULONG SyscallNum )
{
	if ( !pFunction || SyscallNum <= 0 )
		return false;

	auto ServiceTableBase = ( PULONG )g_KeServiceDescriptorTable->ServiceTableBase;

	auto irql = utils::WPOFF();

	auto SsdtEntry = GetOffsetAddress( ULONG64( pFunction ) );
	SsdtEntry &= 0xFFFFFFF0;
	SsdtEntry += ServiceTableBase[ SyscallNum ] & 0x0F;
	ServiceTableBase[ SyscallNum ] = SsdtEntry;

	utils::WPON( irql );

	return true;
}

void ssdt::Init()
{
#ifndef USE_KASPERSKY
	g_KeServiceDescriptorTable = PSYSTEM_SERVICE_TABLE( GetKeServiceDescriptorTable64() );
	DBGPRINT( "KeServiceDescriptorTable: 0x%p\n", g_KeServiceDescriptorTable );
	if ( !g_KeServiceDescriptorTable )
		return;

	auto KiServiceTable = PULONG( g_KeServiceDescriptorTable->ServiceTableBase );
	DBGPRINT( "KeServiceDescriptorTable->ServiceTableBase: 0x%p\n", KiServiceTable );
	if ( !KiServiceTable )
		return;

	DBGPRINT( "KeServiceDescriptorTable->NumberOfServices: %lld\n", g_KeServiceDescriptorTable->NumberOfServices );

	auto ntoskrnl = ULONG64( tools::GetNtKernelBase() );
	DBGPRINT( "ntoskrnl: 0x%llx\n", ntoskrnl );
	if ( !ntoskrnl )
		return;

	ULONG ulCodeSize = 0;
	auto pCode = PUCHAR( tools::GetImageTextSection( ntoskrnl, &ulCodeSize ) );
	if ( pCode )
	{
		DBGPRINT( "ntoskrnl.exe .text section %p\n", pCode );

		if ( HookSSDT( pCode, ulCodeSize, &hkNtQuerySystemInformation, reinterpret_cast< PVOID* >( &oNtQuerySystemInformation ), SYSCALL_NTQUERYSYSINFO ) )
		{
			DBGPRINT( "NtQuerySystemInformation hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtQuerySystemInformation!\n" );

		if ( HookSSDT( pCode, ulCodeSize, &hkNtOpenProcess, reinterpret_cast< PVOID* >( &oNtOpenProcess ), SYSCALL_NTOPENPROCESS ) )
		{
			DBGPRINT( "NtOpenProcess hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtOpenProcess!\n" );

		if ( HookSSDT( pCode, ulCodeSize, &hkNtAllocateVirtualMemory, reinterpret_cast< PVOID* >( &oNtAllocateVirtualMemory ), SYSCALL_NTALLOCVIRTUALMEM ) )
		{
			DBGPRINT( "NtAllocateVirtualMemory hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtAllocateVirtualMemory!\n" );

		if ( HookSSDT( pCode, ulCodeSize, &hkNtFreeVirtualMemory, reinterpret_cast< PVOID* >( &oNtFreeVirtualMemory ), SYSCALL_NTFREEVIRTUALMEM ) )
		{
			DBGPRINT( "NtFreeVirtualMemory hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtFreeVirtualMemory!\n" );

		if ( HookSSDT( pCode, ulCodeSize, &hkNtWriteVirtualMemory, reinterpret_cast< PVOID* >( &oNtWriteVirtualMemory ), SYSCALL_NTWRITEVIRTUALMEM ) )
		{
			DBGPRINT( "NtWriteVirtualMemory hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtWriteVirtualMemory!\n" );

		if ( HookSSDT( pCode, ulCodeSize, &hkNtDeviceIoControlFile, reinterpret_cast< PVOID* >( &oNtDeviceIoControlFile ), SYSCALL_NTDEVICEIOCTRLFILE ) )
		{
			DBGPRINT( "NtDeviceIoControlFile hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtDeviceIoControlFile!\n" );
	}
#else
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
#endif
}

void ssdt::Destroy()
{
#ifndef USE_KASPERSKY
	if ( !g_KeServiceDescriptorTable )
		return;

	if ( !UnhookSSDT( oNtQuerySystemInformation, SYSCALL_NTQUERYSYSINFO ) )
		DBGPRINT( "Failed to unhook NtQuerySystemInformation!\n" );

	if ( !UnhookSSDT( oNtOpenProcess, SYSCALL_NTOPENPROCESS ) )
		DBGPRINT( "Failed to unhook NtOpenProcess!\n" );

	if ( !UnhookSSDT( oNtAllocateVirtualMemory, SYSCALL_NTALLOCVIRTUALMEM ) )
		DBGPRINT( "Failed to unhook NtAllocateVirtualMemory!\n" );

	if ( !UnhookSSDT( oNtFreeVirtualMemory, SYSCALL_NTFREEVIRTUALMEM ) )
		DBGPRINT( "Failed to unhook NtFreeVirtualMemory!\n" );

	if ( !UnhookSSDT( oNtWriteVirtualMemory, SYSCALL_NTWRITEVIRTUALMEM ) )
		DBGPRINT( "Failed to unhook NtWriteVirtualMemory!\n" );

	if ( !UnhookSSDT( oNtDeviceIoControlFile, SYSCALL_NTDEVICEIOCTRLFILE ) )
		DBGPRINT( "Failed to unhook NtDeviceIoControlFile!\n" );
#else
	if ( !kaspersky::is_klhk_loaded() )
		return;

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
#endif
}