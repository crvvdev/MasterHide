#include "stdafx.h"

PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTableShadow = NULL;
HANDLE hCsrssPID = HANDLE( -1 );

ULONGLONG GetKeServiceDescriptorTableShadow64()
{
	PUCHAR StartSearchAddress = ( PUCHAR )__readmsr( 0xC0000082 );
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for ( i = StartSearchAddress; i < EndSearchAddress; i++ )
	{
		if ( MmIsAddressValid( i ) && MmIsAddressValid( i + 1 ) && MmIsAddressValid( i + 2 ) )
		{
			b1 = *i;
			b2 = *( i + 1 );
			b3 = *( i + 2 );
			if ( b1 == 0x4c && b2 == 0x8d && b3 == 0x1d )
			{
				memcpy( &templong, i + 3, 4 );
				addr = ( ULONGLONG )templong + ( ULONGLONG )i + 7;
				return addr;
			}
		}
	}
	return 0;
}

ULONGLONG GetSSSDTFuncCurAddr64( ULONG64 Index )
{
	ULONGLONG	W32pServiceTable = 0, qwTemp = 0;
	LONG 	dwTemp = 0;
	W32pServiceTable = ( ULONGLONG )( g_KeServiceDescriptorTableShadow->ServiceTableBase );
	qwTemp = W32pServiceTable + 4 * ( Index - 0x1000 );
	dwTemp = *( PLONG )qwTemp;
	dwTemp = dwTemp >> 4;
	qwTemp = W32pServiceTable + ( LONG64 )dwTemp;
	return qwTemp;
}

bool HookSSSDT( PUCHAR pCode, ULONG ulCodeSize, PVOID pNewFunction, PVOID* pOldFunction, ULONG SyscallNum )
{
	if ( !pNewFunction || !pOldFunction || SyscallNum <= 0 )
		return false;

	ULONGLONG				W32pServiceTable = 0, qwTemp = 0;
	LONG 					dwTemp = 0;
	KIRQL					irql;

	//
	// Log the Syscall number that we're hooking
	//
	DBGPRINT( "[ HookSSSDT ] Syscall: 0x%X\n", SyscallNum );

	//
	// Log the Original function address
	//
	*pOldFunction = PVOID( GetSSSDTFuncCurAddr64( SyscallNum ) );
	DBGPRINT( "[ HookSSSDT ] Original: 0x%p\n", *pOldFunction );

	*( PULONG64 )( jmp_trampoline + 3 ) = ULONG64( pNewFunction );

	//
	// Find a suitable code cave inside the module .text section that we can use to trampoline to our hook
	//
	auto pCodeCave = utils::FindCodeCave( pCode, ulCodeSize, sizeof( jmp_trampoline ) );
	if ( !pCodeCave )
	{
		DBGPRINT( "[ HookSSSDT ] Failed to find a suitable code cave.\n" );
		return false;
	}

	DBGPRINT( "[ HookSSSDT ] Code Cave: 0x%p\n", pCodeCave );

	//
	// Change page protection
	//
	auto Mdl = IoAllocateMdl( pCodeCave, sizeof( jmp_trampoline ), 0, 0, NULL );
	if ( Mdl == NULL )
	{
		DBGPRINT( "[ HookSSSDT ] IoAllocateMdl failed!\n" );
		return false;
	}

	MmProbeAndLockPages( Mdl, KernelMode, IoWriteAccess );

	auto Mapping = MmMapLockedPagesSpecifyCache( Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority );
	if ( Mapping == NULL )
	{
		MmUnlockPages( Mdl );
		IoFreeMdl( Mdl );
		DBGPRINT( "[ HookSSSDT ] MmMapLockedPagesSpecifyCache failed!\n" );
		return false;
	}

	//
	// Modify SSSDT table
	//
	irql = utils::WPOFF();

	RtlCopyMemory( Mapping, jmp_trampoline, sizeof( jmp_trampoline ) );

	W32pServiceTable = ( ULONGLONG )( g_KeServiceDescriptorTableShadow->ServiceTableBase );
	qwTemp = W32pServiceTable + 4 * ( SyscallNum - 0x1000 );
	dwTemp = ( LONG )( ( ULONG64 )pCodeCave - W32pServiceTable );
	dwTemp = dwTemp << 4;

	*( PLONG )qwTemp = dwTemp;

	utils::WPON( irql );

	//
	// Restore protection
	//
	MmUnmapLockedPages( Mapping, Mdl );
	MmUnlockPages( Mdl );
	IoFreeMdl( Mdl );

	return true;
}

bool UnhookSSSDT( PVOID pFunction, ULONG SyscallNum )
{
	if ( !pFunction || SyscallNum <= 0 )
		return false;

	ULONGLONG				W32pServiceTable = 0, qwTemp = 0;
	LONG 					dwTemp = 0;
	KIRQL					irql;

	irql = utils::WPOFF();

	W32pServiceTable = ( ULONGLONG )( g_KeServiceDescriptorTableShadow->ServiceTableBase );
	qwTemp = W32pServiceTable + 4 * ( SyscallNum - 0x1000 );
	dwTemp = ( LONG )( ( ULONG64 )pFunction - W32pServiceTable );
	dwTemp = dwTemp << 4;

	*( PLONG )qwTemp = dwTemp;

	utils::WPON( irql );

	return true;
}

PSYSTEM_HANDLE_INFORMATION_EX GetSystemHandleInformation()
{
	PSYSTEM_HANDLE_INFORMATION_EX pSHInfo = NULL;
	NTSTATUS Status = STATUS_NO_MEMORY;
	ULONG SMInfoLen = 0x1000;

	do
	{
		pSHInfo = ( PSYSTEM_HANDLE_INFORMATION_EX )ExAllocatePoolWithTag( PagedPool, SMInfoLen, TAG );
		if ( !pSHInfo )
			break;

		Status = ZwQuerySystemInformation( SystemHandleInformation, pSHInfo, SMInfoLen, &SMInfoLen );
		if ( !NT_SUCCESS( Status ) )
		{
			ExFreePoolWithTag( pSHInfo, TAG );
			pSHInfo = NULL;
		}
	} while ( Status == STATUS_INFO_LENGTH_MISMATCH );

	return pSHInfo;
}

HANDLE GetCsrssPid()
{
	HANDLE CsrId = ( HANDLE )0;
	PSYSTEM_HANDLE_INFORMATION_EX pHandles = GetSystemHandleInformation();
	if ( pHandles )
	{
		unsigned i;
		for ( i = 0; i < pHandles->NumberOfHandles && !CsrId; i++ )
		{
			OBJECT_ATTRIBUTES obj; CLIENT_ID cid;
			HANDLE Process, hObject;
			InitializeObjectAttributes( &obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL );
			cid.UniqueProcess = ( HANDLE )pHandles->Information[ i ].ProcessId;
			cid.UniqueThread = 0;

			auto res = ZwOpenProcess( &Process, PROCESS_DUP_HANDLE, &obj, &cid );
			if ( NT_SUCCESS( res ) )
			{
				res = ZwDuplicateObject( Process, ( PHANDLE )( pHandles->Information[ i ].Handle ), NtCurrentProcess(), &hObject, 0, FALSE, DUPLICATE_SAME_ACCESS );
				if ( NT_SUCCESS( res ) )
				{
					UCHAR Buff[ 0x200 ];
					POBJECT_NAME_INFORMATION ObjName = ( POBJECT_NAME_INFORMATION )&Buff;

					res = ZwQueryObject( hObject, ObjectTypeInformation, ObjName, sizeof( Buff ), NULL );
					if ( NT_SUCCESS( res ) )
					{
						if ( ObjName->Name.Buffer && ( !wcsncmp( L"Port", ObjName->Name.Buffer, 4 ) || !wcsncmp( L"ALPC Port", ObjName->Name.Buffer, 9 ) ) )
						{
							res = ZwQueryObject( hObject, ( OBJECT_INFORMATION_CLASS )1, ObjName, sizeof( Buff ), NULL );
							if ( NT_SUCCESS( res ) )
							{
								if ( ObjName->Name.Buffer && !wcsncmp( L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20 ) )
									CsrId = ( HANDLE )pHandles->Information[ i ].ProcessId;
							}
						}
					}
					else
						DBGPRINT( "[ GetCsr ] ZwQueryObject failed 0x%X\n", res );

					ZwClose( hObject );
				}
				else if ( res != STATUS_NOT_SUPPORTED )
					DBGPRINT( "[ GetCsr ] ZwDuplicateObject failed 0x%X\n", res );

				ZwClose( Process );
			}
			else
				DBGPRINT( "[ GetCsr ] NtOpenProcess failed 0x%X\n", res );
		}
		ExFreePoolWithTag( pHandles, TAG );
	}
	return CsrId;
}

void sssdt::Init()
{
#ifndef USE_KASPERSKY
	g_KeServiceDescriptorTableShadow = PSYSTEM_SERVICE_TABLE( GetKeServiceDescriptorTableShadow64() + sizeof( SYSTEM_SERVICE_TABLE ) );
	DBGPRINT( "KeServiceDescriptorTableShadow: 0x%p\n", g_KeServiceDescriptorTableShadow );

	if ( !g_KeServiceDescriptorTableShadow )
		return;

	auto W32pServiceTable = PULONG( g_KeServiceDescriptorTableShadow->ServiceTableBase );
	DBGPRINT( "KeServiceDescriptorTableShadow->ServiceTableBase: 0x%p\n", W32pServiceTable );

	if ( !W32pServiceTable )
		return;

	DBGPRINT( "KeServiceDescriptorTableShadow->NumberOfServices: %lld\n", g_KeServiceDescriptorTableShadow->NumberOfServices );

	auto Csrss = GetCsrssPid();

	PEPROCESS Process = nullptr;
	auto res = PsLookupProcessByProcessId( Csrss, &Process );
	if ( !NT_SUCCESS( res ) )
	{
		DBGPRINT( "[ ShadowSSDT ] PsLookupProcessByProcessId failed 0x%X\n", res );
		return;
	}

	//
	// Save csrss.exe PID for later
	//
	hCsrssPID = Csrss;

	KAPC_STATE apc{ };
	KeStackAttachProcess( Process, &apc );

	auto win32k = ULONG64( tools::GetModuleBase( "\\SystemRoot\\System32\\win32k.sys" ) );
	DBGPRINT( "win32k: 0x%llx\n", win32k );
	if ( !win32k )
		return;

	ULONG ulCodeSize = 0;
	auto pCode = PUCHAR( tools::GetImageTextSection( win32k, &ulCodeSize ) );
	if ( pCode )
	{
		DBGPRINT( "win32k.sys .text section 0x%p\n", pCode );

		if ( HookSSSDT( pCode, ulCodeSize, &hkNtUserQueryWindow, reinterpret_cast< PVOID* >( &oNtUserQueryWindow ), SYSCALL_NTUSERQUERYWND ) )
		{
			DBGPRINT( "NtUserQueryWindow hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtUserQueryWindow!\n" );

		if ( HookSSSDT( pCode, ulCodeSize, &hkNtUserFindWindowEx, reinterpret_cast< PVOID* >( &oNtUserFindWindowEx ), SYSCALL_NTUSERFINDWNDEX ) )
		{
			DBGPRINT( "NtUserFindWindowEx hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtUserFindWindowEx!\n" );

		if ( HookSSSDT( pCode, ulCodeSize, &hkNtUserWindowFromPoint, reinterpret_cast< PVOID* >( &oNtUserWindowFromPoint ), SYSCALL_NTUSERWNDFROMPOINT ) )
		{
			DBGPRINT( "NtUserWindowFromPoint hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtUserWindowFromPoint!\n" );

		if ( HookSSSDT( pCode, ulCodeSize, &hkNtUserBuildHwndList, reinterpret_cast< PVOID* >( &oNtUserBuildHwndList ), SYSCALL_NTUSERBUILDWNDLIST ) )
		{
			DBGPRINT( "NtUserBuildHwndList hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtUserBuildHwndList!\n" );

		if ( HookSSSDT( pCode, ulCodeSize, &hkNtUserGetForegroundWindow, reinterpret_cast< PVOID* >( &oNtUserGetForegroundWindow ), SYSCALL_NTGETFOREGROUNDWND ) )
		{
			DBGPRINT( "NtUserGetForegroundWindow hooked successfully!\n" );
		}
		else
			DBGPRINT( "Failed to hook NtUserGetForegroundWindow!\n" );
	}

	KeUnstackDetachProcess( &apc );
	ObDereferenceObject( Process );
#else

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

void sssdt::Destroy()
{
#ifndef USE_KASPERSKY
	if ( !g_KeServiceDescriptorTableShadow )
		return;

	PEPROCESS Process = nullptr;
	auto res = PsLookupProcessByProcessId( hCsrssPID, &Process );
	if ( !NT_SUCCESS( res ) )
	{
		DBGPRINT( "[ DestroyShadowSSDT ] PsLookupProcessByProcessId failed 0x%X\n", res );
		return;
	}

	KAPC_STATE apc{ };
	KeStackAttachProcess( Process, &apc );

	if ( !UnhookSSSDT( oNtUserFindWindowEx, SYSCALL_NTUSERFINDWNDEX ) )
		DBGPRINT( "Failed to unhook NtUserFindWindowEx!\n" );

	if ( !UnhookSSSDT( oNtUserWindowFromPoint, SYSCALL_NTUSERWNDFROMPOINT ) )
		DBGPRINT( "Failed to unhook NtUserWindowFromPoint!\n" );

	if ( !UnhookSSSDT( oNtUserBuildHwndList, SYSCALL_NTUSERBUILDWNDLIST ) )
		DBGPRINT( "Failed to unhook NtUserBuildHwndList!\n" );

	if ( !UnhookSSSDT( oNtUserGetForegroundWindow, SYSCALL_NTGETFOREGROUNDWND ) )
		DBGPRINT( "Failed to unhook NtUserGetForegroundWindow!\n" );

	if ( !UnhookSSSDT( oNtUserQueryWindow, SYSCALL_NTUSERQUERYWND ) )
		DBGPRINT( "Failed to unhook NtUserQueryWindow!\n" );

	KeUnstackDetachProcess( &apc );
	ObDereferenceObject( Process );
#else
	if ( !kaspersky::is_klhk_loaded() )
		return;

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
#endif
}