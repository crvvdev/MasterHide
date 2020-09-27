#include "stdafx.h"

namespace masterhide
{
	namespace tools
	{
		bool IsProtectedProcess( HANDLE PID )
		{
			UNICODE_STRING wsProcName{ };
			if ( !GetProcessName( PID, &wsProcName ) )
				return false;

			bool bResult = false;
			if ( wsProcName.Buffer )
			{
				for ( int i = 0; i < ARRAYSIZE( globals::wsProtectedProcesses ); ++i )
				{
					if ( wcsstr( wsProcName.Buffer, globals::wsProtectedProcesses[ i ] ) )
					{
						bResult = true;
						break;
					}
				}
				FreeUnicodeString( &wsProcName );
			}
			return bResult;
		}

		bool IsProtectedProcess( PWCH Buffer )
		{
			if ( !Buffer )
				return false;

			for ( int i = 0; i < ARRAYSIZE( globals::wsProtectedProcesses ); ++i )
			{
				if ( wcsstr( Buffer, globals::wsProtectedProcesses[ i ] ) )
				{
					return true;
				}
			}
			return false;
		}

		bool IsProtectedProcessEx( PEPROCESS Process )
		{
			UNICODE_STRING wsProcName{ };
			if ( !GetProcessNameByPEPROCESS( Process, &wsProcName ) )
				return false;

			bool bResult = false;
			if ( wsProcName.Buffer )
			{
				for ( int i = 0; i < ARRAYSIZE( globals::wsProtectedProcesses ); ++i )
				{
					if ( wcsstr( wsProcName.Buffer, globals::wsProtectedProcesses[ i ] ) )
					{
						bResult = true;
						break;
					}
				}
				FreeUnicodeString( &wsProcName );
			}
			return bResult;
		}

		bool IsMonitoredProcess( HANDLE PID )
		{
			UNICODE_STRING wsProcName{ };
			if ( !GetProcessName( PID, &wsProcName ) )
				return false;

			bool bResult = false;
			if ( wsProcName.Buffer )
			{
				for ( int i = 0; i < ARRAYSIZE( globals::wsMonitoredProcesses ); ++i )
				{
					if ( wcsstr( wsProcName.Buffer, globals::wsMonitoredProcesses[ i ] ) )
					{
						bResult = true;
						break;
					}
				}
				FreeUnicodeString( &wsProcName );
			}
			return bResult;
		}

		bool IsMonitoredProcessEx( PEPROCESS Process )
		{
			UNICODE_STRING wsProcName{ };
			if ( !GetProcessNameByPEPROCESS( Process, &wsProcName ) )
				return false;

			bool bResult = false;
			if ( wsProcName.Buffer )
			{
				for ( int i = 0; i < ARRAYSIZE( globals::wsMonitoredProcesses ); ++i )
				{
					if ( wcsstr( wsProcName.Buffer, globals::wsMonitoredProcesses[ i ] ) )
					{
						bResult = true;
						break;
					}
				}
				FreeUnicodeString( &wsProcName );
			}
			return bResult;
		}

		bool IsBlacklistedProcess( HANDLE PID )
		{
			UNICODE_STRING wsProcName{ };
			if ( !GetProcessName( PID, &wsProcName ) )
				return false;

			bool bResult = false;
			if ( wsProcName.Buffer )
			{
				for ( int i = 0; i < ARRAYSIZE( globals::wsBlacklistedProcessess ); ++i )
				{
					if ( wcsstr( wsProcName.Buffer, globals::wsBlacklistedProcessess[ i ] ) )
					{
						bResult = true;
						break;
					}
				}
				FreeUnicodeString( &wsProcName );
			}
			return bResult;
		}

		bool IsBlacklistedProcessEx( PEPROCESS Process )
		{
			UNICODE_STRING wsProcName{ };
			if ( !GetProcessNameByPEPROCESS( Process, &wsProcName ) )
				return false;

			bool bResult = false;
			if ( wsProcName.Buffer )
			{
				for ( int i = 0; i < ARRAYSIZE( globals::wsBlacklistedProcessess ); ++i )
				{
					if ( wcsstr( wsProcName.Buffer, globals::wsBlacklistedProcessess[ i ] ) )
					{
						bResult = true;
						break;
					}
				}
				FreeUnicodeString( &wsProcName );
			}
			return bResult;
		}
	}
};

NtOpenProcess_ oNtOpenProcess = NULL;
NTSTATUS NTAPI hkNtOpenProcess( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId )
{
	const auto ret = oNtOpenProcess( ProcessHandle, DesiredAccess, ObjectAttributes, ClientId );
	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) || tools::IsProtectedProcess( PsGetCurrentProcessId() ) )
		return ret;

	if ( NT_SUCCESS( ret ) )
	{
		if ( tools::IsBlacklistedProcess( PsGetCurrentProcessId() ) )
		{
			if ( tools::IsProtectedProcess( ClientId->UniqueProcess ) )
			{
				DBGPRINT( "Denying access from PID %p to PID %p\n", PsGetCurrentProcessId(), ClientId->UniqueProcess );
				ZwClose( *ProcessHandle );
				*ProcessHandle = HANDLE( -1 );
				return STATUS_ACCESS_DENIED;
			}
		}

		if ( tools::IsMonitoredProcess( ClientId->UniqueProcess ) )
		{
			UNICODE_STRING wsProcName{ };
			if ( tools::GetProcessName( ClientId->UniqueProcess, &wsProcName ) )
			{
				if ( wsProcName.Buffer )
				{
					auto ShortName = wcsrchr( wsProcName.Buffer, '\\' );
					DBGPRINT( "[ OP ] PID %p is opening a handle with access mask 0x%X to process %ws\n", PsGetCurrentProcessId(), DesiredAccess, ShortName );
					FreeUnicodeString( &wsProcName );
				}
			}
		}
	}
	return ret;
}

NtWriteVirtualMemory_ oNtWriteVirtualMemory = NULL;
NTSTATUS NTAPI hkNtWriteVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten )
{
	const auto res = oNtWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten );
	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) || tools::IsProtectedProcess( PsGetCurrentProcessId() ) )
		return res;

	if ( NT_SUCCESS( res ) )
	{
		//
		// Get Name from handle
		// 
		PEPROCESS Process = nullptr;
		auto ret = ObReferenceObjectByHandle( ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), ( PVOID* )&Process, nullptr );
		if ( !NT_SUCCESS( ret ) )
			return res;

		if ( tools::IsMonitoredProcessEx( Process ) )
		{
			UNICODE_STRING wsProcName{ };
			if ( tools::GetProcessName( PsGetCurrentProcessId(), &wsProcName ) )
			{
				if ( wsProcName.Buffer )
				{
					auto ShortName = wcsrchr( wsProcName.Buffer, '\\' );
					DBGPRINT( "[ WPM ] From: %p to %ws with BaseAddress 0x%p Buffer 0x%p Length %d\n", PsGetCurrentProcessId(), ShortName, BaseAddress, Buffer, NumberOfBytesToWrite );
					FreeUnicodeString( &wsProcName );
				}
			}
		}

		ObDereferenceObject( Process );
	}
	return res;
}

NtAllocateVirtualMemory_ oNtAllocateVirtualMemory = NULL;
NTSTATUS NTAPI hkNtAllocateVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect )
{
	const auto res = oNtAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect );
	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) || tools::IsProtectedProcess( PsGetCurrentProcessId() ) )
		return res;

	if ( NT_SUCCESS( res ) && BaseAddress && RegionSize && *RegionSize >= 0x1000 )
	{
		//
		// Get Name from handle
		// 
		PEPROCESS Process = nullptr;
		auto ret = ObReferenceObjectByHandle( ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), ( PVOID* )&Process, nullptr );
		if ( !NT_SUCCESS( ret ) )
			return res;

		if ( tools::IsMonitoredProcessEx( Process ) )
		{
			UNICODE_STRING wsProcName{ };
			if ( tools::GetProcessName( PsGetCurrentProcessId(), &wsProcName ) )
			{
				if ( wsProcName.Buffer )
				{
					auto ShortName = wcsrchr( wsProcName.Buffer, '\\' );
					DBGPRINT( "[ AVM ] From: %p to %ws with BaseAddress 0x%p Length 0x%llx Type 0x%X Protect 0x%X\n", PsGetCurrentProcessId(), ShortName, *BaseAddress, *RegionSize, AllocationType, Protect );
					FreeUnicodeString( &wsProcName );
				}
			}
		}

		ObDereferenceObject( Process );
	}
	return res;
}

NtFreeVirtualMemory_ oNtFreeVirtualMemory = NULL;
NTSTATUS NTAPI hkNtFreeVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType )
{
	const auto res = oNtFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeType );
	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) || tools::IsProtectedProcess( PsGetCurrentProcessId() ) )
		return res;

	if ( NT_SUCCESS( res ) && BaseAddress && RegionSize && *RegionSize >= 0x1000 )
	{
		//
		// Get Name from handle
		// 
		PEPROCESS Process = nullptr;
		auto ret = ObReferenceObjectByHandle( ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), ( PVOID* )&Process, nullptr );
		if ( !NT_SUCCESS( ret ) )
			return res;

		if ( tools::IsMonitoredProcessEx( Process ) )
		{
			UNICODE_STRING wsProcName{ };
			if ( tools::GetProcessName( PsGetCurrentProcessId(), &wsProcName ) )
			{
				if ( wsProcName.Buffer )
				{
					auto ShortName = wcsrchr( wsProcName.Buffer, '\\' );
					DBGPRINT( "[ FVM ] From: %p to %ws with BaseAddress 0x%p Length 0x%llx FreeType 0x%X\n", PsGetCurrentProcessId(), ShortName, *BaseAddress, *RegionSize, FreeType );
					tools::DumpMZ( PUCHAR( *BaseAddress ) );
					FreeUnicodeString( &wsProcName );
				}
			}
		}

		ObDereferenceObject( Process );
	}
	return res;
}

NtDeviceIoControlFile_ oNtDeviceIoControlFile = NULL;
NTSTATUS NTAPI hkNtDeviceIoControlFile( HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	const auto ret = oNtDeviceIoControlFile( FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength );

	//
	// If the callee process is a protected process we ignore it
	//
	if ( !tools::IsBlacklistedProcess( PsGetCurrentProcessId() ) )
		return ret;

	if ( NT_SUCCESS( ret ) )
	{
		const auto szNewModel = globals::szFakeModels[ 0 ];
		wchar_t wsProcess[ MAX_PATH ] = L"\\Unknown";

		UNICODE_STRING wsProcName{ };
		if ( tools::GetProcessName( PsGetCurrentProcessId(), &wsProcName ) )
		{
			if ( wsProcName.Buffer )
			{
				wcscpy_s( wsProcess, wsProcName.Buffer );
				FreeUnicodeString( &wsProcName );
			}
		}

		auto ShortName = wcsrchr( wsProcess, '\\' );

		__try
		{
			//
			// Hardware Spoofing
			//
			switch ( IoControlCode )
			{

			case IOCTL_STORAGE_QUERY_PROPERTY:
			{
				PSTORAGE_PROPERTY_QUERY Query = PSTORAGE_PROPERTY_QUERY( InputBuffer );
				if ( Query && Query->PropertyId == StorageDeviceProperty )
				{
					if ( OutputBufferLength >= sizeof( STORAGE_DEVICE_DESCRIPTOR ) )
					{
						PSTORAGE_DEVICE_DESCRIPTOR Desc = PSTORAGE_DEVICE_DESCRIPTOR( OutputBuffer );
						if ( Desc )
						{
							if ( Desc->SerialNumberOffset )
							{
								auto Serial = PCHAR( Desc ) + Desc->SerialNumberOffset;
								DBGPRINT( "%ws Spoofing Serial ( 0x%X ) Old: %s New: %s\n", ShortName, IoControlCode, Serial, globals::szFakeSerial );
								memset( Serial, 0, strlen( Serial ) );
								strcpy( Serial, globals::szFakeSerial );
							}

							if ( Desc->ProductIdOffset )
							{
								auto Model = PCHAR( Desc ) + Desc->ProductIdOffset;
								DBGPRINT( "%ws Spoofing Model ( 0x%X ) Old: %s New: %s\n", ShortName, IoControlCode, Model, szNewModel );
								memset( Model, 0, strlen( Model ) );
								strcpy( Model, szNewModel );
							}
						}
					}
				}
				break;
			}

			case IOCTL_ATA_PASS_THROUGH:
			{
				if ( OutputBufferLength >= sizeof( ATA_PASS_THROUGH_EX ) + sizeof( PIDENTIFY_DEVICE_DATA ) )
				{
					PATA_PASS_THROUGH_EX Ata = PATA_PASS_THROUGH_EX( OutputBuffer );
					if ( Ata && Ata->DataBufferOffset )
					{
						PIDENTIFY_DEVICE_DATA Identify = PIDENTIFY_DEVICE_DATA( PCHAR( OutputBuffer ) + Ata->DataBufferOffset );
						if ( Identify )
						{
							auto Serial = PCHAR( Identify->SerialNumber );
							if ( strlen( Serial ) > 0 )
							{
								tools::SwapEndianness( Serial, sizeof( Identify->SerialNumber ) );

								DBGPRINT( "%ws Spoofing Serial ( 0x%X ) Old: %s New: %s\n", ShortName, IoControlCode, Serial, globals::szFakeSerial );
								memset( Serial, 0, strlen( Serial ) );
								strcpy( Serial, globals::szFakeSerial );

								tools::SwapEndianness( Serial, sizeof( Identify->SerialNumber ) );
							}

							auto Model = PCHAR( Identify->ModelNumber );
							if ( strlen( Model ) > 0 )
							{
								// Fix invalid characters.
								Model[ sizeof( Identify->ModelNumber ) - 1 ] = 0;
								Model[ sizeof( Identify->ModelNumber ) - 2 ] = 0;

								tools::SwapEndianness( Model, sizeof( Identify->ModelNumber ) - 2 );

								DBGPRINT( "%ws Spoofing Model ( 0x%X ) Old: %s New: %s\n", ShortName, IoControlCode, Model, szNewModel );
								memset( Model, 0, strlen( Model ) );
								strcpy( Model, szNewModel );

								tools::SwapEndianness( Model, sizeof( Identify->ModelNumber ) - 2 );
							}
						}
					}
				}
				break;
			}

			case SMART_RCV_DRIVE_DATA:
			{
				if ( OutputBufferLength >= sizeof( SENDCMDOUTPARAMS ) )
				{
					PSENDCMDOUTPARAMS Cmd = PSENDCMDOUTPARAMS( OutputBuffer );
					if ( Cmd )
					{
						PIDSECTOR Sector = PIDSECTOR( Cmd->bBuffer );
						if ( Sector )
						{
							auto Serial = PCHAR( Sector->sSerialNumber );
							if ( strlen( Serial ) > 0 )
							{
								tools::SwapEndianness( Serial, sizeof( Sector->sSerialNumber ) );

								DBGPRINT( "%ws Spoofing Serial ( 0x%X ) Old: %s New: %s\n", ShortName, IoControlCode, Serial, globals::szFakeSerial );
								memset( Serial, 0, strlen( Serial ) );
								strcpy( Serial, globals::szFakeSerial );

								tools::SwapEndianness( Serial, sizeof( Sector->sSerialNumber ) );
							}

							auto Model = PCHAR( Sector->sModelNumber );
							if ( strlen( Model ) > 0 )
							{
								// Fix invalid characters.
								Model[ sizeof( Sector->sModelNumber ) - 1 ] = 0;
								Model[ sizeof( Sector->sModelNumber ) - 2 ] = 0;

								tools::SwapEndianness( Model, sizeof( Sector->sModelNumber ) - 2 );

								DBGPRINT( "%ws Spoofing Model ( 0x%X ) Old: %s New: %s\n", ShortName, IoControlCode, Model, szNewModel );
								memset( Model, 0, strlen( Model ) );
								strcpy( Model, szNewModel );

								tools::SwapEndianness( Model, sizeof( Sector->sModelNumber ) - 2 );
							}
						}
					}
				}
				break;
			}

			case IOCTL_DISK_GET_PARTITION_INFO_EX:
			{
				if ( OutputBufferLength >= sizeof( PARTITION_INFORMATION_EX ) )
				{
					PPARTITION_INFORMATION_EX PartInfo = PPARTITION_INFORMATION_EX( OutputBuffer );
					if ( PartInfo && PartInfo->PartitionStyle == PARTITION_STYLE_GPT )
					{
						DBGPRINT( "%ws Zero'ing partition GUID (EX)\n", ShortName );
						memset( &PartInfo->Gpt.PartitionId, 0, sizeof( GUID ) );
					}
				}
				break;
			}

			case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
			{
				if ( OutputBufferLength >= sizeof( DRIVE_LAYOUT_INFORMATION_EX ) )
				{
					PDRIVE_LAYOUT_INFORMATION_EX LayoutInfo = PDRIVE_LAYOUT_INFORMATION_EX( OutputBuffer );
					if ( LayoutInfo && LayoutInfo->PartitionStyle == PARTITION_STYLE_GPT )
					{
						DBGPRINT( "%ws Zero'ing partition GUID\n", ShortName );
						memset( &LayoutInfo->Gpt.DiskId, 0, sizeof( GUID ) );
					}
				}
				break;
			}

			case IOCTL_MOUNTMGR_QUERY_POINTS:
			{
				if ( OutputBufferLength >= sizeof( MOUNTMGR_MOUNT_POINTS ) )
				{
					PMOUNTMGR_MOUNT_POINTS Points = PMOUNTMGR_MOUNT_POINTS( OutputBuffer );
					if ( Points )
					{
						DBGPRINT( "%ws Spoofing mounted points\n", ShortName );
						for ( unsigned i = 0; i < Points->NumberOfMountPoints; ++i )
						{
							auto Point = &Points->MountPoints[ i ];

							if ( Point->UniqueIdOffset )
								Point->UniqueIdLength = 0;

							if ( Point->SymbolicLinkNameOffset )
								Point->SymbolicLinkNameLength = 0;
						}
					}
				}
				break;
			}

			case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
			{
				if ( OutputBufferLength >= sizeof( MOUNTDEV_UNIQUE_ID ) )
				{
					PMOUNTDEV_UNIQUE_ID UniqueId = PMOUNTDEV_UNIQUE_ID( OutputBuffer );
					if ( UniqueId )
					{
						DBGPRINT( "%ws Spoofing mounted unique id\n", ShortName );
						UniqueId->UniqueIdLength = 0;
					}
				}
				break;
			}

			case IOCTL_NDIS_QUERY_GLOBAL_STATS:
			{
				switch ( *( PDWORD )InputBuffer )
				{
				case OID_802_3_PERMANENT_ADDRESS:
				case OID_802_3_CURRENT_ADDRESS:
				case OID_802_5_PERMANENT_ADDRESS:
				case OID_802_5_CURRENT_ADDRESS:
					DBGPRINT( "%ws Spoofing permanent MAC\n", ShortName );
					memcpy( OutputBuffer, globals::szFakeMAC, sizeof( globals::szFakeMAC ) );
					break;
				}
			}

			}
		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{

		}
	}
	return ret;
}

NtQuerySystemInformation_ oNtQuerySystemInformation = NULL;
NTSTATUS NTAPI hkNtQuerySystemInformation( SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length, PULONG ReturnLength )
{
	const auto ret = oNtQuerySystemInformation( SystemInformationClass, Buffer, Length, ReturnLength );

	//
	// If the callee process is a protected process we ignore it
	//
	if ( tools::IsProtectedProcess( PsGetCurrentProcessId() ) )
		return ret;

	if ( NT_SUCCESS( ret ) )
	{
		//
		// Hide from Driver list
		// 
		if ( SystemInformationClass == SystemModuleInformation )
		{
			const auto pModule = PRTL_PROCESS_MODULES( Buffer );
			const auto pEntry = &pModule->Modules[ 0 ];

			for ( unsigned i = 0; i < pModule->NumberOfModules; ++i )
			{
				if ( pEntry[ i ].ImageBase && pEntry[ i ].ImageSize && strlen( ( char* )pEntry[ i ].FullPathName ) > 2 )
				{
					for ( int x = 0; x < ARRAYSIZE( globals::szProtectedDrivers ); ++x )
					{
						if ( strstr( ( char* )pEntry[ i ].FullPathName, globals::szProtectedDrivers[ x ] ) )
						{
							const auto next_entry = i + 1;

							if ( next_entry < pModule->NumberOfModules )
								memcpy( &pEntry[ i ], &pEntry[ next_entry ], sizeof( RTL_PROCESS_MODULE_INFORMATION ) );
							else
							{
								memset( &pEntry[ i ], 0, sizeof( RTL_PROCESS_MODULE_INFORMATION ) );
								pModule->NumberOfModules--;
							}
						}
					}
				}
			}
		}
		//
		// Hide from Process list
		//
		else if (
			SystemInformationClass == SystemProcessInformation ||
			SystemInformationClass == SystemSessionProcessInformation ||
			SystemInformationClass == SystemExtendedProcessInformation )
		{
			PSYSTEM_PROCESS_INFO pCurr = NULL;
			PSYSTEM_PROCESS_INFO pNext = PSYSTEM_PROCESS_INFO( Buffer );

			while ( pNext->NextEntryOffset != 0 )
			{
				pCurr = pNext;
				pNext = ( PSYSTEM_PROCESS_INFO )( ( PUCHAR )pCurr + pCurr->NextEntryOffset );

				//
				// Erase our protected processes from the list
				//
				if ( pNext->ImageName.Buffer && tools::IsProtectedProcess( pNext->ImageName.Buffer ) )
				{
					if ( pNext->NextEntryOffset == 0 )
					{
						pCurr->NextEntryOffset = 0;
					}
					else
					{
						pCurr->NextEntryOffset += pNext->NextEntryOffset;
					}

					pNext = pCurr;
				}
			}
		}
		//
		// Hide from handle list
		//
		else if ( SystemInformationClass == SystemHandleInformation )
		{
			if ( tools::IsBlacklistedProcess( PsGetCurrentProcessId() ) )
			{
				const auto pHandle = PSYSTEM_HANDLE_INFORMATION( Buffer );
				const auto pEntry = &pHandle->Information[ 0 ];

				for ( unsigned i = 0; i < pHandle->NumberOfHandles; ++i )
				{
					if ( tools::IsProtectedProcess( ULongToHandle( pEntry[ i ].ProcessId ) ) )
					{
						const auto next_entry = i + 1;

						if ( next_entry < pHandle->NumberOfHandles )
							memcpy( &pEntry[ i ], &pEntry[ next_entry ], sizeof( SYSTEM_HANDLE ) );
						else
						{
							memset( &pEntry[ i ], 0, sizeof( SYSTEM_HANDLE ) );
							pHandle->NumberOfHandles--;
						}
					}
				}
			}
		}
		else if ( SystemInformationClass == SystemExtendedHandleInformation )
		{
			if ( tools::IsBlacklistedProcess( PsGetCurrentProcessId() ) )
			{
				const auto pHandle = PSYSTEM_HANDLE_INFORMATION_EX( Buffer );
				const auto pEntry = &pHandle->Information[ 0 ];

				for ( unsigned i = 0; i < pHandle->NumberOfHandles; ++i )
				{
					if ( tools::IsProtectedProcess( ULongToHandle( pEntry[ i ].ProcessId ) ) )
					{
						const auto next_entry = i + 1;

						if ( next_entry < pHandle->NumberOfHandles )
							memcpy( &pEntry[ i ], &pEntry[ next_entry ], sizeof( SYSTEM_HANDLE ) );
						else
						{
							memset( &pEntry[ i ], 0, sizeof( SYSTEM_HANDLE ) );
							pHandle->NumberOfHandles--;
						}
					}
				}
			}
		}
		//
		// Spoof code integrity status
		//
		else if ( SystemInformationClass == SystemCodeIntegrityInformation )
		{
			PSYSTEM_CODEINTEGRITY_INFORMATION Integrity = PSYSTEM_CODEINTEGRITY_INFORMATION( Buffer );

			// Spoof test sign flag if present
			if ( Integrity->CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN )
				Integrity->CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_TESTSIGN;

			// Set as always enabled.
			Integrity->CodeIntegrityOptions |= CODEINTEGRITY_OPTION_ENABLED;
		}
	}
	return ret;
}

NtLoadDriver_ oNtLoadDriver = NULL;
NTSTATUS NTAPI hkNtLoadDriver( PUNICODE_STRING DriverServiceName )
{
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	bool bLoad = true;

	if ( DriverServiceName && DriverServiceName->Buffer )
	{
		/*

		For example:

		if ( wcsstr( DriverServiceName->Buffer, L"BEDaisy.sys" ) )
			bLoad = false;

		Loading will be blocked.
		*/
	}

	if ( bLoad )
	{
		ret = oNtLoadDriver( DriverServiceName );
		if ( NT_SUCCESS( ret ) )
			DBGPRINT( "Loading Driver: %ws\n", DriverServiceName->Buffer );
	}
	return ret;
}

NtUserWindowFromPoint_ oNtUserWindowFromPoint = NULL;
HWND NTAPI hkNtUserWindowFromPoint( LONG x, LONG y )
{
	const auto res = oNtUserWindowFromPoint( x, y );

	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) )
		return res;

	if ( !tools::IsBlacklistedProcessEx( PsGetCurrentProcess() ) )
		return res;

	return 0;
}

NtUserQueryWindow_ oNtUserQueryWindow = NULL;
HANDLE NTAPI hkNtUserQueryWindow( HWND WindowHandle, HANDLE TypeInformation )
{
	const auto res = oNtUserQueryWindow( WindowHandle, TypeInformation );

	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) )
		return res;

	if ( !tools::IsBlacklistedProcessEx( PsGetCurrentProcess() ) )
		return res;

	auto PID = oNtUserQueryWindow( WindowHandle, 0 );
	if ( tools::IsProtectedProcess( PID ) )
		return 0;

	return res;
}

NtUserFindWindowEx_ oNtUserFindWindowEx = NULL;
HWND NTAPI hkNtUserFindWindowEx( HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType )
{
	const auto res = oNtUserFindWindowEx( hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType );

	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) )
		return res;

	if ( !tools::IsBlacklistedProcessEx( PsGetCurrentProcess() ) )
		return res;

	if ( res )
	{
		auto PID = oNtUserQueryWindow( res, 0 );
		if ( tools::IsProtectedProcess( PID ) )
		{
			return NULL;
		}
	}
	return res;
}

NtUserBuildHwndList_ oNtUserBuildHwndList = NULL;
NTSTATUS NTAPI hkNtUserBuildHwndList( HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded )
{
	const auto res = oNtUserBuildHwndList( hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded );

	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) )
		return res;

	if ( !tools::IsBlacklistedProcessEx( PsGetCurrentProcess() ) )
		return res;

	if ( fEnumChildren == 1 )
	{
		auto PID = oNtUserQueryWindow( hwndNext, 0 );
		if ( tools::IsProtectedProcess( PID ) )
			return STATUS_UNSUCCESSFUL;
	}

	if ( NT_SUCCESS( res ) )
	{
		ULONG i = 0;
		ULONG j;

		while ( i < *pcHwndNeeded )
		{
			auto PID = oNtUserQueryWindow( phwndFirst[ i ], 0 );
			if ( tools::IsProtectedProcess( PID ) )
			{
				for ( j = i; j < ( *pcHwndNeeded ) - 1; j++ )
					phwndFirst[ j ] = phwndFirst[ j + 1 ];
				phwndFirst[ *pcHwndNeeded - 1 ] = 0;
				( *pcHwndNeeded )--;
				continue;
			}
			i++;
		}
	}
	return res;
}

NtUserGetForegroundWindow_ oNtUserGetForegroundWindow = NULL;
HWND LastForeWnd = HWND( -1 );

HWND NTAPI hkNtUserGetForegroundWindow( VOID )
{
	const auto res = oNtUserGetForegroundWindow();

	if ( PsIsProtectedProcess( PsGetCurrentProcess() ) || PsIsSystemProcess( PsGetCurrentProcess() ) )
		return res;

	if ( !tools::IsBlacklistedProcessEx( PsGetCurrentProcess() ) )
		return res;

	auto PID = oNtUserQueryWindow( res, 0 );
	if ( tools::IsProtectedProcess( PID ) )
		return LastForeWnd;
	else
		LastForeWnd = res;

	return res;
}