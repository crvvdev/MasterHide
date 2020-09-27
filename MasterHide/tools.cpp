#include "stdafx.h"

PUCHAR ntdll = nullptr;
PUCHAR win32u = nullptr;

namespace masterhide
{
	namespace tools
	{
		bool GetProcessName( HANDLE PID, PUNICODE_STRING ProcessImageName )
		{
			KAPC_STATE apc{ };
			bool bReturn = false;

			if ( !ProcessImageName )
				return false;

			PEPROCESS Process = nullptr;
			auto status = PsLookupProcessByProcessId( PID, &Process );
			if ( !NT_SUCCESS( status ) )
				return false;

			KeStackAttachProcess( Process, &apc );

			//
			// Credits: iPower
			//
			wchar_t lpModuleName[ MAX_PATH ];
			status = ZwQueryVirtualMemory( NtCurrentProcess(), PsGetProcessSectionBaseAddress( Process ), ( MEMORY_INFORMATION_CLASS )2, lpModuleName, sizeof( lpModuleName ), NULL );
			if ( NT_SUCCESS( status ) )
			{
				PUNICODE_STRING pModuleName = ( PUNICODE_STRING )lpModuleName;
				if ( pModuleName->Length > 0 )
				{
					AllocateUnicodeString( ProcessImageName, pModuleName->MaximumLength );
					RtlCopyUnicodeString( ProcessImageName, pModuleName );
					bReturn = true;
				}
			}

			KeUnstackDetachProcess( &apc );
			ObDereferenceObject( Process );

			return bReturn;
		}

		bool GetProcessNameByPEPROCESS( PEPROCESS Process, PUNICODE_STRING ProcessImageName )
		{
			KAPC_STATE apc{ };
			bool bReturn = false;
			bool bAttached = false;

			if ( !ProcessImageName )
				return false;

			if ( Process != PsGetCurrentProcess() )
			{
				KeStackAttachProcess( Process, &apc );
				bAttached = true;
			}

			wchar_t lpModuleName[ MAX_PATH ];
			auto status = ZwQueryVirtualMemory( NtCurrentProcess(), PsGetProcessSectionBaseAddress( Process ), ( MEMORY_INFORMATION_CLASS )2, lpModuleName, sizeof( lpModuleName ), NULL );
			if ( NT_SUCCESS( status ) )
			{
				PUNICODE_STRING pModuleName = ( PUNICODE_STRING )lpModuleName;
				if ( pModuleName->Length > 0 )
				{
					AllocateUnicodeString( ProcessImageName, pModuleName->MaximumLength );
					RtlCopyUnicodeString( ProcessImageName, pModuleName );
					bReturn = true;
				}
			}

			if ( bAttached )
				KeUnstackDetachProcess( &apc );

			return bReturn;
		}

		PEPROCESS FindPEPROCESSById( PWCH wsName )
		{
			if ( !wsName )
				return nullptr;

			for ( unsigned i = 4; i < 0xFFFF; i += 0x4 )
			{
				PEPROCESS Process = nullptr;
				if ( !NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( i ), &Process ) ) )
					continue;

				UNICODE_STRING wsProcName{ };
				if ( !GetProcessNameByPEPROCESS( Process, &wsProcName ) )
				{
					ObDereferenceObject( Process );
					continue;
				}

				if ( wsProcName.Buffer && wcsstr( wsProcName.Buffer, wsName ) )
					return Process;

				ObDereferenceObject( Process );
			}
			return nullptr;
		}

		bool DumpMZ( PUCHAR pImageBase )
		{
			__try
			{
				if ( !pImageBase )
				{
					DBGPRINT( "[ DumpMZ ] Invalid image base!\n" );
					return false;
				}

				ProbeForRead( pImageBase, sizeof( pImageBase ), __alignof( pImageBase ) );

				PIMAGE_DOS_HEADER dos = PIMAGE_DOS_HEADER( pImageBase );
				if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
				{
					DBGPRINT( "[ DumpMZ ] Invalid DOS signature!\n" );
					return false;
				}

				PIMAGE_NT_HEADERS32 nt32 = PIMAGE_NT_HEADERS32( pImageBase + dos->e_lfanew );
				if ( nt32->Signature != IMAGE_NT_SIGNATURE )
				{
					DBGPRINT( "[ DumpMZ ] Invalid NT signature!\n" );
					return false;
				}

				ULONG uImageSize = NULL;

				if ( nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 )
				{
					uImageSize = nt32->OptionalHeader.SizeOfImage;
				}
				else
				{
					PIMAGE_NT_HEADERS64 nt64 = PIMAGE_NT_HEADERS64( pImageBase + dos->e_lfanew );
					uImageSize = nt64->OptionalHeader.SizeOfImage;
				}

				if ( KeGetCurrentIrql() != PASSIVE_LEVEL )
				{
					DBGPRINT( "[ DumpMZ ] Curerent IRQL too high for IO operations!\n" );
					return false;
				}

				DBGPRINT( "[ DumpMZ ] ImageBase: 0x%p\n", pImageBase );
				DBGPRINT( "[ DumpMZ ] ImageSize: 0x%X\n", uImageSize );

				wchar_t wsFilePath[ MAX_PATH ]{ };
				RtlStringCbPrintfW( wsFilePath, sizeof( wsFilePath ), L"\\SystemRoot\\Dumped_%p.dll", pImageBase );

				DBGPRINT( "[ DumpMZ ] Save Location: %ws\n", wsFilePath );

				UNICODE_STRING wsFinalPath{ };
				RtlInitUnicodeString( &wsFinalPath, wsFilePath );

				OBJECT_ATTRIBUTES oa{ };
				InitializeObjectAttributes( &oa, &wsFinalPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

				IO_STATUS_BLOCK io{ };
				HANDLE hFile{ };

				auto res = ZwCreateFile( &hFile, GENERIC_WRITE, &oa, &io, NULL,
					FILE_ATTRIBUTE_NORMAL,
					0,
					FILE_OVERWRITE_IF,
					FILE_SYNCHRONOUS_IO_NONALERT,
					NULL, 0 );

				if ( !NT_SUCCESS( res ) )
				{
					DBGPRINT( "[ DumpMZ ] ZwCreateFile failed 0x%X\n", res );
					return false;
				}

				res = ZwWriteFile( hFile, NULL, NULL, NULL, &io, pImageBase, uImageSize, NULL, NULL );
				if ( !NT_SUCCESS( res ) )
				{
					ZwClose( hFile );
					DBGPRINT( "[ DumpMZ ] ZwWriteFile failed 0x%X\n", res );
					return false;
				}

				DBGPRINT( "[ DumpMZ ] Dump success!\n" );
				ZwClose( hFile );
				return false;
			}
			__except ( EXCEPTION_EXECUTE_HANDLER )
			{
				return false;
			}
		}

		PIMAGE_SECTION_HEADER GetSectionHeader( const ULONG64 image_base, const char* section_name )
		{
			if ( !image_base || !section_name )
				return nullptr;

			const auto pimage_dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( image_base );
			const auto pimage_nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS64 >( image_base + pimage_dos_header->e_lfanew );

			auto psection = IMAGE_FIRST_SECTION( pimage_nt_headers );

			PIMAGE_SECTION_HEADER psection_hdr = nullptr;

			const auto NumberOfSections = pimage_nt_headers->FileHeader.NumberOfSections;

			for ( auto i = 0; i < NumberOfSections; ++i )
			{
				if ( strstr( ( char* )psection->Name, section_name ) )
				{
					psection_hdr = psection;
					break;
				}

				++psection;
			}

			return psection_hdr;
		}

		bool bDataCompare( const char* pdata, const char* bmask, const char* szmask )
		{
			for ( ; *szmask; ++szmask, ++pdata, ++bmask )
			{
				if ( *szmask == 'x' && *pdata != *bmask )
					return false;
			}

			return !*szmask;
		}

		ULONG64 InternalFindPattern( const ULONG64 base, const ULONG size, const char* bmask, const char* szmask )
		{
			for ( auto i = 0ul; i < size; ++i )
				if ( bDataCompare( PCHAR( base + i ), bmask, szmask ) )
					return base + i;

			return 0;
		}

		ULONG64 FindPatternKM( const char* szModuleName, const char* szsection, const char* bmask, const char* szmask )
		{
			if ( !szModuleName || !szsection || !bmask || !szmask )
				return 0;

			const auto module_base = ULONG64( GetModuleBase( szModuleName ) );

			if ( !module_base )
				return 0;

			const auto psection = GetSectionHeader( module_base, szsection );

			return psection ? InternalFindPattern( module_base + psection->VirtualAddress, psection->Misc.VirtualSize, bmask, szmask ) : 0;
		}

		PVOID GetImageTextSection( const ULONG64 uImageBase, ULONG* ulSectionSize )
		{
			if ( !uImageBase )
				return nullptr;

			const auto pText = GetSectionHeader( uImageBase, ".text" );
			if ( !pText )
				return nullptr;

			if ( ulSectionSize )
				*ulSectionSize = pText->Misc.VirtualSize;

			return PVOID( uImageBase + pText->VirtualAddress );
		}

		PVOID GetNtKernelBase()
		{
			return GetModuleBase( "\\SystemRoot\\System32\\ntoskrnl.exe" );
		}

		PVOID GetModuleBase( const char* szModule )
		{
			PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = nullptr;
			ULONG ulBytes = 0;
			PVOID pImageBase = nullptr;

			__try
			{
				auto status = ZwQuerySystemInformation( SystemModuleInformation, 0, ulBytes, &ulBytes );
				if ( !ulBytes )
				{
					DBGPRINT( "[ GetModuleBase ] ZwQuerySystemInformation failed 0x%X\n", status );
					return nullptr;
				}

				pSystemInfoBuffer = PSYSTEM_MODULE_INFORMATION( ExAllocatePoolWithTag( PagedPool, ulBytes, TAG ) );
				if ( !pSystemInfoBuffer )
				{
					DBGPRINT( "[ GetModuleBase ] ExAllocatePoolWithTag failed!\n" );
					return nullptr;
				}

				status = ZwQuerySystemInformation( SystemModuleInformation, pSystemInfoBuffer, ulBytes, &ulBytes );
				if ( !NT_SUCCESS( status ) )
				{
					DBGPRINT( "[ GetModuleBase ] ZwQuerySystemInformation[1] failed 0x%X\n", status );
					ExFreePoolWithTag( pSystemInfoBuffer, TAG );
					return nullptr;
				}

				for ( unsigned i = 0; i < pSystemInfoBuffer->ModulesCount; ++i )
				{
					auto Buff = &pSystemInfoBuffer->Modules[ i ];

					if ( !_stricmp( Buff->ImageName, szModule ) )
					{
						pImageBase = Buff->Base;
						break;
					}
				}
			}
			__finally
			{
				if ( pSystemInfoBuffer )
					ExFreePoolWithTag( pSystemInfoBuffer, TAG );
			}

			return pImageBase;
		}

		NTSTATUS LoadFile( PUNICODE_STRING FileName, PUCHAR* pImageBase )
		{
			if ( !FileName )
				return STATUS_INVALID_PARAMETER;

			OBJECT_ATTRIBUTES oa{ };
			InitializeObjectAttributes( &oa, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

			if ( KeGetCurrentIrql() != PASSIVE_LEVEL )
			{
				DBGPRINT( "[ LoadFile ] IRQL too high for IO operations!\n" );
				return STATUS_UNSUCCESSFUL;
			}

			HANDLE FileHandle = NULL;

			IO_STATUS_BLOCK IoStatusBlock{ };
			auto res = ZwCreateFile( &FileHandle,
				GENERIC_READ,
				&oa,
				&IoStatusBlock, NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL, 0 );

			if ( !NT_SUCCESS( res ) )
			{
				DBGPRINT( "[ LoadFile ] ZwCreateFile failed 0x%X\n", res );
				return STATUS_UNSUCCESSFUL;
			}

			FILE_STANDARD_INFORMATION StandardInformation{ };
			res = ZwQueryInformationFile( FileHandle, &IoStatusBlock, &StandardInformation, sizeof( FILE_STANDARD_INFORMATION ), FileStandardInformation );
			if ( !NT_SUCCESS( res ) )
			{
				DBGPRINT( "[ LoadFile ] ZwQueryInformationFile failed 0x%X\n", res );
				ZwClose( FileHandle );
				return STATUS_UNSUCCESSFUL;
			}

			auto FileSize = StandardInformation.EndOfFile.LowPart;
			auto FileBuffer = PUCHAR( ExAllocatePoolWithTag( NonPagedPool, FileSize, TAG ) );

			if ( !FileBuffer )
			{
				DBGPRINT( "[ LoadFile ] ExAllocatePoolWithTag failed\n" );
				ZwClose( FileHandle );
				return STATUS_SUCCESS;
			}

			LARGE_INTEGER li{ };
			res = ZwReadFile( FileHandle,
				NULL, NULL, NULL,
				&IoStatusBlock,
				FileBuffer,
				FileSize,
				&li, NULL );
			if ( !NT_SUCCESS( res ) )
			{
				DBGPRINT( "[ LoadFile ] ZwReadFile failed 0x%X\n", res );
				ExFreePoolWithTag( FileBuffer, TAG );
				ZwClose( FileHandle );
				return STATUS_SUCCESS;
			}

			auto dos = PIMAGE_DOS_HEADER( FileBuffer );
			if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
			{
				DBGPRINT( "[ LoadFile ] Invalid DOS signature!\n" );
				ExFreePoolWithTag( FileBuffer, TAG );
				ZwClose( FileHandle );
				return STATUS_SUCCESS;
			}

			auto nt = PIMAGE_NT_HEADERS64( FileBuffer + dos->e_lfanew );
			if ( nt->Signature != IMAGE_NT_SIGNATURE )
			{
				DBGPRINT( "[ LoadFile ] Invalid NT signature!\n" );
				ExFreePoolWithTag( FileBuffer, TAG );
				ZwClose( FileHandle );
				return STATUS_SUCCESS;
			}

			auto Image = PUCHAR( ExAllocatePoolWithTag( NonPagedPool, nt->OptionalHeader.SizeOfImage, TAG ) );
			if ( !Image )
			{
				DBGPRINT( "[ LoadFile ] ExAllocatePoolWithTag[1] failed!\n" );
				ExFreePoolWithTag( FileBuffer, TAG );
				ZwClose( FileHandle );
				return STATUS_SUCCESS;
			}

			memcpy( Image, FileBuffer, nt->OptionalHeader.SizeOfHeaders );

			auto pISH = IMAGE_FIRST_SECTION( nt );
			for ( unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++ )
				memcpy(
					Image + pISH[ i ].VirtualAddress,
					FileBuffer + pISH[ i ].PointerToRawData,
					pISH[ i ].SizeOfRawData );

			if ( pImageBase )
				*pImageBase = Image;

			ExFreePoolWithTag( FileBuffer, TAG );
			ZwClose( FileHandle );
			return STATUS_SUCCESS;
		}

		PVOID GetFunctionAddress( PVOID Module, LPCSTR FunctionName )
		{
			PIMAGE_DOS_HEADER pIDH;
			PIMAGE_NT_HEADERS pINH;
			PIMAGE_EXPORT_DIRECTORY pIED;

			PULONG Address, Name;
			PUSHORT Ordinal;

			ULONG i;

			pIDH = ( PIMAGE_DOS_HEADER )Module;
			pINH = ( PIMAGE_NT_HEADERS )( ( PUCHAR )Module + pIDH->e_lfanew );

			pIED = ( PIMAGE_EXPORT_DIRECTORY )( ( PUCHAR )Module + pINH->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

			Address = ( PULONG )( ( PUCHAR )Module + pIED->AddressOfFunctions );
			Name = ( PULONG )( ( PUCHAR )Module + pIED->AddressOfNames );

			Ordinal = ( PUSHORT )( ( PUCHAR )Module + pIED->AddressOfNameOrdinals );

			for ( i = 0; i < pIED->AddressOfFunctions; i++ )
			{
				if ( !strcmp( FunctionName, ( char* )Module + Name[ i ] ) )
				{
					return ( PVOID )( ( PUCHAR )Module + Address[ Ordinal[ i ] ] );
				}
			}

			return NULL;
		}

		ULONG GetNtSyscall( LPCSTR FunctionName )
		{
			if ( !ntdll )
			{
				UNICODE_STRING FileName = RTL_CONSTANT_STRING( L"\\SystemRoot\\System32\\ntdll.dll" );

				auto res = LoadFile( &FileName, &ntdll );
				if ( !NT_SUCCESS( res ) )
					DBGPRINT( "[ GetNtSyscall ] Failed to load ntdll.dll 0x%X\n", res )
			}

			if ( ntdll )
			{
				auto Fn = PUCHAR( GetFunctionAddress( ntdll, FunctionName ) );
				if ( Fn )
				{
					for ( int i = 0; i < 24; ++i )
					{
						if ( Fn[ i ] == 0xC2 || Fn[ i ] == 0xC3 )
							break;

						if ( Fn[ i ] == 0xB8 )
							return *( PULONG )( Fn + i + 1 );
					}
				}
			}
			return 0;
		}

		ULONG GetWin32Syscall( LPCSTR FunctionName )
		{
			if ( !win32u )
			{
				UNICODE_STRING FileName = RTL_CONSTANT_STRING( L"\\SystemRoot\\System32\\win32u.dll" );

				auto res = LoadFile( &FileName, &win32u );
				if ( !NT_SUCCESS( res ) )
					DBGPRINT( "[ GetWin32Syscall ] Failed to load win32u.dll 0x%X\n", res )
			}

			if ( win32u )
			{
				auto Fn = PUCHAR( GetFunctionAddress( win32u, FunctionName ) );
				if ( Fn )
				{
					for ( int i = 0; i < 24; ++i )
					{
						if ( Fn[ i ] == 0xC2 || Fn[ i ] == 0xC3 )
							break;

						if ( Fn[ i ] == 0xB8 )
							return *( PULONG )( Fn + i + 1 );
					}
				}
			}
			return 0;
		}

		void UnloadImages()
		{
			if ( ntdll )
				ExFreePoolWithTag( ntdll, TAG );

			if ( win32u )
				ExFreePoolWithTag( win32u, TAG );
		}
	};
};

namespace masterhide
{
	namespace utils
	{
		KIRQL WPOFF()
		{
			KIRQL Irql = KeRaiseIrqlToDpcLevel();
			UINT_PTR cr0 = __readcr0();

			cr0 &= ~0x10000;
			__writecr0( cr0 );
			_disable();

			return Irql;
		}

		void WPON( KIRQL Irql )
		{
			UINT_PTR cr0 = __readcr0();

			cr0 |= 0x10000;
			_enable();
			__writecr0( cr0 );

			KeLowerIrql( Irql );
		}

		const PUCHAR FindCodeCave( PUCHAR Code, ULONG ulCodeSize, size_t CaveLength )
		{
			for ( unsigned i = 0, j = 0; i < ulCodeSize; i++ )
			{
				if ( Code[ i ] == 0x90 || Code[ i ] == 0xCC )
					j++;
				else
					j = 0;

				if ( j == CaveLength )
					return PUCHAR( ( ULONG_PTR )Code + i - CaveLength + 1 );
			}
			return nullptr;
		}
	}
};