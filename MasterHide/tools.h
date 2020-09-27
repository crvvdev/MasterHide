#pragma once

#define SYSCALL_INDEX( a )	( *( PULONG )( ( PUCHAR )a + 1 ) )

inline void AllocateUnicodeString( PUNICODE_STRING us, USHORT Size )
{
	if ( !us )
		return;

	__try
	{
		us->Length = 0;
		us->MaximumLength = 0;
		us->Buffer = PWSTR( ExAllocatePoolWithTag( NonPagedPool, Size, TAG ) );
		if ( us->Buffer )
		{
			us->Length = 0;
			us->MaximumLength = Size;
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER ) { }
}

inline void FreeUnicodeString( PUNICODE_STRING us )
{
	if ( !us )
		return;

	__try
	{
		if ( us->MaximumLength > 0 && us->Buffer )
			ExFreePoolWithTag( us->Buffer, TAG );

		us->Length = 0;
		us->MaximumLength = 0;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER ) { }
}

namespace masterhide
{
	namespace utils
	{
		extern KIRQL WPOFF();
		extern void WPON( KIRQL Irql );
		extern const PUCHAR FindCodeCave( PUCHAR Code, ULONG ulCodeSize, size_t CaveLength );
	}
};

namespace masterhide
{
	namespace tools
	{
		//
		// Tools
		//
		extern ULONG64 FindPatternKM( const char* szModuleName, const char* szsection, const char* bmask, const char* szmask );
		extern bool GetProcessName( HANDLE PID, PUNICODE_STRING wsProcessName );
		extern bool GetProcessNameByPEPROCESS( PEPROCESS Process, PUNICODE_STRING ProcessImageName );
		extern PVOID GetNtKernelBase();
		extern PVOID GetModuleBase( const char* szModule );
		extern PEPROCESS FindPEPROCESSById( PWCH wsName );

		inline void SwapEndianness( PCHAR ptr, size_t size )
		{
			struct u16
			{
				UCHAR high;
				UCHAR low;
			};

			for ( u16* pStruct = ( u16* )ptr; pStruct < ( u16* )ptr + size / 2; pStruct++ )
			{
				auto tmp = pStruct->low;
				pStruct->low = pStruct->high;
				pStruct->high = tmp;
			}
		}

		//
		// Helpers
		//
		extern ULONG GetNtSyscall( LPCSTR FunctionName );
		extern ULONG GetWin32Syscall( LPCSTR FunctionName );
		extern PVOID GetImageTextSection( const ULONG64 uImageBase, ULONG* ulSectionSize );

		//
		// Misc
		//
		extern bool DumpMZ( PUCHAR pImageBase );
		extern void UnloadImages();
	}
}