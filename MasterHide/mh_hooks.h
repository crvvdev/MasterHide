#pragma once

//HARDCODED for Windows 7 x64 SP1 7601

//
// ntoskrnl.exe
//
static auto SYSCALL_NTUSERFINDWNDEX = 0x106e;
static auto SYSCALL_NTUSERWNDFROMPOINT = 0x1014;
static auto SYSCALL_NTUSERBUILDWNDLIST = 0x101c;
static auto SYSCALL_NTGETFOREGROUNDWND = 0x103c;
static auto SYSCALL_NTUSERQUERYWND = 0x1010;

//
// win32k.sys
//
static auto SYSCALL_NTQUERYSYSINFO = 0x0033;
static auto SYSCALL_NTOPENPROCESS = 0x0023;
static auto SYSCALL_NTALLOCVIRTUALMEM = 0x0015;
static auto SYSCALL_NTWRITEVIRTUALMEM = 0x0037;
static auto SYSCALL_NTFREEVIRTUALMEM = 0x001b;
static auto SYSCALL_NTDEVICEIOCTRLFILE = 0x0004;
static auto SYSCALL_NTLOADDRIVER = 0x0004;

namespace masterhide
{
	namespace tools
	{
		extern bool IsProtectedProcess( HANDLE PID );
		extern bool IsProtectedProcess( PWCH Buffer );
		extern bool IsProtectedProcessEx( PEPROCESS Process );
		extern bool IsMonitoredProcess( HANDLE PID );
		extern bool IsMonitoredProcessEx( PEPROCESS Process );
		extern bool IsBlacklistedProcess( HANDLE PID );
		extern bool IsBlacklistedProcessEx( PEPROCESS Process );
	}
};

//
// ntoskrnl.exe hooks
//
using NtQuerySystemInformation_ = NTSTATUS( NTAPI* )( SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG );
extern NtQuerySystemInformation_ oNtQuerySystemInformation;

NTSTATUS NTAPI hkNtQuerySystemInformation( SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length, PULONG ReturnLength );

using NtOpenProcess_ = NTSTATUS( NTAPI* ) ( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId );
extern NtOpenProcess_ oNtOpenProcess;

NTSTATUS NTAPI hkNtOpenProcess( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId );

using NtAllocateVirtualMemory_ = NTSTATUS( NTAPI* )( HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect );
extern NtAllocateVirtualMemory_ oNtAllocateVirtualMemory;

NTSTATUS NTAPI hkNtAllocateVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect );

using NtFreeVirtualMemory_ = NTSTATUS( NTAPI* )( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType );
extern NtFreeVirtualMemory_ oNtFreeVirtualMemory;

NTSTATUS NTAPI hkNtFreeVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType );

using NtWriteVirtualMemory_ = NTSTATUS( NTAPI* )( HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten );
extern NtWriteVirtualMemory_ oNtWriteVirtualMemory;

NTSTATUS NTAPI hkNtWriteVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten );

using NtDeviceIoControlFile_ = NTSTATUS( NTAPI* )( HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
extern NtDeviceIoControlFile_ oNtDeviceIoControlFile;

NTSTATUS NTAPI hkNtDeviceIoControlFile( HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );

using NtLoadDriver_ = NTSTATUS( NTAPI* )( PUNICODE_STRING DriverServiceName );
extern NtLoadDriver_ oNtLoadDriver;

NTSTATUS NTAPI hkNtLoadDriver( PUNICODE_STRING DriverServiceName );

//
// win32k.sys hooks
//
using NtUserWindowFromPoint_ = HWND( NTAPI* )( LONG, LONG );
extern NtUserWindowFromPoint_ oNtUserWindowFromPoint;

HWND hkNtUserWindowFromPoint( LONG x, LONG y );

using NtUserQueryWindow_ = HANDLE( NTAPI* )( HWND, HANDLE );
extern NtUserQueryWindow_ oNtUserQueryWindow;

HANDLE hkNtUserQueryWindow( HWND WindowHandle, HANDLE TypeInformation );

using NtUserFindWindowEx_ = HWND( NTAPI* )( HWND, HWND, PUNICODE_STRING, PUNICODE_STRING, DWORD );
extern NtUserFindWindowEx_ oNtUserFindWindowEx;

HWND NTAPI hkNtUserFindWindowEx( HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType );

using NtUserBuildHwndList_ = NTSTATUS( NTAPI* )( HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded );
extern NtUserBuildHwndList_ oNtUserBuildHwndList;

NTSTATUS NTAPI hkNtUserBuildHwndList( HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded );

using NtUserGetForegroundWindow_ = HWND( NTAPI* )( VOID );
extern NtUserGetForegroundWindow_ oNtUserGetForegroundWindow;

HWND NTAPI hkNtUserGetForegroundWindow( VOID );