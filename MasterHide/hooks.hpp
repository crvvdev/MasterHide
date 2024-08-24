#pragma once

namespace masterhide
{
namespace process
{
bool IsProtectedProcess(_In_ HANDLE processId);
bool IsProtectedProcess(_In_ LPCWSTR processName);
bool IsProtectedProcess(_In_ PEPROCESS process);
bool IsMonitoredProcess(_In_ HANDLE processId);
bool IsMonitoredProcess(_In_ PEPROCESS process);
bool IsBlacklistedProcess(_In_ HANDLE processId);
bool IsBlacklistedProcess(_In_ PEPROCESS process);
} // namespace process

namespace hooks
{
inline ERESOURCE g_resource{};

void WaitForHooksCompletion();

//
// SSDT Hooks
//
NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length,
                                          PULONG ReturnLength);
inline decltype(&hkNtQuerySystemInformation) oNtQuerySystemInformation = nullptr;

using NtOpenProcess_ = NTSTATUS(NTAPI *)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                         POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                               PCLIENT_ID ClientId);
inline decltype(&hkNtOpenProcess) oNtOpenProcess = nullptr;

NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                         PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
inline decltype(&hkNtAllocateVirtualMemory) oNtAllocateVirtualMemory = nullptr;

NTSTATUS NTAPI hkNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
inline decltype(&hkNtFreeVirtualMemory) oNtFreeVirtualMemory = nullptr;

NTSTATUS NTAPI hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,
                                      PULONG NumberOfBytesWritten);
inline decltype(&hkNtWriteVirtualMemory) oNtWriteVirtualMemory = nullptr;

NTSTATUS NTAPI hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                       PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
                                       ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
inline decltype(&hkNtDeviceIoControlFile) oNtDeviceIoControlFile = nullptr;

NTSTATUS NTAPI hkNtLoadDriver(PUNICODE_STRING DriverServiceName);
inline decltype(&hkNtLoadDriver) oNtLoadDriver = nullptr;

//
// Shadow SSDT hooks
//
HWND hkNtUserWindowFromPoint(LONG x, LONG y);
inline decltype(&hkNtUserWindowFromPoint) oNtUserWindowFromPoint = nullptr;

HANDLE hkNtUserQueryWindow(HWND WindowHandle, HANDLE TypeInformation);
inline decltype(&hkNtUserQueryWindow) oNtUserQueryWindow = nullptr;

HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass,
                                PUNICODE_STRING lpszWindow, DWORD dwType);
inline decltype(&hkNtUserFindWindowEx) oNtUserFindWindowEx = nullptr;

NTSTATUS NTAPI hkNtUserBuildHwndList(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax,
                                     HWND *phwndFirst, ULONG *pcHwndNeeded);
inline decltype(&hkNtUserBuildHwndList) oNtUserBuildHwndList = nullptr;

HWND NTAPI hkNtUserGetForegroundWindow(VOID);
inline decltype(&hkNtUserGetForegroundWindow) oNtUserGetForegroundWindow = nullptr;
} // namespace hooks
} // namespace masterhide