#pragma once

namespace masterhide
{
namespace hooks
{
/// <summary>
/// Initialize hooks.
/// </summary>
/// <returns>STATUS_SUCCESS on success, otherwise any NTSTATUS value</returns>
NTSTATUS Initialize();

/// <summary>
/// De-initialize hooks.
/// </summary>
void Deinitialize();

// SSDT hooks
//
NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length,
                                          PULONG ReturnLength);
NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                               PCLIENT_ID ClientId);
NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                         PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NTAPI hkNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
NTSTATUS NTAPI hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,
                                      PULONG NumberOfBytesWritten);
NTSTATUS NTAPI hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                       PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
                                       ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
NTSTATUS NTAPI hkNtLoadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS NTAPI hkNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                        PVOID ThreadInformation, ULONG ThreadInformationLength);
NTSTATUS NTAPI hkNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                           PVOID ProcessInformation, ULONG ProcessInformationLength,
                                           PULONG ReturnLength);
NTSTATUS NTAPI hkNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                         PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSTATUS NTAPI hkNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                          PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI hkNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation,
                               ULONG ObjectInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI hkNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                  HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
                                  SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
NTSTATUS NTAPI hkNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS NTAPI hkNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
NTSTATUS NTAPI hkNtContinue(PCONTEXT Context, ULONG64 TestAlert);
NTSTATUS NTAPI hkNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                              PCLIENT_ID ClientId);
NTSTATUS NTAPI hkNtYieldExecution();
NTSTATUS NTAPI hkNtClose(HANDLE Handle);
NTSTATUS NTAPI hkNtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength,
                                      PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
NTSTATUS NTAPI hkNtQuerySystemTime(PLARGE_INTEGER SystemTime);
NTSTATUS NTAPI hkNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);
NTSTATUS NTAPI hkNtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass,
                                             PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength);

// Shadow SSDT hooks
//
HWND hkNtUserWindowFromPoint(LONG x, LONG y);
HANDLE hkNtUserQueryWindow(HWND WindowHandle, WINDOWINFOCLASS WindowInfo);
HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass,
                                PUNICODE_STRING lpszWindow, DWORD dwType);
NTSTATUS NTAPI hkNtUserBuildHwndList_Win7(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread,
                                          UINT cHwndMax, HWND *phwndFirst, ULONG *pcHwndNeeded);
NTSTATUS NTAPI hkNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag,
                                     ULONG dwThreadId, ULONG lParam, HWND *pWnd, PULONG pBufSize);
HWND NTAPI hkNtUserGetForegroundWindow(VOID);

typedef struct _HOOK_ENTRY
{
    BOOLEAN Win32k;
    CHAR ServiceName[64];
    PVOID Original;
    PVOID New;
    USHORT ServiceIndex;
    KEVENT Event;
    ReferenceGuard RefCount;
#if (MASTERHIDE_MODE == MASTERHIDE_MODE_SSDTHOOK)
    LONG OldSsdt;
    LONG NewSsdt;
    UCHAR OriginalBytes[12];
#endif
} HOOK_ENTRY, *PHOOK_ENTRY;

extern HOOK_ENTRY g_HookList[];
} // namespace hooks
} // namespace masterhide