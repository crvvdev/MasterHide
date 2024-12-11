#pragma once

namespace masterhide
{
namespace hooks
{
// Globals
//
extern KMUTEX g_NtCloseMutex;
inline bool g_initialized = false;

// Functions
//
NTSTATUS Initialize();
void Deinitialize();

// SSDT hooks
//
NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length,
                                          PULONG ReturnLength);
// inline decltype(&hkNtQuerySystemInformation) oNtQuerySystemInformation = nullptr;

using NtOpenProcess_ = NTSTATUS(NTAPI *)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                         POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                               PCLIENT_ID ClientId);
// inline decltype(&hkNtOpenProcess) oNtOpenProcess = nullptr;

NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                         PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
// inline decltype(&hkNtAllocateVirtualMemory) oNtAllocateVirtualMemory = nullptr;

NTSTATUS NTAPI hkNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
// inline decltype(&hkNtFreeVirtualMemory) oNtFreeVirtualMemory = nullptr;

NTSTATUS NTAPI hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,
                                      PULONG NumberOfBytesWritten);
// inline decltype(&hkNtWriteVirtualMemory) oNtWriteVirtualMemory = nullptr;

NTSTATUS NTAPI hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                       PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
                                       ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
// inline decltype(&hkNtDeviceIoControlFile) oNtDeviceIoControlFile = nullptr;

NTSTATUS NTAPI hkNtLoadDriver(PUNICODE_STRING DriverServiceName);
// inline decltype(&hkNtLoadDriver) oNtLoadDriver = nullptr;

NTSTATUS NTAPI hkNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                        PVOID ThreadInformation, ULONG ThreadInformationLength);
// inline decltype(&hkNtSetInformationThread) oNtSetInformationThread = nullptr;

NTSTATUS NTAPI hkNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                           PVOID ProcessInformation, ULONG ProcessInformationLength,
                                           PULONG ReturnLength);
// inline decltype(&hkNtQueryInformationProcess) oNtQueryInformationProcess = nullptr;

NTSTATUS NTAPI hkNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                         PVOID ProcessInformation, ULONG ProcessInformationLength);
// inline decltype(&hkNtSetInformationProcess) oNtSetInformationProcess = nullptr;

NTSTATUS NTAPI hkNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                          PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
// inline decltype(&hkNtQueryInformationThread) oNtQueryInformationThread = nullptr;

NTSTATUS NTAPI hkNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation,
                               ULONG ObjectInformationLength, PULONG ReturnLength);
// inline decltype(&hkNtQueryObject) oNtQueryObject = nullptr;

NTSTATUS NTAPI hkNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                  HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
                                  SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
// inline decltype(&hkNtCreateThreadEx) oNtCreateThreadEx = nullptr;

NTSTATUS NTAPI hkNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
// inline decltype(&hkNtGetContextThread) oNtGetContextThread = nullptr;

NTSTATUS NTAPI hkNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
// inline decltype(&hkNtSetContextThread) oNtSetContextThread = nullptr;

NTSTATUS NTAPI hkNtContinue(PCONTEXT Context, ULONG64 TestAlert);
// inline decltype(&hkNtContinue) oNtContinue = nullptr;

NTSTATUS NTAPI hkNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                              PCLIENT_ID ClientId);
// inline decltype(&hkNtOpenThread) oNtOpenThread = nullptr;

NTSTATUS NTAPI hkNtYieldExecution();
// inline decltype(&hkNtYieldExecution) oNtYieldExecution = nullptr;

NTSTATUS NTAPI hkNtClose(HANDLE Handle);
// inline decltype(&hkNtClose) oNtClose = nullptr;

NTSTATUS NTAPI hkNtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength,
                                      PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
// inline decltype(&hkNtSystemDebugControl) oNtSystemDebugControl = nullptr;

NTSTATUS NTAPI hkNtQuerySystemTime(PLARGE_INTEGER SystemTime);
// inline decltype(&hkNtQuerySystemTime) oNtQuerySystemTime = nullptr;

NTSTATUS NTAPI hkNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);
// inline decltype(&hkNtQueryPerformanceCounter) oNtQueryPerformanceCounter = nullptr;

// Shadow SSDT hooks
//
inline HWND(NTAPI *NtUserGetThreadState)(ThreadStateRoutines Routine) = nullptr;

HWND hkNtUserWindowFromPoint(LONG x, LONG y);
// inline decltype(&hkNtUserWindowFromPoint) oNtUserWindowFromPoint = nullptr;

HANDLE hkNtUserQueryWindow(HWND WindowHandle, WINDOWINFOCLASS WindowInfo);
// inline decltype(&hkNtUserQueryWindow) oNtUserQueryWindow = nullptr;

HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass,
                                PUNICODE_STRING lpszWindow, DWORD dwType);
// inline decltype(&hkNtUserFindWindowEx) oNtUserFindWindowEx = nullptr;

NTSTATUS NTAPI hkNtUserBuildHwndList_Win7(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread,
                                          UINT cHwndMax, HWND *phwndFirst, ULONG *pcHwndNeeded);
// inline decltype(&hkNtUserBuildHwndList_Win7) oNtUserBuildHwndList_Win7 = nullptr;

NTSTATUS NTAPI hkNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag,
                                     ULONG dwThreadId, ULONG lParam, HWND *pWnd, PULONG pBufSize);
// inline decltype(&hkNtUserBuildHwndList) oNtUserBuildHwndList = nullptr;

HWND NTAPI hkNtUserGetForegroundWindow(VOID);
// inline decltype(&hkNtUserGetForegroundWindow) oNtUserGetForegroundWindow = nullptr;

typedef struct _HOOK_ENTRY
{
    BOOLEAN Shadow;
    CHAR ServiceName[64];
    PVOID Original;
    PVOID New;
    USHORT ServiceIndex;
    LONG RefCount;
#if (MASTERHIDE_MODE == MASTERHIDE_MODE_SSDTHOOK)
    LONG OldSsdt;
    LONG NewSsdt;
    UCHAR OriginalBytes[12];
#endif
} HOOK_ENTRY, *PHOOK_ENTRY;

extern HOOK_ENTRY g_HookList[];
} // namespace hooks
} // namespace masterhide