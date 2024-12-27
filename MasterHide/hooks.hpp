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
NTSTATUS NTAPI hkNtYieldExecution();
NTSTATUS NTAPI hkNtClose(HANDLE Handle);
NTSTATUS NTAPI hkNtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength,
                                      PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
NTSTATUS NTAPI hkNtQuerySystemTime(PLARGE_INTEGER SystemTime);
NTSTATUS NTAPI hkNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);
NTSTATUS NTAPI hkNtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass,
                                             PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI hkNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags,
                                  PHANDLE NewProcessHandle);
NTSTATUS NTAPI hkNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess,
                                     ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes,
                                     POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags,
                                     PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
                                     PVOID CreateInfo,   // PPS_CREATE_INFO
                                     PVOID AttributeList // PPS_ATTRIBUTE_LIST
);

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
HWND NTAPI NtUserGetThreadState(ThreadStateRoutines Routine);

typedef struct _HOOK_ENTRY
{
    KEVENT Event;
    PVOID OriginalFunc;
    PVOID NewFunc;
    CHAR ServiceName[64];
    BOOLEAN Win32k;
    ReferenceGuard RefCount;
    USHORT ServiceIndex;
    UCHAR OriginalBytes[12];

    _HOOK_ENTRY()
    {
        RtlZeroMemory(this, sizeof(*this));
    }

    constexpr _HOOK_ENTRY(const char *serviceName, BOOLEAN win32k, PVOID newFunc)
        : Event{}, OriginalFunc(nullptr), NewFunc(newFunc), Win32k(win32k), RefCount{}, ServiceIndex(MAXUSHORT),
          OriginalBytes{}
    {
        size_t length = 0;

        while (serviceName[length] != '\0' && length < ARRAYSIZE(ServiceName) - 1)
        {
            ServiceName[length] = serviceName[length];
            ++length;
        }

        ServiceName[length] = '\0';

        for (size_t i = length + 1; i < sizeof(ServiceName); ++i)
        {
            ServiceName[i] = '\0';
        }
    }

} HOOK_ENTRY, *PHOOK_ENTRY;

extern HOOK_ENTRY g_HookList[];
} // namespace hooks
} // namespace masterhide