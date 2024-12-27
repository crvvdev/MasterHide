#pragma once

#include <evntrace.h>
#include <wmistr.h>
#include "hde\hde64.h"

#define IA32_LSTAR_MSR 0xC0000082
#define KPCR_RSP_BASE 0x1A8

#define EtwpStartTrace 1
#define EtwpStopTrace 2
#define EtwpQueryTrace 3
#define EtwpUpdateTrace 4
#define EtwpFlushTrace 5

typedef struct _EVENT_TRACE_PROPERTIES
{
    WNODE_HEADER Wnode;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    union {
        LONG AgeLimit;
        LONG FlushThreshold;
    } DUMMYUNIONNAME;
    ULONG NumberOfBuffers;
    ULONG FreeBuffers;
    ULONG EventsLost;
    ULONG BuffersWritten;
    ULONG LogBuffersLost;
    ULONG RealTimeBuffersLost;
    HANDLE LoggerThreadId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;

} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

/* 54dea73a-ed1f-42a4-af713e63d056f174 */
const GUID CkclSessionGuid = {0x54dea73a, 0xed1f, 0x42a4, {0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74}};

enum CKCL_TRACE_OPERATION
{
    CKCL_TRACE_START,
    CKCL_TRACE_SYSCALL,
    CKCL_TRACE_END
};

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
    ULONG64 Unknown[3];
    UNICODE_STRING ProviderName;

} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

typedef VOID(__fastcall *SSDT_CALLBACK)(ULONG, PVOID *);

inline HANDLE g_WatchdogThreadHandle = nullptr;
inline BOOLEAN g_WatchdogSignal = FALSE;

inline SSDT_CALLBACK g_SsdtCallback = NULL;
inline PVOID g_SyscallTableAddress = nullptr;

inline PVOID *g_GetCpuClock = nullptr;
inline PVOID *g_HvlpReferenceTscPage = nullptr;
inline PVOID *g_HvlGetQpcBias = nullptr;

inline PVOID g_HvlGetQpcBiasOriginal = nullptr;
inline PVOID g_GetCpuClockOriginal = nullptr;

PVOID GetSyscallEntry();

ULONG64
hkHvlGetQpcBias(VOID);

BOOLEAN
StartSyscallHook(VOID);

ULONG64
SyscallHookHandler(VOID);

VOID WatchdogThread(_In_ PVOID StartContext);

NTSTATUS
ModifyTraceSettings(_In_ const CKCL_TRACE_OPERATION &TraceOperation);

NTSTATUS InitializeInfinityHook(_In_ SSDT_CALLBACK ssdtCallback);
void DeinitializeInfinityHook();