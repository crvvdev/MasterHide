#pragma once

#define DEFINE_DYN_CONTEXT_PROC(return_type, proc_name, var_type)                                                      \
    __forceinline return_type proc_name(var_type p)                                                                    \
    {                                                                                                                  \
        return reinterpret_cast<return_type>(PTR_OFFSET_ADD(p, Offsets.proc_name));                                    \
    }

#define DEFINE_DYN_CONTEXT_PROC_PTR(return_type, proc_name, var_type)                                                  \
    __forceinline return_type proc_name(var_type p)                                                                    \
    {                                                                                                                  \
        return *reinterpret_cast<return_type *>(PTR_OFFSET_ADD(p, Offsets.proc_name));                                 \
    }

namespace masterhide
{
namespace dyn
{
#define KERNEL_BASE dyn::DynCtx.Kernel.Base
#define KERNEL_SIZE dyn::DynCtx.Kernel.Size
#define KERNEL_BUILD_VERSION dyn::DynCtx.Kernel.BuildVersion
#define KERNEL_BUILD_MAJOR dyn::DynCtx.Kernel.MajorVersion
#define KERNEL_BUILD_MINOR dyn::DynCtx.Kernel.MinorVersion

// Structs
//
struct DynamicContext_t
{
    struct
    {
        PVOID Base;
        ULONG Size;
        ULONG MajorVersion;
        ULONG MinorVersion;
        ULONG BuildVersion;
        KDDEBUGGER_DATA64 KdBlock;
#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
        ULONG_PTR EtwpDebuggerData;
        ULONG_PTR HvlpReferenceTscPage;
        ULONG_PTR HvlGetQpcBias;
#endif
        PULONG_PTR KeServiceDescriptorTable;
        PULONG_PTR KeServiceDescriptorTableShadow;
    } Kernel;

    struct
    {
#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
        ULONG GetCpuClock; // struct _WMI_LOGGER_CONTEXT
#endif
        ULONG SeAuditProcessCreationInfoOffset;   // struct _EPROCESS
        ULONG BypassProcessFreezeFlagOffset;      // struct _KTHREAD
        ULONG ThreadHideFromDebuggerFlagOffset;   // struct _ETHREAD
        ULONG ThreadBreakOnTerminationFlagOffset; // struct _ETHREAD
        ULONG PicoContextOffset;                  // struct _ETHREAD
        ULONG RestrictSetThreadContextOffset;     // struct _EPROCESS

    } Offsets;

    struct
    {

    } Fn;

#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
    DEFINE_DYN_CONTEXT_PROC(PVOID *, GetCpuClock, ULONG_PTR)
#endif
};

extern DynamicContext_t DynCtx;

// Globals
//
inline bool g_initialized = false;

/// <summary>
/// Initialize dynamic context.
/// </summary>
/// <returns>STATUS_SUCCESS on success, otherwise any NTSTATUS value</returns>
NTSTATUS Initialize();
} // namespace dyn
} // namespace masterhide