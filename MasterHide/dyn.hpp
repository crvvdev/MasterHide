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
#define KERNEL_BUILD dyn::DynCtx.Kernel.BuildVersion

// Structs
//
struct
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

    } Kernel;

    struct
    {
#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
        ULONG GetCpuClock;
#endif
        ULONG SeAuditProcessCreationInfoOffset;
        ULONG BypassProcessFreezeFlagOffset;
        ULONG ThreadHideFromDebuggerFlagOffset;
        ULONG ThreadBreakOnTerminationFlagOffset;
        ULONG PicoContextOffset;
        ULONG RestrictSetThreadContextOffset;

    } Offsets;

    struct
    {

    } Fn;

#if (MASTERHIDE_MODE == MASTERHIDE_MODE_INFINITYHOOK)
    DEFINE_DYN_CONTEXT_PROC(PVOID *, GetCpuClock, ULONG_PTR)
#endif

} inline DynCtx{};

// Globals
//
inline bool g_initialized = false;

// Functions
//
NTSTATUS Initialize();
} // namespace dyn
} // namespace masterhide