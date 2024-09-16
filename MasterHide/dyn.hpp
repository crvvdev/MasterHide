#pragma once

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
        PUCHAR Base;
        ULONG Size;
        ULONG MajorVersion;
        ULONG MinorVersion;
        ULONG BuildVersion;
        KDDEBUGGER_DATA64 KdBlock;

    } Kernel;

    struct
    {
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

} inline DynCtx{};

// Globals
//
inline bool g_initialized = false;

// Functions
//
NTSTATUS Initialize();
} // namespace dyn
} // namespace masterhide