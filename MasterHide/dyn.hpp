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
        INT64(__fastcall *MiGetPteAddress)(UINT64);

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