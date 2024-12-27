#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <type_traits>

#include <ntifs.h>
#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <ntddndis.h>
#include <scsi.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "thirdparty/scope_guard/include/scope_guard.hpp"

#ifdef __cplusplus
extern "C"
{
#endif
#include <phnt.h>
#include <ntpebteb.h>
#include <ntldr.h>
#include "ntfill.hpp"
#ifdef __cplusplus
}
#endif

#ifndef DBGPRINT
#if DBG
#define DBGPRINT(x, ...) DbgPrintEx(NULL, NULL, "[MasterHide] " x "\n", __VA_ARGS__);
#else
#define DBGPRINT(...)
#endif
#endif

#ifndef BIT
#define BIT(x) (1LL << (x))
#endif

#include "kaspersky.hpp"
#include "infinityhook.hpp"

#include "..\shared\shared.hpp"

#include "fnv1a.hpp"
#include "wpp_trace.hpp"
#include "dyn.hpp"
#include "tools.hpp"
#include "callbacks.hpp"
#include "syscalls.hpp"
#include "utils.hpp"
#include "object.hpp"
#include "process.hpp"
#include "hooks.hpp"

using namespace masterhide;