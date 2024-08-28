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
#include <phnt.h>
//#include <ntfill.h>
#include <ntpebteb.h>
#include <ntldr.h>
//#include <kphapi.h>

#ifndef DBGPRINT
#if _DEBUG
#define DBGPRINT(x, ...) DbgPrintEx(NULL, NULL, "[ MasterHide ] " x "\n", __VA_ARGS__);
#else
#define DBGPRINT(...)
#endif
#endif

#include "ntfill.hpp"
#include "fnv1a.hpp"
#include "wpp_trace.hpp"
#include "misc.hpp"
#include "utils.hpp"
#include "process.hpp"
#ifdef USE_KASPERSKY
#include "kaspersky.hpp"
#endif
#include "ssdt.hpp"
#include "shadow_ssdt.hpp"
#include "hooks.hpp"

using namespace masterhide;