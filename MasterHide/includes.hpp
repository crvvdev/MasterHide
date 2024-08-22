#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <ntddndis.h>
#include <ntimage.h>
#include <scsi.h>
#include <intrin.h>
#include <ntstrsafe.h>

#define TAG '00hm'

#ifndef DBGPRINT
#if _DEBUG
#define DBGPRINT(x, ...) DbgPrintEx(NULL, NULL, "[ MasterHide ] " x "\n", __VA_ARGS__);
#else
#define DBGPRINT(...)
#endif
#endif

//
// Uncomment that to use ordinary SSDT/SSSDT hooking
//
#define USE_KASPERSKY

#include "winnt.hpp"
#include "globals.hpp"
#include "misc.hpp"
#include "kaspersky.hpp"
#include "ssdt.hpp"
#include "shadow_ssdt.hpp"
#include "hooks.hpp"

using namespace masterhide;