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
#include <windef.h>
#include <ntstrsafe.h>

#define TAG					'gtHM'
#define DBGPRINT( x, ... )	DbgPrintEx( 0, 0, "[ MasterHide ] " x, __VA_ARGS__ );

#define USE_KASPERSKY

static UCHAR szFakeMAC[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x2 };

//
// Customize HD Serial and Model
static char szFakeSerial[] = "XJEBA1973M2";

static char* szFakeModels[] =
{
	"Samsung EVO 970",
	//...
};

//
// Those drivers will not appear on drivers list
static char* szProtectedDrivers[] =
{
	"dbk64",
	"processhacker2",
	//...
};

//
// Those processes will not appear on process list or via window methods
static wchar_t* wsProtectedProcesses[] =
{
	L"cheatengine",
	L"ProcessHacker"
	//...
};

//
// Those processes will be monitored 
static wchar_t* wsMonitoredProcesses[] =
{
	L"Tibia",
	//...
};

//
// Those processess will be blacklisted to query data on protect processes
static wchar_t* wsBlacklistedProcessess[] =
{
	L"Tibia",
	//...
};

#include "winnt.h"
#include "tools.h"
#include "kaspersky.hpp"
#include "ssdt.h"
#include "shadow_ssdt.h"
#include "mh_hooks.h"