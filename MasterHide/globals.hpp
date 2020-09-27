#pragma once

namespace masterhide
{
	namespace globals
	{
		//
		// Custom MAC Address
		//
		static UCHAR szFakeMAC[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x2 };

		//
		// Custom HD Serial and Model
		//
		static char szFakeSerial[] = "XJEBA1973M2";

		static char* szFakeModels[] =
		{
			"Samsung EVO 970",
			//...
		};

		//
		// Those drivers will not appear on drivers list
		//
		static char* szProtectedDrivers[] =
		{
			"dbk64",
			"processhacker2",
			//...
		};

		//
		// Those processes will not appear on process list or via window methods
		//
		static wchar_t* wsProtectedProcesses[] =
		{
			L"cheatengine",
			L"ProcessHacker"
			//...
		};

		//
		// Those processes will be monitored 
		//
		static wchar_t* wsMonitoredProcesses[] =
		{
			L"Tibia",
			//...
		};

		//
		// Those processess will be blacklisted to query data on protect processes
		//
		static wchar_t* wsBlacklistedProcessess[] =
		{
			L"Tibia",
			//...
		};
	}
};