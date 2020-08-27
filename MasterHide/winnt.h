#pragma once

#pragma warning(push)
#pragma warning(disable: 4201)

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	_SYSTEM_HANDLE Information[ 1 ];
} _SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	_SYSTEM_HANDLE Information[ 1 ];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_MODULE
{
	PVOID Reserved[ 2 ];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[ 256 ];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[ 1 ];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID ServiceTableBase;
	PVOID ServiceCounterTableBase;
	ULONGLONG NumberOfServices;
	PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation, // q: RTL_PROCESS_LOCKS
	SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q
	SystemVdmBopInformation, // not implemented // 20
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented
	SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
	SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q
	SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q
	SystemComPlusPackage, // q; s
	SystemNumaAvailableMemory, // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation, // q
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
	SystemObjectSecurityMode, // q: ULONG // 70
	SystemWatchdogTimerHandler, // s (kernel-mode only)
	SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
	SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation, // q; s (kernel-mode only)
	SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
	SystemPrefetchPatchInformation, // not implemented
	SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
	SystemNumaProximityNodeInformation, // q
	SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s
	SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s // SmQueryStoreInformation
	SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
	SystemNativeBasicInformation, // not implemented
	SystemSpare1, // not implemented
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation, // q
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
	SystemBadPageInformation,
	SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
	SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
	SystemSpare0,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation,
	SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags,
	SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation,
	SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
	SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation,
	SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation, // 180
	SystemSupportedProcessorArchitectures,
	SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
	SystemControlFlowTransition,
	SystemKernelDebuggingAllowed,
	SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
	SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemIntegrityQuotaInformation,
	SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
	SystemProcessorIdleMaskInformation, // since REDSTONE3
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
	SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
	SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemFirmwarePartitionInformation, // 200
	SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
	SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
	SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
	SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
	SystemCodeIntegrityUnlockModeInformation,
	SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
	SystemFlags2Information,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[ 3 ];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// private
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
	USHORT NextOffset;
	RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

#define CODEINTEGRITY_OPTION_ENABLED 0x01 
#define CODEINTEGRITY_OPTION_TESTSIGN 0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED 0x04
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED 0x08
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED 0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD 0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD 0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED 0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD 0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED 0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED 0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED 0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED 0x2000

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG  Length;
	ULONG  CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

#pragma warning(pop)

//
// IDE command definitions
//
#define IDE_COMMAND_NOP                         0x00
#define IDE_COMMAND_DATA_SET_MANAGEMENT         0x06
#define IDE_COMMAND_ATAPI_RESET                 0x08
#define IDE_COMMAND_READ                        0x20
#define IDE_COMMAND_READ_EXT                    0x24
#define IDE_COMMAND_READ_DMA_EXT                0x25
#define IDE_COMMAND_READ_DMA_QUEUED_EXT         0x26
#define IDE_COMMAND_READ_MULTIPLE_EXT           0x29
#define IDE_COMMAND_READ_LOG_EXT                0x2f
#define IDE_COMMAND_WRITE                       0x30
#define IDE_COMMAND_WRITE_EXT                   0x34
#define IDE_COMMAND_WRITE_DMA_EXT               0x35
#define IDE_COMMAND_WRITE_DMA_QUEUED_EXT        0x36
#define IDE_COMMAND_WRITE_MULTIPLE_EXT          0x39
#define IDE_COMMAND_WRITE_DMA_FUA_EXT           0x3D
#define IDE_COMMAND_WRITE_DMA_QUEUED_FUA_EXT    0x3E
#define IDE_COMMAND_WRITE_LOG_EXT               0x3f
#define IDE_COMMAND_VERIFY                      0x40
#define IDE_COMMAND_VERIFY_EXT                  0x42
#define IDE_COMMAND_WRITE_LOG_DMA_EXT           0x57
#define IDE_COMMAND_TRUSTED_NON_DATA            0x5B
#define IDE_COMMAND_TRUSTED_RECEIVE             0x5C
#define IDE_COMMAND_TRUSTED_RECEIVE_DMA         0x5D
#define IDE_COMMAND_TRUSTED_SEND                0x5E
#define IDE_COMMAND_TRUSTED_SEND_DMA            0x5F
#define IDE_COMMAND_READ_FPDMA_QUEUED           0x60        // NCQ Read command
#define IDE_COMMAND_WRITE_FPDMA_QUEUED          0x61        // NCQ Write command
#define IDE_COMMAND_NCQ_NON_DATA                0x63        // NCQ Non-Data command
#define IDE_COMMAND_SEND_FPDMA_QUEUED           0x64        // NCQ Send command
#define IDE_COMMAND_RECEIVE_FPDMA_QUEUED        0x65        // NCQ Receive command
#define IDE_COMMAND_SET_DATE_AND_TIME           0x77        // optional 48bit command
#define IDE_COMMAND_EXECUTE_DEVICE_DIAGNOSTIC   0x90
#define IDE_COMMAND_SET_DRIVE_PARAMETERS        0x91
#define IDE_COMMAND_ATAPI_PACKET                0xA0
#define IDE_COMMAND_ATAPI_IDENTIFY              0xA1
#define IDE_COMMAND_SMART                       0xB0
#define IDE_COMMAND_READ_LOG_DMA_EXT            0xB1
#define IDE_COMMAND_SANITIZE_DEVICE             0xB4
#define IDE_COMMAND_READ_MULTIPLE               0xC4
#define IDE_COMMAND_WRITE_MULTIPLE              0xC5
#define IDE_COMMAND_SET_MULTIPLE                0xC6
#define IDE_COMMAND_READ_DMA                    0xC8
#define IDE_COMMAND_WRITE_DMA                   0xCA
#define IDE_COMMAND_WRITE_DMA_QUEUED            0xCC
#define IDE_COMMAND_WRITE_MULTIPLE_FUA_EXT      0xCE
#define IDE_COMMAND_GET_MEDIA_STATUS            0xDA
#define IDE_COMMAND_DOOR_LOCK                   0xDE
#define IDE_COMMAND_DOOR_UNLOCK                 0xDF
#define IDE_COMMAND_STANDBY_IMMEDIATE           0xE0
#define IDE_COMMAND_IDLE_IMMEDIATE              0xE1
#define IDE_COMMAND_CHECK_POWER                 0xE5
#define IDE_COMMAND_SLEEP                       0xE6
#define IDE_COMMAND_FLUSH_CACHE                 0xE7
#define IDE_COMMAND_FLUSH_CACHE_EXT             0xEA
#define IDE_COMMAND_IDENTIFY                    0xEC
#define IDE_COMMAND_MEDIA_EJECT                 0xED
#define IDE_COMMAND_SET_FEATURE                 0xEF
#define IDE_COMMAND_SECURITY_SET_PASSWORD       0xF1
#define IDE_COMMAND_SECURITY_UNLOCK             0xF2
#define IDE_COMMAND_SECURITY_ERASE_PREPARE      0xF3
#define IDE_COMMAND_SECURITY_ERASE_UNIT         0xF4
#define IDE_COMMAND_SECURITY_FREEZE_LOCK        0xF5
#define IDE_COMMAND_SECURITY_DISABLE_PASSWORD   0xF6
#define IDE_COMMAND_NOT_VALID                   0xFF

//
// IDE status definitions
//
#define IDE_STATUS_ERROR             0x01
#define IDE_STATUS_INDEX             0x02
#define IDE_STATUS_CORRECTED_ERROR   0x04
#define IDE_STATUS_DRQ               0x08
#define IDE_STATUS_DSC               0x10
#define IDE_STATUS_DEVICE_FAULT      0x20
#define IDE_STATUS_DRDY              0x40
#define IDE_STATUS_IDLE              0x50
#define IDE_STATUS_BUSY              0x80

typedef struct _IDSECTOR {
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[ 3 ];
	CHAR    sSerialNumber[ 20 ];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[ 8 ];
	CHAR    sModelNumber[ 40 ];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[ 128 ];
} IDSECTOR, * PIDSECTOR;

#pragma pack(push, id_device_data, 1)
typedef struct _IDENTIFY_DEVICE_DATA {

	struct {
		USHORT Reserved1 : 1;
		USHORT Retired3 : 1;
		USHORT ResponseIncomplete : 1;
		USHORT Retired2 : 3;
		USHORT FixedDevice : 1;                 // obsolete
		USHORT RemovableMedia : 1;              // obsolete
		USHORT Retired1 : 7;
		USHORT DeviceType : 1;
	} GeneralConfiguration;                     // word 0

	USHORT NumCylinders;                        // word 1, obsolete
	USHORT SpecificConfiguration;               // word 2
	USHORT NumHeads;                            // word 3, obsolete
	USHORT Retired1[ 2 ];
	USHORT NumSectorsPerTrack;                  // word 6, obsolete
	USHORT VendorUnique1[ 3 ];
	UCHAR  SerialNumber[ 20 ];                    // word 10-19
	USHORT Retired2[ 2 ];
	USHORT Obsolete1;
	UCHAR  FirmwareRevision[ 8 ];                 // word 23-26
	UCHAR  ModelNumber[ 40 ];                     // word 27-46
	UCHAR  MaximumBlockTransfer;                // word 47. 01h-10h = Maximum number of sectors that shall be transferred per interrupt on READ/WRITE MULTIPLE commands
	UCHAR  VendorUnique2;

	struct {
		USHORT FeatureSupported : 1;
		USHORT Reserved : 15;
	}TrustedComputing;                          // word 48

	struct {
		UCHAR CurrentLongPhysicalSectorAlignment : 2;
		UCHAR ReservedByte49 : 6;

		UCHAR DmaSupported : 1;
		UCHAR LbaSupported : 1;                 // Shall be set to one to indicate that LBA is supported.
		UCHAR IordyDisable : 1;
		UCHAR IordySupported : 1;
		UCHAR Reserved1 : 1;                    // Reserved for the IDENTIFY PACKET DEVICE command
		UCHAR StandybyTimerSupport : 1;
		UCHAR Reserved2 : 2;                    // Reserved for the IDENTIFY PACKET DEVICE command

		USHORT ReservedWord50;
	}Capabilities;                              // word 49-50

	USHORT ObsoleteWords51[ 2 ];

	USHORT TranslationFieldsValid : 3;            // word 53, bit 0 - Obsolete; bit 1 - words 70:64 valid; bit 2; word 88 valid
	USHORT Reserved3 : 5;
	USHORT FreeFallControlSensitivity : 8;

	USHORT NumberOfCurrentCylinders;            // word 54, obsolete
	USHORT NumberOfCurrentHeads;                // word 55, obsolete
	USHORT CurrentSectorsPerTrack;              // word 56, obsolete
	ULONG  CurrentSectorCapacity;               // word 57, word 58, obsolete

	UCHAR  CurrentMultiSectorSetting;           // word 59
	UCHAR  MultiSectorSettingValid : 1;
	UCHAR  ReservedByte59 : 3;
	UCHAR  SanitizeFeatureSupported : 1;
	UCHAR  CryptoScrambleExtCommandSupported : 1;
	UCHAR  OverwriteExtCommandSupported : 1;
	UCHAR  BlockEraseExtCommandSupported : 1;

	ULONG  UserAddressableSectors;              // word 60-61, for 28-bit commands

	USHORT ObsoleteWord62;

	USHORT MultiWordDMASupport : 8;             // word 63
	USHORT MultiWordDMAActive : 8;

	USHORT AdvancedPIOModes : 8;                // word 64. bit 0:1 - PIO mode supported
	USHORT ReservedByte64 : 8;

	USHORT MinimumMWXferCycleTime;              // word 65
	USHORT RecommendedMWXferCycleTime;          // word 66
	USHORT MinimumPIOCycleTime;                 // word 67
	USHORT MinimumPIOCycleTimeIORDY;            // word 68

	struct {
		USHORT Reserved : 2;
		USHORT NonVolatileWriteCache : 1;                   // All write cache is non-volatile
		USHORT ExtendedUserAddressableSectorsSupported : 1;
		USHORT DeviceEncryptsAllUserData : 1;
		USHORT ReadZeroAfterTrimSupported : 1;
		USHORT Optional28BitCommandsSupported : 1;
		USHORT IEEE1667 : 1;            // Reserved for IEEE 1667
		USHORT DownloadMicrocodeDmaSupported : 1;
		USHORT SetMaxSetPasswordUnlockDmaSupported : 1;
		USHORT WriteBufferDmaSupported : 1;
		USHORT ReadBufferDmaSupported : 1;
		USHORT DeviceConfigIdentifySetDmaSupported : 1;     // obsolete
		USHORT LPSAERCSupported : 1;                        // Long Physical Sector Alignment Error Reporting Control is supported.
		USHORT DeterministicReadAfterTrimSupported : 1;
		USHORT CFastSpecSupported : 1;
	}AdditionalSupported;                       // word 69

	USHORT ReservedWords70[ 5 ];                  // word 70 - reserved
	// word 71:74 - Reserved for the IDENTIFY PACKET DEVICE command

	//Word 75
	USHORT QueueDepth : 5;          //  Maximum queue depth - 1
	USHORT ReservedWord75 : 11;

	struct {
		// Word 76
		USHORT Reserved0 : 1;    // shall be set to 0
		USHORT SataGen1 : 1;    // Supports SATA Gen1 Signaling Speed (1.5Gb/s)
		USHORT SataGen2 : 1;    // Supports SATA Gen2 Signaling Speed (3.0Gb/s)
		USHORT SataGen3 : 1;    // Supports SATA Gen3 Signaling Speed (6.0Gb/s)

		USHORT Reserved1 : 4;

		USHORT NCQ : 1;    // Supports the NCQ feature set
		USHORT HIPM : 1;    // Supports HIPM
		USHORT PhyEvents : 1;    // Supports the SATA Phy Event Counters log
		USHORT NcqUnload : 1;    // Supports Unload while NCQ commands are outstanding

		USHORT NcqPriority : 1;    // Supports NCQ priority information
		USHORT HostAutoPS : 1;    // Supports Host Automatic Partial to Slumber transitions
		USHORT DeviceAutoPS : 1;    // Supports Device Automatic Partial to Slumber transitions
		USHORT ReadLogDMA : 1;    // Supports READ LOG DMA EXT as equivalent to READ LOG EXT

		// Word 77
		USHORT Reserved2 : 1;                // shall be set to 0
		USHORT CurrentSpeed : 3;                // Coded value indicating current negotiated Serial ATA signal speed

		USHORT NcqStreaming : 1;                // Supports NCQ Streaming
		USHORT NcqQueueMgmt : 1;                // Supports NCQ Queue Management Command
		USHORT NcqReceiveSend : 1;              // Supports RECEIVE FPDMA QUEUED and SEND FPDMA QUEUED commands
		USHORT DEVSLPtoReducedPwrState : 1;

		USHORT Reserved3 : 8;
	}SerialAtaCapabilities;

	// Word 78
	struct {
		USHORT Reserved0 : 1;                //shall be set to 0
		USHORT NonZeroOffsets : 1;                // Device supports non-zero buffer offsets in DMA Setup FIS
		USHORT DmaSetupAutoActivate : 1;          // Device supports DMA Setup auto-activation
		USHORT DIPM : 1;                // Device supports DIPM

		USHORT InOrderData : 1;                // Device supports in-order data delivery
		USHORT HardwareFeatureControl : 1;        // Hardware Feature Control is supported
		USHORT SoftwareSettingsPreservation : 1;  // Device supports Software Settings Preservation
		USHORT NCQAutosense : 1;                  // Supports NCQ Autosense

		USHORT DEVSLP : 1;         // Device supports link power state - device sleep
		USHORT HybridInformation : 1;         // Device supports Hybrid Information Feature (If the device does not support NCQ (word 76 bit 8 is 0), then this bit shall be cleared to 0.)

		USHORT Reserved1 : 6;
	}SerialAtaFeaturesSupported;

	// Word 79
	struct {
		USHORT Reserved0 : 1;                // shall be set to 0
		USHORT NonZeroOffsets : 1;                // Non-zero buffer offsets in DMA Setup FIS enabled
		USHORT DmaSetupAutoActivate : 1;          // DMA Setup auto-activation optimization enabled
		USHORT DIPM : 1;                // DIPM enabled

		USHORT InOrderData : 1;                // In-order data delivery enabled
		USHORT HardwareFeatureControl : 1;        // Hardware Feature Control is enabled
		USHORT SoftwareSettingsPreservation : 1;  // Software Settings Preservation enabled
		USHORT DeviceAutoPS : 1;                // Device Automatic Partial to Slumber transitions enabled

		USHORT DEVSLP : 1;         // link power state - device sleep is enabled
		USHORT HybridInformation : 1;         // Hybrid Information Feature is enabled

		USHORT Reserved1 : 6;
	}SerialAtaFeaturesEnabled;

	USHORT MajorRevision;                       // word 80. bit 5 - supports ATA5; bit 6 - supports ATA6; bit 7 - supports ATA7; bit 8 - supports ATA8-ACS; bit 9 - supports ACS-2;
	USHORT MinorRevision;                       // word 81. T13 minior version number

	struct {

		//
		// Word 82
		//
		USHORT SmartCommands : 1;           // The SMART feature set is supported
		USHORT SecurityMode : 1;            // The Security feature set is supported
		USHORT RemovableMediaFeature : 1;   // obsolete
		USHORT PowerManagement : 1;         // shall be set to 1
		USHORT Reserved1 : 1;               // PACKET feature set, set to 0 indicates not supported for ATA devices (only support for ATAPI devices)
		USHORT WriteCache : 1;              // The volatile write cache is supported
		USHORT LookAhead : 1;               // Read look-ahead is supported
		USHORT ReleaseInterrupt : 1;        // obsolete
		USHORT ServiceInterrupt : 1;        // obsolete
		USHORT DeviceReset : 1;             // Shall be cleared to zero to indicate that the DEVICE RESET command is not supported
		USHORT HostProtectedArea : 1;       // obsolete
		USHORT Obsolete1 : 1;
		USHORT WriteBuffer : 1;             // The WRITE BUFFER command is supported
		USHORT ReadBuffer : 1;              // The READ BUFFER command is supported
		USHORT Nop : 1;                     // The NOP command is supported
		USHORT Obsolete2 : 1;

		//
		// Word 83
		//
		USHORT DownloadMicrocode : 1;       // The DOWNLOAD MICROCODE command is supported
		USHORT DmaQueued : 1;               // obsolete
		USHORT Cfa : 1;                     // The CFA feature set is supported
		USHORT AdvancedPm : 1;              // The APM feature set is supported
		USHORT Msn : 1;                     // obsolete
		USHORT PowerUpInStandby : 1;        // The PUIS feature set is supported
		USHORT ManualPowerUp : 1;           // SET FEATURES subcommand is required to spin-up after power-up
		USHORT Reserved2 : 1;
		USHORT SetMax : 1;                  // obsolete
		USHORT Acoustics : 1;               // obsolete
		USHORT BigLba : 1;                  // The 48-bit Address feature set is supported
		USHORT DeviceConfigOverlay : 1;     // obsolete
		USHORT FlushCache : 1;              // Shall be set to one to indicate that the mandatory FLUSH CACHE command is supported
		USHORT FlushCacheExt : 1;           // The FLUSH CACHE EXT command is supported
		USHORT WordValid83 : 2;             // shall be 01b


		//
		// Word 84
		//
		USHORT SmartErrorLog : 1;           // SMART error logging is supported
		USHORT SmartSelfTest : 1;           // The SMART self-test is supported
		USHORT MediaSerialNumber : 1;       // Media serial number is supported
		USHORT MediaCardPassThrough : 1;    // obsolete
		USHORT StreamingFeature : 1;        // The Streaming feature set is supported
		USHORT GpLogging : 1;               // The GPL feature set is supported
		USHORT WriteFua : 1;                // The WRITE DMA FUA EXT and WRITE MULTIPLE FUA EXT commands are supported
		USHORT WriteQueuedFua : 1;          // obsolete
		USHORT WWN64Bit : 1;                // The 64-bit World wide name is supported
		USHORT URGReadStream : 1;           // obsolete
		USHORT URGWriteStream : 1;          // obsolete
		USHORT ReservedForTechReport : 2;
		USHORT IdleWithUnloadFeature : 1;   // The IDLE IMMEDIATE command with UNLOAD feature is supported
		USHORT WordValid : 2;               // shall be 01b

	}CommandSetSupport;

	struct {

		//
		// Word 85
		//
		USHORT SmartCommands : 1;           // The SMART feature set is enabled
		USHORT SecurityMode : 1;            // The Security feature set is enabled
		USHORT RemovableMediaFeature : 1;   // obsolete
		USHORT PowerManagement : 1;         // Shall be set to one to indicate that the mandatory Power Management feature set is supported
		USHORT Reserved1 : 1;               // Shall be cleared to zero to indicate that the PACKET feature set is not supported
		USHORT WriteCache : 1;              // The volatile write cache is enabled
		USHORT LookAhead : 1;               // Read look-ahead is enabled
		USHORT ReleaseInterrupt : 1;        // The release interrupt is enabled
		USHORT ServiceInterrupt : 1;        // The SERVICE interrupt is enabled
		USHORT DeviceReset : 1;             // Shall be cleared to zero to indicate that the DEVICE RESET command is not supported
		USHORT HostProtectedArea : 1;       // obsolete
		USHORT Obsolete1 : 1;
		USHORT WriteBuffer : 1;             // The WRITE BUFFER command is supported
		USHORT ReadBuffer : 1;              // The READ BUFFER command is supported
		USHORT Nop : 1;                     // The NOP command is supported
		USHORT Obsolete2 : 1;

		//
		// Word 86
		//
		USHORT DownloadMicrocode : 1;       // The DOWNLOAD MICROCODE command is supported
		USHORT DmaQueued : 1;               // obsolete
		USHORT Cfa : 1;                     // The CFA feature set is supported
		USHORT AdvancedPm : 1;              // The APM feature set is enabled
		USHORT Msn : 1;                     // obsolete
		USHORT PowerUpInStandby : 1;        // The PUIS feature set is enabled
		USHORT ManualPowerUp : 1;           // SET FEATURES subcommand is required to spin-up after power-up
		USHORT Reserved2 : 1;
		USHORT SetMax : 1;                  // obsolete
		USHORT Acoustics : 1;               // obsolete
		USHORT BigLba : 1;                  // The 48-bit Address features set is supported
		USHORT DeviceConfigOverlay : 1;     // obsolete
		USHORT FlushCache : 1;              // FLUSH CACHE command supported
		USHORT FlushCacheExt : 1;           // FLUSH CACHE EXT command supported
		USHORT Resrved3 : 1;
		USHORT Words119_120Valid : 1;       // Words 119..120 are valid

		//
		// Word 87
		//
		USHORT SmartErrorLog : 1;           // SMART error logging is supported
		USHORT SmartSelfTest : 1;           // SMART self-test supported
		USHORT MediaSerialNumber : 1;       // Media serial number is valid
		USHORT MediaCardPassThrough : 1;    // obsolete
		USHORT StreamingFeature : 1;        // obsolete
		USHORT GpLogging : 1;               // The GPL feature set is supported
		USHORT WriteFua : 1;                // The WRITE DMA FUA EXT and WRITE MULTIPLE FUA EXT commands are supported
		USHORT WriteQueuedFua : 1;          // obsolete
		USHORT WWN64Bit : 1;                // The 64-bit World wide name is supported
		USHORT URGReadStream : 1;           // obsolete
		USHORT URGWriteStream : 1;          // obsolete
		USHORT ReservedForTechReport : 2;
		USHORT IdleWithUnloadFeature : 1;   // The IDLE IMMEDIATE command with UNLOAD FEATURE is supported
		USHORT Reserved4 : 2;               // bit 14 shall be set to 1; bit 15 shall be cleared to 0

	}CommandSetActive;

	USHORT UltraDMASupport : 8;                 // word 88. bit 0 - UDMA mode 0 is supported ... bit 6 - UDMA mode 6 and below are supported
	USHORT UltraDMAActive : 8;                 // word 88. bit 8 - UDMA mode 0 is selected ... bit 14 - UDMA mode 6 is selected

	struct {                                    // word 89
		USHORT TimeRequired : 15;
		USHORT ExtendedTimeReported : 1;
	} NormalSecurityEraseUnit;

	struct {                                    // word 90
		USHORT TimeRequired : 15;
		USHORT ExtendedTimeReported : 1;
	} EnhancedSecurityEraseUnit;

	USHORT CurrentAPMLevel : 8;                 // word 91
	USHORT ReservedWord91 : 8;

	USHORT MasterPasswordID;                    // word 92. Master Password Identifier

	USHORT HardwareResetResult;                 // word 93

	USHORT CurrentAcousticValue : 8;            // word 94. obsolete
	USHORT RecommendedAcousticValue : 8;

	USHORT StreamMinRequestSize;                // word 95
	USHORT StreamingTransferTimeDMA;            // word 96
	USHORT StreamingAccessLatencyDMAPIO;        // word 97
	ULONG  StreamingPerfGranularity;            // word 98, 99

	ULONG  Max48BitLBA[ 2 ];                      // word 100-103

	USHORT StreamingTransferTime;               // word 104. Streaming Transfer Time - PIO

	USHORT DsmCap;                              // word 105

	struct {
		USHORT LogicalSectorsPerPhysicalSector : 4;         // n power of 2: logical sectors per physical sector
		USHORT Reserved0 : 8;
		USHORT LogicalSectorLongerThan256Words : 1;
		USHORT MultipleLogicalSectorsPerPhysicalSector : 1;
		USHORT Reserved1 : 2;                               // bit 14 - shall be set to  1; bit 15 - shall be clear to 0
	} PhysicalLogicalSectorSize;                // word 106

	USHORT InterSeekDelay;                      //word 107.     Inter-seek delay for ISO 7779 standard acoustic testing
	USHORT WorldWideName[ 4 ];                    //words 108-111
	USHORT ReservedForWorldWideName128[ 4 ];      //words 112-115
	USHORT ReservedForTlcTechnicalReport;       //word 116
	USHORT WordsPerLogicalSector[ 2 ];            //words 117-118 Logical sector size (DWord)

	struct {
		USHORT ReservedForDrqTechnicalReport : 1;
		USHORT WriteReadVerify : 1;                 // The Write-Read-Verify feature set is supported
		USHORT WriteUncorrectableExt : 1;           // The WRITE UNCORRECTABLE EXT command is supported
		USHORT ReadWriteLogDmaExt : 1;              // The READ LOG DMA EXT and WRITE LOG DMA EXT commands are supported
		USHORT DownloadMicrocodeMode3 : 1;          // Download Microcode mode 3 is supported
		USHORT FreefallControl : 1;                 // The Free-fall Control feature set is supported
		USHORT SenseDataReporting : 1;              // Sense Data Reporting feature set is supported
		USHORT ExtendedPowerConditions : 1;         // Extended Power Conditions feature set is supported
		USHORT Reserved0 : 6;
		USHORT WordValid : 2;                       // shall be 01b
	}CommandSetSupportExt;                      //word 119

	struct {
		USHORT ReservedForDrqTechnicalReport : 1;
		USHORT WriteReadVerify : 1;                 // The Write-Read-Verify feature set is enabled
		USHORT WriteUncorrectableExt : 1;           // The WRITE UNCORRECTABLE EXT command is supported
		USHORT ReadWriteLogDmaExt : 1;              // The READ LOG DMA EXT and WRITE LOG DMA EXT commands are supported
		USHORT DownloadMicrocodeMode3 : 1;          // Download Microcode mode 3 is supported
		USHORT FreefallControl : 1;                 // The Free-fall Control feature set is enabled
		USHORT SenseDataReporting : 1;              // Sense Data Reporting feature set is enabled
		USHORT ExtendedPowerConditions : 1;         // Extended Power Conditions feature set is enabled
		USHORT Reserved0 : 6;
		USHORT Reserved1 : 2;                       // bit 14 - shall be set to  1; bit 15 - shall be clear to 0
	}CommandSetActiveExt;                       //word 120

	USHORT ReservedForExpandedSupportandActive[ 6 ];

	USHORT MsnSupport : 2;                      //word 127. obsolete
	USHORT ReservedWord127 : 14;

	struct {                                    //word 128
		USHORT SecuritySupported : 1;
		USHORT SecurityEnabled : 1;
		USHORT SecurityLocked : 1;
		USHORT SecurityFrozen : 1;
		USHORT SecurityCountExpired : 1;
		USHORT EnhancedSecurityEraseSupported : 1;
		USHORT Reserved0 : 2;
		USHORT SecurityLevel : 1;                   // Master Password Capability: 0 = High, 1 = Maximum
		USHORT Reserved1 : 7;
	} SecurityStatus;

	USHORT ReservedWord129[ 31 ];                 //word 129...159. Vendor specific

	struct {                                    //word 160
		USHORT MaximumCurrentInMA : 12;
		USHORT CfaPowerMode1Disabled : 1;
		USHORT CfaPowerMode1Required : 1;
		USHORT Reserved0 : 1;
		USHORT Word160Supported : 1;
	} CfaPowerMode1;

	USHORT ReservedForCfaWord161[ 7 ];                //Words 161-167

	USHORT NominalFormFactor : 4;                   //Word 168
	USHORT ReservedWord168 : 12;

	struct {                                        //Word 169
		USHORT SupportsTrim : 1;
		USHORT Reserved0 : 15;
	} DataSetManagementFeature;

	USHORT AdditionalProductID[ 4 ];                  //Words 170-173

	USHORT ReservedForCfaWord174[ 2 ];                //Words 174-175

	USHORT CurrentMediaSerialNumber[ 30 ];            //Words 176-205

	struct {                                        //Word 206
		USHORT Supported : 1;                           // The SCT Command Transport is supported
		USHORT Reserved0 : 1;                           // obsolete
		USHORT WriteSameSuported : 1;                   // The SCT Write Same command is supported
		USHORT ErrorRecoveryControlSupported : 1;       // The SCT Error Recovery Control command is supported
		USHORT FeatureControlSuported : 1;              // The SCT Feature Control command is supported
		USHORT DataTablesSuported : 1;                  // The SCT Data Tables command is supported
		USHORT Reserved1 : 6;
		USHORT VendorSpecific : 4;
	} SCTCommandTransport;

	USHORT ReservedWord207[ 2 ];                      //Words 207-208

	struct {                                        //Word 209
		USHORT AlignmentOfLogicalWithinPhysical : 14;
		USHORT Word209Supported : 1;                     // shall be set to 1
		USHORT Reserved0 : 1;                            // shall be cleared to 0
	} BlockAlignment;

	USHORT WriteReadVerifySectorCountMode3Only[ 2 ];  //Words 210-211
	USHORT WriteReadVerifySectorCountMode2Only[ 2 ];  //Words 212-213

	struct {
		USHORT NVCachePowerModeEnabled : 1;
		USHORT Reserved0 : 3;
		USHORT NVCacheFeatureSetEnabled : 1;
		USHORT Reserved1 : 3;
		USHORT NVCachePowerModeVersion : 4;
		USHORT NVCacheFeatureSetVersion : 4;
	} NVCacheCapabilities;                  //Word 214. obsolete
	USHORT NVCacheSizeLSW;                  //Word 215. obsolete
	USHORT NVCacheSizeMSW;                  //Word 216. obsolete

	USHORT NominalMediaRotationRate;        //Word 217; value 0001h means non-rotating media.

	USHORT ReservedWord218;                 //Word 218

	struct {
		UCHAR NVCacheEstimatedTimeToSpinUpInSeconds;
		UCHAR Reserved;
	} NVCacheOptions;                       //Word 219. obsolete

	USHORT  WriteReadVerifySectorCountMode : 8;     //Word 220. Write-Read-Verify feature set current mode
	USHORT  ReservedWord220 : 8;

	USHORT  ReservedWord221;                //Word 221

	struct {                                //Word 222 Transport major version number
		USHORT  MajorVersion : 12;              // 0000h or FFFFh = device does not report version
		USHORT  TransportType : 4;
	} TransportMajorVersion;

	USHORT  TransportMinorVersion;          // Word 223

	USHORT  ReservedWord224[ 6 ];             // Word 224...229

	ULONG   ExtendedNumberOfUserAddressableSectors[ 2 ];  // Words 230...233 Extended Number of User Addressable Sectors

	USHORT  MinBlocksPerDownloadMicrocodeMode03;        // Word 234 Minimum number of 512-byte data blocks per Download Microcode mode 03h operation
	USHORT  MaxBlocksPerDownloadMicrocodeMode03;        // Word 235 Maximum number of 512-byte data blocks per Download Microcode mode 03h operation

	USHORT ReservedWord236[ 19 ];             // Word 236...254

	USHORT Signature : 8;                   //Word 255
	USHORT CheckSum : 8;

} IDENTIFY_DEVICE_DATA, * PIDENTIFY_DEVICE_DATA;
#pragma pack (pop, id_device_data)

extern "C"
{
	NTSYSAPI POBJECT_TYPE* IoDriverObjectType;

	NTSYSAPI BOOLEAN
		NTAPI
		PsIsProtectedProcess(
			_In_ PEPROCESS Process
		);

	NTSYSAPI
		BOOLEAN
		NTAPI
		PsIsSystemProcess(
			_In_ PEPROCESS Process
		);

	NTSYSAPI
		PVOID
		PsGetProcessSectionBaseAddress(
			__in PEPROCESS Process
		);

	NTSYSAPI NTSTATUS NTAPI
		ObReferenceObjectByName(
			__in PUNICODE_STRING ObjectName,
			__in ULONG Attributes,
			__in_opt PACCESS_STATE AccessState,
			__in_opt ACCESS_MASK DesiredAccess,
			__in POBJECT_TYPE ObjectType,
			__in KPROCESSOR_MODE AccessMode,
			__inout_opt PVOID ParseContext,
			__out PVOID* Object
		);

	NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_   PVOID                    SystemInformation,
		_In_      ULONG                    SystemInformationLength,
		_Out_opt_ PULONG                   ReturnLength
	);

	NTSYSAPI NTSTATUS WINAPI ZwQueryInformationProcess(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
	);
};