#pragma once

#pragma warning(push)
#pragma warning(disable : 4201)

#define PROCESS_DEBUG_INHERIT 0x00000001    // default for a non-debugged process
#define PROCESS_NO_DEBUG_INHERIT 0x00000002 // default for a debugged process

typedef enum _WINDOWINFOCLASS
{
    WindowProcess,
    WindowThread,
    WindowActiveWindow,
    WindowFocusWindow,
    WindowIsHung,
    WindowClientBase,
    WindowIsForegroundThread,
#ifdef FE_IME
    WindowDefaultImeWindow,
    WindowDefaultInputContext,
#endif
} WINDOWINFOCLASS;

enum ThreadStateRoutines
{
    THREADSTATE_FOCUSWINDOW = 0,
    THREADSTATE_ACTIVEWINDOW,
    THREADSTATE_CAPTUREWINDOW,
    THREADSTATE_DEFAULTIMEWINDOW,
    THREADSTATE_DEFAULTINPUTCONTEXT,
    THREADSTATE_GETINPUTSTATE,
    THREADSTATE_GETCURSOR,
    THREADSTATE_CHANGEBITS,
    THREADSTATE_UPTIMELASTREAD,
    THREADSTATE_GETMESSAGEEXTRAINFO,
    THREADSTATE_INSENDMESSAGE,
    THREADSTATE_GETMESSAGETIME,
    THREADSTATE_FOREGROUNDTHREAD,
    THREADSTATE_IMECOMPATFLAGS,
    THREADSTATE_OLDKEYBOARDLAYOUT,
    THREADSTATE_ISWINLOGON,
    THREADSTATE_UNKNOWN_0x10,
    THREADSTATE_CHECKCONIME,
    THREADSTATE_GETTHREADINFO,
};

typedef struct _SYSTEM_SERVICE_TABLE
{
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONGLONG NumberOfServices;
    PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

#if 0
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
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    struct NON_PAGED_DEBUG_INFO *NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    union {
        USHORT SignatureLevel : 4;
        USHORT SignatureType : 3;
        USHORT Frozen : 2;
        USHORT HotPatch : 1;
        USHORT Unused : 6;
        USHORT EntireField;
    } u1;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG CoverageSectionSize;
    PVOID CoverageSection;
    PVOID LoadedImports;
    union {
        PVOID Spare;
        struct _KLDR_DATA_TABLE_ENTRY *NtDataTableEntry; // win11
    };
    ULONG SizeOfImageNotRounded;
    ULONG TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
#endif

#pragma warning(pop)

#define IDE_COMMAND_NOP 0x00
#define IDE_COMMAND_DATA_SET_MANAGEMENT 0x06
#define IDE_COMMAND_ATAPI_RESET 0x08
#define IDE_COMMAND_READ 0x20
#define IDE_COMMAND_READ_EXT 0x24
#define IDE_COMMAND_READ_DMA_EXT 0x25
#define IDE_COMMAND_READ_DMA_QUEUED_EXT 0x26
#define IDE_COMMAND_READ_MULTIPLE_EXT 0x29
#define IDE_COMMAND_READ_LOG_EXT 0x2f
#define IDE_COMMAND_WRITE 0x30
#define IDE_COMMAND_WRITE_EXT 0x34
#define IDE_COMMAND_WRITE_DMA_EXT 0x35
#define IDE_COMMAND_WRITE_DMA_QUEUED_EXT 0x36
#define IDE_COMMAND_WRITE_MULTIPLE_EXT 0x39
#define IDE_COMMAND_WRITE_DMA_FUA_EXT 0x3D
#define IDE_COMMAND_WRITE_DMA_QUEUED_FUA_EXT 0x3E
#define IDE_COMMAND_WRITE_LOG_EXT 0x3f
#define IDE_COMMAND_VERIFY 0x40
#define IDE_COMMAND_VERIFY_EXT 0x42
#define IDE_COMMAND_WRITE_LOG_DMA_EXT 0x57
#define IDE_COMMAND_TRUSTED_NON_DATA 0x5B
#define IDE_COMMAND_TRUSTED_RECEIVE 0x5C
#define IDE_COMMAND_TRUSTED_RECEIVE_DMA 0x5D
#define IDE_COMMAND_TRUSTED_SEND 0x5E
#define IDE_COMMAND_TRUSTED_SEND_DMA 0x5F
#define IDE_COMMAND_READ_FPDMA_QUEUED 0x60    // NCQ Read command
#define IDE_COMMAND_WRITE_FPDMA_QUEUED 0x61   // NCQ Write command
#define IDE_COMMAND_NCQ_NON_DATA 0x63         // NCQ Non-Data command
#define IDE_COMMAND_SEND_FPDMA_QUEUED 0x64    // NCQ Send command
#define IDE_COMMAND_RECEIVE_FPDMA_QUEUED 0x65 // NCQ Receive command
#define IDE_COMMAND_SET_DATE_AND_TIME 0x77    // optional 48bit command
#define IDE_COMMAND_EXECUTE_DEVICE_DIAGNOSTIC 0x90
#define IDE_COMMAND_SET_DRIVE_PARAMETERS 0x91
#define IDE_COMMAND_ATAPI_PACKET 0xA0
#define IDE_COMMAND_ATAPI_IDENTIFY 0xA1
#define IDE_COMMAND_SMART 0xB0
#define IDE_COMMAND_READ_LOG_DMA_EXT 0xB1
#define IDE_COMMAND_SANITIZE_DEVICE 0xB4
#define IDE_COMMAND_READ_MULTIPLE 0xC4
#define IDE_COMMAND_WRITE_MULTIPLE 0xC5
#define IDE_COMMAND_SET_MULTIPLE 0xC6
#define IDE_COMMAND_READ_DMA 0xC8
#define IDE_COMMAND_WRITE_DMA 0xCA
#define IDE_COMMAND_WRITE_DMA_QUEUED 0xCC
#define IDE_COMMAND_WRITE_MULTIPLE_FUA_EXT 0xCE
#define IDE_COMMAND_GET_MEDIA_STATUS 0xDA
#define IDE_COMMAND_DOOR_LOCK 0xDE
#define IDE_COMMAND_DOOR_UNLOCK 0xDF
#define IDE_COMMAND_STANDBY_IMMEDIATE 0xE0
#define IDE_COMMAND_IDLE_IMMEDIATE 0xE1
#define IDE_COMMAND_CHECK_POWER 0xE5
#define IDE_COMMAND_SLEEP 0xE6
#define IDE_COMMAND_FLUSH_CACHE 0xE7
#define IDE_COMMAND_FLUSH_CACHE_EXT 0xEA
#define IDE_COMMAND_IDENTIFY 0xEC
#define IDE_COMMAND_MEDIA_EJECT 0xED
#define IDE_COMMAND_SET_FEATURE 0xEF
#define IDE_COMMAND_SECURITY_SET_PASSWORD 0xF1
#define IDE_COMMAND_SECURITY_UNLOCK 0xF2
#define IDE_COMMAND_SECURITY_ERASE_PREPARE 0xF3
#define IDE_COMMAND_SECURITY_ERASE_UNIT 0xF4
#define IDE_COMMAND_SECURITY_FREEZE_LOCK 0xF5
#define IDE_COMMAND_SECURITY_DISABLE_PASSWORD 0xF6
#define IDE_COMMAND_NOT_VALID 0xFF

#define IDE_STATUS_ERROR 0x01
#define IDE_STATUS_INDEX 0x02
#define IDE_STATUS_CORRECTED_ERROR 0x04
#define IDE_STATUS_DRQ 0x08
#define IDE_STATUS_DSC 0x10
#define IDE_STATUS_DEVICE_FAULT 0x20
#define IDE_STATUS_DRDY 0x40
#define IDE_STATUS_IDLE 0x50
#define IDE_STATUS_BUSY 0x80

typedef struct _IDSECTOR
{
    USHORT wGenConfig;
    USHORT wNumCyls;
    USHORT wReserved;
    USHORT wNumHeads;
    USHORT wBytesPerTrack;
    USHORT wBytesPerSector;
    USHORT wSectorsPerTrack;
    USHORT wVendorUnique[3];
    CHAR sSerialNumber[20];
    USHORT wBufferType;
    USHORT wBufferSize;
    USHORT wECCSize;
    CHAR sFirmwareRev[8];
    CHAR sModelNumber[40];
    USHORT wMoreVendorUnique;
    USHORT wDoubleWordIO;
    USHORT wCapabilities;
    USHORT wReserved1;
    USHORT wPIOTiming;
    USHORT wDMATiming;
    USHORT wBS;
    USHORT wNumCurrentCyls;
    USHORT wNumCurrentHeads;
    USHORT wNumCurrentSectorsPerTrack;
    ULONG ulCurrentSectorCapacity;
    USHORT wMultSectorStuff;
    ULONG ulTotalAddressableSectors;
    USHORT wSingleWordDMA;
    USHORT wMultiWordDMA;
    UCHAR bReserved[128];
} IDSECTOR, *PIDSECTOR;

#pragma pack(push, id_device_data, 1)
typedef struct _IDENTIFY_DEVICE_DATA
{
    struct
    {
        USHORT Reserved1 : 1;
        USHORT Retired3 : 1;
        USHORT ResponseIncomplete : 1;
        USHORT Retired2 : 3;
        USHORT FixedDevice : 1;    // obsolete
        USHORT RemovableMedia : 1; // obsolete
        USHORT Retired1 : 7;
        USHORT DeviceType : 1;
    } GeneralConfiguration; // word 0

    USHORT NumCylinders;          // word 1, obsolete
    USHORT SpecificConfiguration; // word 2
    USHORT NumHeads;              // word 3, obsolete
    USHORT Retired1[2];
    USHORT NumSectorsPerTrack; // word 6, obsolete
    USHORT VendorUnique1[3];
    UCHAR SerialNumber[20]; // word 10-19
    USHORT Retired2[2];
    USHORT Obsolete1;
    UCHAR FirmwareRevision[8];  // word 23-26
    UCHAR ModelNumber[40];      // word 27-46
    UCHAR MaximumBlockTransfer; // word 47. 01h-10h = Maximum number of sectors that shall be transferred per interrupt
                                // on READ/WRITE MULTIPLE commands
    UCHAR VendorUnique2;

    struct
    {
        USHORT FeatureSupported : 1;
        USHORT Reserved : 15;
    } TrustedComputing; // word 48

    struct
    {
        UCHAR CurrentLongPhysicalSectorAlignment : 2;
        UCHAR ReservedByte49 : 6;

        UCHAR DmaSupported : 1;
        UCHAR LbaSupported : 1; // Shall be set to one to indicate that LBA is supported.
        UCHAR IordyDisable : 1;
        UCHAR IordySupported : 1;
        UCHAR Reserved1 : 1; // Reserved for the IDENTIFY PACKET DEVICE command
        UCHAR StandybyTimerSupport : 1;
        UCHAR Reserved2 : 2; // Reserved for the IDENTIFY PACKET DEVICE command

        USHORT ReservedWord50;
    } Capabilities; // word 49-50

    USHORT ObsoleteWords51[2];

    USHORT TranslationFieldsValid : 3; // word 53, bit 0 - Obsolete; bit 1 - words 70:64 valid; bit 2; word 88 valid
    USHORT Reserved3 : 5;
    USHORT FreeFallControlSensitivity : 8;

    USHORT NumberOfCurrentCylinders; // word 54, obsolete
    USHORT NumberOfCurrentHeads;     // word 55, obsolete
    USHORT CurrentSectorsPerTrack;   // word 56, obsolete
    ULONG CurrentSectorCapacity;     // word 57, word 58, obsolete

    UCHAR CurrentMultiSectorSetting; // word 59
    UCHAR MultiSectorSettingValid : 1;
    UCHAR ReservedByte59 : 3;
    UCHAR SanitizeFeatureSupported : 1;
    UCHAR CryptoScrambleExtCommandSupported : 1;
    UCHAR OverwriteExtCommandSupported : 1;
    UCHAR BlockEraseExtCommandSupported : 1;

    ULONG UserAddressableSectors; // word 60-61, for 28-bit commands

    USHORT ObsoleteWord62;

    USHORT MultiWordDMASupport : 8; // word 63
    USHORT MultiWordDMAActive : 8;

    USHORT AdvancedPIOModes : 8; // word 64. bit 0:1 - PIO mode supported
    USHORT ReservedByte64 : 8;

    USHORT MinimumMWXferCycleTime;     // word 65
    USHORT RecommendedMWXferCycleTime; // word 66
    USHORT MinimumPIOCycleTime;        // word 67
    USHORT MinimumPIOCycleTimeIORDY;   // word 68

    struct
    {
        USHORT Reserved : 2;
        USHORT NonVolatileWriteCache : 1; // All write cache is non-volatile
        USHORT ExtendedUserAddressableSectorsSupported : 1;
        USHORT DeviceEncryptsAllUserData : 1;
        USHORT ReadZeroAfterTrimSupported : 1;
        USHORT Optional28BitCommandsSupported : 1;
        USHORT IEEE1667 : 1; // Reserved for IEEE 1667
        USHORT DownloadMicrocodeDmaSupported : 1;
        USHORT SetMaxSetPasswordUnlockDmaSupported : 1;
        USHORT WriteBufferDmaSupported : 1;
        USHORT ReadBufferDmaSupported : 1;
        USHORT DeviceConfigIdentifySetDmaSupported : 1; // obsolete
        USHORT LPSAERCSupported : 1; // Long Physical Sector Alignment Error Reporting Control is supported.
        USHORT DeterministicReadAfterTrimSupported : 1;
        USHORT CFastSpecSupported : 1;
    } AdditionalSupported; // word 69

    USHORT ReservedWords70[5]; // word 70 - reserved
    // word 71:74 - Reserved for the IDENTIFY PACKET DEVICE command

    // Word 75
    USHORT QueueDepth : 5; //  Maximum queue depth - 1
    USHORT ReservedWord75 : 11;

    struct
    {
        // Word 76
        USHORT Reserved0 : 1; // shall be set to 0
        USHORT SataGen1 : 1;  // Supports SATA Gen1 Signaling Speed (1.5Gb/s)
        USHORT SataGen2 : 1;  // Supports SATA Gen2 Signaling Speed (3.0Gb/s)
        USHORT SataGen3 : 1;  // Supports SATA Gen3 Signaling Speed (6.0Gb/s)

        USHORT Reserved1 : 4;

        USHORT NCQ : 1;       // Supports the NCQ feature set
        USHORT HIPM : 1;      // Supports HIPM
        USHORT PhyEvents : 1; // Supports the SATA Phy Event Counters log
        USHORT NcqUnload : 1; // Supports Unload while NCQ commands are outstanding

        USHORT NcqPriority : 1;  // Supports NCQ priority information
        USHORT HostAutoPS : 1;   // Supports Host Automatic Partial to Slumber transitions
        USHORT DeviceAutoPS : 1; // Supports Device Automatic Partial to Slumber transitions
        USHORT ReadLogDMA : 1;   // Supports READ LOG DMA EXT as equivalent to READ LOG EXT

        // Word 77
        USHORT Reserved2 : 1;    // shall be set to 0
        USHORT CurrentSpeed : 3; // Coded value indicating current negotiated Serial ATA signal speed

        USHORT NcqStreaming : 1;   // Supports NCQ Streaming
        USHORT NcqQueueMgmt : 1;   // Supports NCQ Queue Management Command
        USHORT NcqReceiveSend : 1; // Supports RECEIVE FPDMA QUEUED and SEND FPDMA QUEUED commands
        USHORT DEVSLPtoReducedPwrState : 1;

        USHORT Reserved3 : 8;
    } SerialAtaCapabilities;

    // Word 78
    struct
    {
        USHORT Reserved0 : 1;            // shall be set to 0
        USHORT NonZeroOffsets : 1;       // Device supports non-zero buffer offsets in DMA Setup FIS
        USHORT DmaSetupAutoActivate : 1; // Device supports DMA Setup auto-activation
        USHORT DIPM : 1;                 // Device supports DIPM

        USHORT InOrderData : 1;                  // Device supports in-order data delivery
        USHORT HardwareFeatureControl : 1;       // Hardware Feature Control is supported
        USHORT SoftwareSettingsPreservation : 1; // Device supports Software Settings Preservation
        USHORT NCQAutosense : 1;                 // Supports NCQ Autosense

        USHORT DEVSLP : 1;            // Device supports link power state - device sleep
        USHORT HybridInformation : 1; // Device supports Hybrid Information Feature (If the device does not support NCQ
                                      // (word 76 bit 8 is 0), then this bit shall be cleared to 0.)

        USHORT Reserved1 : 6;
    } SerialAtaFeaturesSupported;

    // Word 79
    struct
    {
        USHORT Reserved0 : 1;            // shall be set to 0
        USHORT NonZeroOffsets : 1;       // Non-zero buffer offsets in DMA Setup FIS enabled
        USHORT DmaSetupAutoActivate : 1; // DMA Setup auto-activation optimization enabled
        USHORT DIPM : 1;                 // DIPM enabled

        USHORT InOrderData : 1;                  // In-order data delivery enabled
        USHORT HardwareFeatureControl : 1;       // Hardware Feature Control is enabled
        USHORT SoftwareSettingsPreservation : 1; // Software Settings Preservation enabled
        USHORT DeviceAutoPS : 1;                 // Device Automatic Partial to Slumber transitions enabled

        USHORT DEVSLP : 1;            // link power state - device sleep is enabled
        USHORT HybridInformation : 1; // Hybrid Information Feature is enabled

        USHORT Reserved1 : 6;
    } SerialAtaFeaturesEnabled;

    USHORT MajorRevision; // word 80. bit 5 - supports ATA5; bit 6 - supports ATA6; bit 7 - supports ATA7; bit 8 -
                          // supports ATA8-ACS; bit 9 - supports ACS-2;
    USHORT MinorRevision; // word 81. T13 minior version number

    struct
    {

        //
        // Word 82
        //
        USHORT SmartCommands : 1;         // The SMART feature set is supported
        USHORT SecurityMode : 1;          // The Security feature set is supported
        USHORT RemovableMediaFeature : 1; // obsolete
        USHORT PowerManagement : 1;       // shall be set to 1
        USHORT Reserved1 : 1;  // PACKET feature set, set to 0 indicates not supported for ATA devices (only support for
                               // ATAPI devices)
        USHORT WriteCache : 1; // The volatile write cache is supported
        USHORT LookAhead : 1;  // Read look-ahead is supported
        USHORT ReleaseInterrupt : 1; // obsolete
        USHORT ServiceInterrupt : 1; // obsolete
        USHORT DeviceReset : 1; // Shall be cleared to zero to indicate that the DEVICE RESET command is not supported
        USHORT HostProtectedArea : 1; // obsolete
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1; // The WRITE BUFFER command is supported
        USHORT ReadBuffer : 1;  // The READ BUFFER command is supported
        USHORT Nop : 1;         // The NOP command is supported
        USHORT Obsolete2 : 1;

        //
        // Word 83
        //
        USHORT DownloadMicrocode : 1; // The DOWNLOAD MICROCODE command is supported
        USHORT DmaQueued : 1;         // obsolete
        USHORT Cfa : 1;               // The CFA feature set is supported
        USHORT AdvancedPm : 1;        // The APM feature set is supported
        USHORT Msn : 1;               // obsolete
        USHORT PowerUpInStandby : 1;  // The PUIS feature set is supported
        USHORT ManualPowerUp : 1;     // SET FEATURES subcommand is required to spin-up after power-up
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;              // obsolete
        USHORT Acoustics : 1;           // obsolete
        USHORT BigLba : 1;              // The 48-bit Address feature set is supported
        USHORT DeviceConfigOverlay : 1; // obsolete
        USHORT FlushCache : 1;    // Shall be set to one to indicate that the mandatory FLUSH CACHE command is supported
        USHORT FlushCacheExt : 1; // The FLUSH CACHE EXT command is supported
        USHORT WordValid83 : 2;   // shall be 01b

        //
        // Word 84
        //
        USHORT SmartErrorLog : 1;        // SMART error logging is supported
        USHORT SmartSelfTest : 1;        // The SMART self-test is supported
        USHORT MediaSerialNumber : 1;    // Media serial number is supported
        USHORT MediaCardPassThrough : 1; // obsolete
        USHORT StreamingFeature : 1;     // The Streaming feature set is supported
        USHORT GpLogging : 1;            // The GPL feature set is supported
        USHORT WriteFua : 1;             // The WRITE DMA FUA EXT and WRITE MULTIPLE FUA EXT commands are supported
        USHORT WriteQueuedFua : 1;       // obsolete
        USHORT WWN64Bit : 1;             // The 64-bit World wide name is supported
        USHORT URGReadStream : 1;        // obsolete
        USHORT URGWriteStream : 1;       // obsolete
        USHORT ReservedForTechReport : 2;
        USHORT IdleWithUnloadFeature : 1; // The IDLE IMMEDIATE command with UNLOAD feature is supported
        USHORT WordValid : 2;             // shall be 01b

    } CommandSetSupport;

    struct
    {

        //
        // Word 85
        //
        USHORT SmartCommands : 1;         // The SMART feature set is enabled
        USHORT SecurityMode : 1;          // The Security feature set is enabled
        USHORT RemovableMediaFeature : 1; // obsolete
        USHORT PowerManagement : 1; // Shall be set to one to indicate that the mandatory Power Management feature set
                                    // is supported
        USHORT Reserved1 : 1;       // Shall be cleared to zero to indicate that the PACKET feature set is not supported
        USHORT WriteCache : 1;      // The volatile write cache is enabled
        USHORT LookAhead : 1;       // Read look-ahead is enabled
        USHORT ReleaseInterrupt : 1; // The release interrupt is enabled
        USHORT ServiceInterrupt : 1; // The SERVICE interrupt is enabled
        USHORT DeviceReset : 1; // Shall be cleared to zero to indicate that the DEVICE RESET command is not supported
        USHORT HostProtectedArea : 1; // obsolete
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1; // The WRITE BUFFER command is supported
        USHORT ReadBuffer : 1;  // The READ BUFFER command is supported
        USHORT Nop : 1;         // The NOP command is supported
        USHORT Obsolete2 : 1;

        //
        // Word 86
        //
        USHORT DownloadMicrocode : 1; // The DOWNLOAD MICROCODE command is supported
        USHORT DmaQueued : 1;         // obsolete
        USHORT Cfa : 1;               // The CFA feature set is supported
        USHORT AdvancedPm : 1;        // The APM feature set is enabled
        USHORT Msn : 1;               // obsolete
        USHORT PowerUpInStandby : 1;  // The PUIS feature set is enabled
        USHORT ManualPowerUp : 1;     // SET FEATURES subcommand is required to spin-up after power-up
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;              // obsolete
        USHORT Acoustics : 1;           // obsolete
        USHORT BigLba : 1;              // The 48-bit Address features set is supported
        USHORT DeviceConfigOverlay : 1; // obsolete
        USHORT FlushCache : 1;          // FLUSH CACHE command supported
        USHORT FlushCacheExt : 1;       // FLUSH CACHE EXT command supported
        USHORT Resrved3 : 1;
        USHORT Words119_120Valid : 1; // Words 119..120 are valid

        //
        // Word 87
        //
        USHORT SmartErrorLog : 1;        // SMART error logging is supported
        USHORT SmartSelfTest : 1;        // SMART self-test supported
        USHORT MediaSerialNumber : 1;    // Media serial number is valid
        USHORT MediaCardPassThrough : 1; // obsolete
        USHORT StreamingFeature : 1;     // obsolete
        USHORT GpLogging : 1;            // The GPL feature set is supported
        USHORT WriteFua : 1;             // The WRITE DMA FUA EXT and WRITE MULTIPLE FUA EXT commands are supported
        USHORT WriteQueuedFua : 1;       // obsolete
        USHORT WWN64Bit : 1;             // The 64-bit World wide name is supported
        USHORT URGReadStream : 1;        // obsolete
        USHORT URGWriteStream : 1;       // obsolete
        USHORT ReservedForTechReport : 2;
        USHORT IdleWithUnloadFeature : 1; // The IDLE IMMEDIATE command with UNLOAD FEATURE is supported
        USHORT Reserved4 : 2;             // bit 14 shall be set to 1; bit 15 shall be cleared to 0

    } CommandSetActive;

    USHORT UltraDMASupport : 8; // word 88. bit 0 - UDMA mode 0 is supported ... bit 6 - UDMA mode 6 and below are
                                // supported
    USHORT UltraDMAActive : 8;  // word 88. bit 8 - UDMA mode 0 is selected ... bit 14 - UDMA mode 6 is selected

    struct
    { // word 89
        USHORT TimeRequired : 15;
        USHORT ExtendedTimeReported : 1;
    } NormalSecurityEraseUnit;

    struct
    { // word 90
        USHORT TimeRequired : 15;
        USHORT ExtendedTimeReported : 1;
    } EnhancedSecurityEraseUnit;

    USHORT CurrentAPMLevel : 8; // word 91
    USHORT ReservedWord91 : 8;

    USHORT MasterPasswordID; // word 92. Master Password Identifier

    USHORT HardwareResetResult; // word 93

    USHORT CurrentAcousticValue : 8; // word 94. obsolete
    USHORT RecommendedAcousticValue : 8;

    USHORT StreamMinRequestSize;         // word 95
    USHORT StreamingTransferTimeDMA;     // word 96
    USHORT StreamingAccessLatencyDMAPIO; // word 97
    ULONG StreamingPerfGranularity;      // word 98, 99

    ULONG Max48BitLBA[2]; // word 100-103

    USHORT StreamingTransferTime; // word 104. Streaming Transfer Time - PIO

    USHORT DsmCap; // word 105

    struct
    {
        USHORT LogicalSectorsPerPhysicalSector : 4; // n power of 2: logical sectors per physical sector
        USHORT Reserved0 : 8;
        USHORT LogicalSectorLongerThan256Words : 1;
        USHORT MultipleLogicalSectorsPerPhysicalSector : 1;
        USHORT Reserved1 : 2;    // bit 14 - shall be set to  1; bit 15 - shall be clear to 0
    } PhysicalLogicalSectorSize; // word 106

    USHORT InterSeekDelay;                 // word 107.     Inter-seek delay for ISO 7779 standard acoustic testing
    USHORT WorldWideName[4];               // words 108-111
    USHORT ReservedForWorldWideName128[4]; // words 112-115
    USHORT ReservedForTlcTechnicalReport;  // word 116
    USHORT WordsPerLogicalSector[2];       // words 117-118 Logical sector size (DWord)

    struct
    {
        USHORT ReservedForDrqTechnicalReport : 1;
        USHORT WriteReadVerify : 1;         // The Write-Read-Verify feature set is supported
        USHORT WriteUncorrectableExt : 1;   // The WRITE UNCORRECTABLE EXT command is supported
        USHORT ReadWriteLogDmaExt : 1;      // The READ LOG DMA EXT and WRITE LOG DMA EXT commands are supported
        USHORT DownloadMicrocodeMode3 : 1;  // Download Microcode mode 3 is supported
        USHORT FreefallControl : 1;         // The Free-fall Control feature set is supported
        USHORT SenseDataReporting : 1;      // Sense Data Reporting feature set is supported
        USHORT ExtendedPowerConditions : 1; // Extended Power Conditions feature set is supported
        USHORT Reserved0 : 6;
        USHORT WordValid : 2; // shall be 01b
    } CommandSetSupportExt;   // word 119

    struct
    {
        USHORT ReservedForDrqTechnicalReport : 1;
        USHORT WriteReadVerify : 1;         // The Write-Read-Verify feature set is enabled
        USHORT WriteUncorrectableExt : 1;   // The WRITE UNCORRECTABLE EXT command is supported
        USHORT ReadWriteLogDmaExt : 1;      // The READ LOG DMA EXT and WRITE LOG DMA EXT commands are supported
        USHORT DownloadMicrocodeMode3 : 1;  // Download Microcode mode 3 is supported
        USHORT FreefallControl : 1;         // The Free-fall Control feature set is enabled
        USHORT SenseDataReporting : 1;      // Sense Data Reporting feature set is enabled
        USHORT ExtendedPowerConditions : 1; // Extended Power Conditions feature set is enabled
        USHORT Reserved0 : 6;
        USHORT Reserved1 : 2; // bit 14 - shall be set to  1; bit 15 - shall be clear to 0
    } CommandSetActiveExt;    // word 120

    USHORT ReservedForExpandedSupportandActive[6];

    USHORT MsnSupport : 2; // word 127. obsolete
    USHORT ReservedWord127 : 14;

    struct
    { // word 128
        USHORT SecuritySupported : 1;
        USHORT SecurityEnabled : 1;
        USHORT SecurityLocked : 1;
        USHORT SecurityFrozen : 1;
        USHORT SecurityCountExpired : 1;
        USHORT EnhancedSecurityEraseSupported : 1;
        USHORT Reserved0 : 2;
        USHORT SecurityLevel : 1; // Master Password Capability: 0 = High, 1 = Maximum
        USHORT Reserved1 : 7;
    } SecurityStatus;

    USHORT ReservedWord129[31]; // word 129...159. Vendor specific

    struct
    { // word 160
        USHORT MaximumCurrentInMA : 12;
        USHORT CfaPowerMode1Disabled : 1;
        USHORT CfaPowerMode1Required : 1;
        USHORT Reserved0 : 1;
        USHORT Word160Supported : 1;
    } CfaPowerMode1;

    USHORT ReservedForCfaWord161[7]; // Words 161-167

    USHORT NominalFormFactor : 4; // Word 168
    USHORT ReservedWord168 : 12;

    struct
    { // Word 169
        USHORT SupportsTrim : 1;
        USHORT Reserved0 : 15;
    } DataSetManagementFeature;

    USHORT AdditionalProductID[4]; // Words 170-173

    USHORT ReservedForCfaWord174[2]; // Words 174-175

    USHORT CurrentMediaSerialNumber[30]; // Words 176-205

    struct
    {                                             // Word 206
        USHORT Supported : 1;                     // The SCT Command Transport is supported
        USHORT Reserved0 : 1;                     // obsolete
        USHORT WriteSameSuported : 1;             // The SCT Write Same command is supported
        USHORT ErrorRecoveryControlSupported : 1; // The SCT Error Recovery Control command is supported
        USHORT FeatureControlSuported : 1;        // The SCT Feature Control command is supported
        USHORT DataTablesSuported : 1;            // The SCT Data Tables command is supported
        USHORT Reserved1 : 6;
        USHORT VendorSpecific : 4;
    } SCTCommandTransport;

    USHORT ReservedWord207[2]; // Words 207-208

    struct
    { // Word 209
        USHORT AlignmentOfLogicalWithinPhysical : 14;
        USHORT Word209Supported : 1; // shall be set to 1
        USHORT Reserved0 : 1;        // shall be cleared to 0
    } BlockAlignment;

    USHORT WriteReadVerifySectorCountMode3Only[2]; // Words 210-211
    USHORT WriteReadVerifySectorCountMode2Only[2]; // Words 212-213

    struct
    {
        USHORT NVCachePowerModeEnabled : 1;
        USHORT Reserved0 : 3;
        USHORT NVCacheFeatureSetEnabled : 1;
        USHORT Reserved1 : 3;
        USHORT NVCachePowerModeVersion : 4;
        USHORT NVCacheFeatureSetVersion : 4;
    } NVCacheCapabilities; // Word 214. obsolete
    USHORT NVCacheSizeLSW; // Word 215. obsolete
    USHORT NVCacheSizeMSW; // Word 216. obsolete

    USHORT NominalMediaRotationRate; // Word 217; value 0001h means non-rotating media.

    USHORT ReservedWord218; // Word 218

    struct
    {
        UCHAR NVCacheEstimatedTimeToSpinUpInSeconds;
        UCHAR Reserved;
    } NVCacheOptions; // Word 219. obsolete

    USHORT WriteReadVerifySectorCountMode : 8; // Word 220. Write-Read-Verify feature set current mode
    USHORT ReservedWord220 : 8;

    USHORT ReservedWord221; // Word 221

    struct
    {                             // Word 222 Transport major version number
        USHORT MajorVersion : 12; // 0000h or FFFFh = device does not report version
        USHORT TransportType : 4;
    } TransportMajorVersion;

    USHORT TransportMinorVersion; // Word 223

    USHORT ReservedWord224[6]; // Word 224...229

    ULONG ExtendedNumberOfUserAddressableSectors[2]; // Words 230...233 Extended Number of User Addressable Sectors

    USHORT MinBlocksPerDownloadMicrocodeMode03; // Word 234 Minimum number of 512-byte data blocks per Download
                                                // Microcode mode 03h operation
    USHORT MaxBlocksPerDownloadMicrocodeMode03; // Word 235 Maximum number of 512-byte data blocks per Download
                                                // Microcode mode 03h operation

    USHORT ReservedWord236[19]; // Word 236...254

    USHORT Signature : 8; // Word 255
    USHORT CheckSum : 8;

} IDENTIFY_DEVICE_DATA, *PIDENTIFY_DEVICE_DATA;
#pragma pack(pop, id_device_data)

typedef struct _IMAGE_DOS_HEADER
{                      // DOS .EXE header
    USHORT e_magic;    // Magic number
    USHORT e_cblp;     // Bytes on last page of file
    USHORT e_cp;       // Pages in file
    USHORT e_crlc;     // Relocations
    USHORT e_cparhdr;  // Size of header in paragraphs
    USHORT e_minalloc; // Minimum extra paragraphs needed
    USHORT e_maxalloc; // Maximum extra paragraphs needed
    USHORT e_ss;       // Initial (relative) SS value
    USHORT e_sp;       // Initial SP value
    USHORT e_csum;     // Checksum
    USHORT e_ip;       // Initial IP value
    USHORT e_cs;       // Initial (relative) CS value
    USHORT e_lfarlc;   // File address of relocation table
    USHORT e_ovno;     // Overlay number
    USHORT e_res[4];   // Reserved words
    USHORT e_oemid;    // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;  // OEM information; e_oemid specific
    USHORT e_res2[10]; // Reserved words
    LONG e_lfanew;     // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER 20

#define IMAGE_FILE_RELOCS_STRIPPED 0x0001         // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002        // File is executable  (i.e. no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004      // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008     // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010       // Aggressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020     // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080       // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE 0x0100           // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200          // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400 // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800       // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM 0x1000                  // System File.
#define IMAGE_FILE_DLL 0x2000                     // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000          // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000       // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN 0
#define IMAGE_FILE_MACHINE_TARGET_HOST                                                                                 \
    0x0001                               // Useful for indicating we want to interact with the host and not a WoW guest.
#define IMAGE_FILE_MACHINE_I386 0x014c   // Intel 386.
#define IMAGE_FILE_MACHINE_R3000 0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000 0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000 0x0168 // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169 // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA 0x0184     // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3 0x01a2       // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP 0x01a3
#define IMAGE_FILE_MACHINE_SH3E 0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4 0x01a6   // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5 0x01a8   // SH5
#define IMAGE_FILE_MACHINE_ARM 0x01c0   // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB 0x01c2 // ARM Thumb/Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4 // ARM Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_AM33 0x01d3
#define IMAGE_FILE_MACHINE_POWERPC 0x01F0 // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#define IMAGE_FILE_MACHINE_IA64 0x0200      // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16 0x0266    // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64 0x0284   // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU 0x0366   // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x0466 // MIPS
#define IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE 0x0520 // Infineon
#define IMAGE_FILE_MACHINE_CEF 0x0CEF
#define IMAGE_FILE_MACHINE_EBC 0x0EBC   // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64 0x8664 // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R 0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_ARM64 0xAA64 // ARM64 Little-Endian
#define IMAGE_FILE_MACHINE_CEE 0xC0EE

#define IMAGE_FILE_MACHINE_CHPE_X86 0x3A64
#define IMAGE_FILE_MACHINE_ARM64EC 0xA641
#define IMAGE_FILE_MACHINE_ARM64X 0xA64E

typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER
{
    //
    // Standard fields.
    //

    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONG BaseOfData;

    //
    // NT additional fields.
    //

    ULONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONG SizeOfStackReserve;
    ULONG SizeOfStackCommit;
    ULONG SizeOfHeapReserve;
    ULONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONGLONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC 0x107

#ifdef _WIN64
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif

typedef struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS
{
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

#define IMAGE_FIRST_SECTION(ntheader)                                                                                  \
    ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +                  \
                             ((ntheader))->FileHeader.SizeOfOptionalHeader))

// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN 0     // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE 1      // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2 // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3 // Image runs in the Windows character subsystem.
// end_winnt
// reserved                                  4   // Old Windows CE subsystem.
// begin_winnt
#define IMAGE_SUBSYSTEM_OS2_CUI 5                  // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI 7                // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8           // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9           // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10         //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11 //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12      //
#define IMAGE_SUBSYSTEM_EFI_ROM 13
#define IMAGE_SUBSYSTEM_XBOX 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG 17

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020 // Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040    // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080 // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100       // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200    // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400       // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800      // Do not bind this image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000 // Image should execute in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000   // Driver uses WDM model
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000     // Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

// Note: The Borland linker sets IMAGE_LIBRARY_xxx flags in DllCharacteristics

// LoaderFlags Values

#define IMAGE_LOADER_FLAGS_COMPLUS 0x00000001       // COM+ image
#define IMAGE_LOADER_FLAGS_SYSTEM_GLOBAL 0x01000000 // Global subsections apply across TS sessions.

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0    // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1    // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2  // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3 // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4  // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5 // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6     // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7    // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8       // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS 9             // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10    // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT 12            // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14 // COM Runtime descriptor

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER
{
    UCHAR Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        ULONG PhysicalAddress;
        ULONG VirtualSize;
    } Misc;
    ULONG VirtualAddress;
    ULONG SizeOfRawData;
    ULONG PointerToRawData;
    ULONG PointerToRelocations;
    ULONG PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER 40

EXTERN_C_START

NTSYSAPI BOOLEAN NTAPI PsIsProtectedProcess(_In_ PEPROCESS Process);

NTSYSAPI
BOOLEAN
NTAPI
PsIsSystemProcess(_In_ PEPROCESS Process);

NTSYSAPI
PVOID NTAPI PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(__in PUNICODE_STRING ObjectName, __in ULONG Attributes,
                                                __in_opt PACCESS_STATE AccessState, __in_opt ACCESS_MASK DesiredAccess,
                                                __in POBJECT_TYPE ObjectType, __in KPROCESSOR_MODE AccessMode,
                                                __inout_opt PVOID ParseContext, __out PVOID *Object);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                 _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength,
                                                 _Out_opt_ PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(_In_ HANDLE ProcessHandle,
                                                  _In_ PROCESSINFOCLASS ProcessInformationClass,
                                                  _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength,
                                                  _Out_opt_ PULONG ReturnLength);

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(IN PVOID ModuleAddress);

EXTERN_C_END