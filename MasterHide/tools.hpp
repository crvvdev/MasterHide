#pragma once

namespace masterhide
{
namespace tags
{
static constexpr ULONG TAG_DEFAULT = '00hm';
static constexpr ULONG TAG_STRING = '10hm';
static constexpr ULONG TAG_HASH_TABLE = '20hm';
static constexpr ULONG TAG_HASH_TABLE_ENTRY = '30hm';
static constexpr ULONG TAG_PROCESS_ENTRY = '40hm';
static constexpr ULONG TAG_PROCESS_RULE_ENTRY = '50hm';
static constexpr ULONG TAG_THREAD_ENTRY = '60hm';
static constexpr ULONG TAG_IMAGE_PATH_ENTRY = '70hm';
static constexpr ULONG TAG_HOOK = '80hm';
static constexpr ULONG TAG_ERESOURCE = '90hm';
} // namespace tags

namespace mutex
{
/// <summary>
/// Helper class for executive resouces (ERESOUCE)
/// </summary>
class EResource
{
  public:
    EResource() = default;
    ~EResource() = default;

    NTSTATUS Initialize();
    NTSTATUS Deinitialize();

    /// <summary>
    /// Obtains exclusive lock
    /// </summary>
    /// <param name="wait">Thread shoud block until lock is acquired or not</param>
    /// <returns>TRUE on success, otherwise FALSE</returns>
    BOOLEAN LockExclusive(_In_ BOOLEAN wait = TRUE);

    /// <summary>
    /// Obtains shared lock
    /// </summary>
    /// <param name="wait">Thread shoud block until lock is acquired or not</param>
    /// <returns>TRUE on success, otherwise FALSE</returns>
    BOOLEAN LockShared(_In_ BOOLEAN wait = TRUE);

    /// <summary>
    /// Unlock executive resource
    /// </summary>
    void Unlock();

    /// <summary>
    /// Get pointer to ERESOURCE
    /// </summary>
    /// <returns></returns>
    __forceinline auto Get() -> PERESOURCE
    {
        return _eresource;
    }

  private:
    bool _initialized = false;
    LONG _refCount = 0;
    PERESOURCE _eresource{};
};
} // namespace mutex

class AutoRefCount
{
  public:
    explicit AutoRefCount(LONG *refCount) : _refCount(refCount)
    {
        InterlockedIncrement(_refCount);
    }

    ~AutoRefCount()
    {
        InterlockedDecrement(_refCount);
    }

    AutoRefCount(const AutoRefCount &) = delete;
    AutoRefCount &operator=(const AutoRefCount &) = delete;

    AutoRefCount(AutoRefCount &&) = delete;
    AutoRefCount &operator=(AutoRefCount &&) = delete;

  private:
    LONG *_refCount;
};

namespace tools
{
template <class T = void *> FORCEINLINE T RipToAbsolute(_In_ ULONG_PTR rip, _In_ INT offset, _In_ INT len)
{
    return (T)(rip + len + *reinterpret_cast<INT32 *>(rip + offset));
}

/// <summary>
/// Try to find code cave in specified memory area.
/// </summary>
/// <param name="startAddress">Start address to search</param>
/// <param name="searchSize">Total number of bytes to search</param>
/// <param name="sizeNeeded">Total number of bytes needed</param>
/// <returns>Memory address to be used, otherwise nullptr</returns>
UCHAR *FindCodeCave(UCHAR *const startAddress, ULONG searchSize, ULONG sizeNeeded);

HANDLE GetProcessIdFromProcessHandle(_In_ HANDLE processHandle);
HANDLE GetProcessIdFromThreadHandle(_In_ HANDLE threadHandle);
bool HasDebugPrivilege();
void DelayThread(_In_ LONG64 milliseconds, _In_ BOOLEAN alertable = FALSE);

/// <summary>
/// Obtains full file name for PEPROCESS, on success the processImageName has to be free'd using RtlFreeUnicodeString
/// when not used anymore.
/// </summary>
/// <param name="process">Process to obtain file name</param>
/// <param name="processImageName">Full file name in NT format</param>
/// <returns>true on success, otherwise false</returns>
_Success_(return != false) bool GetProcessFileName(_In_ PEPROCESS process, _Out_ PUNICODE_STRING processImageName);

bool GetProcessFileName(_In_ HANDLE processId, _Out_ PUNICODE_STRING processImageName);
PEPROCESS GetProcessByName(_In_ LPCWSTR processName);
bool GetNtoskrnl(_Out_ PVOID *moduleBase, _Out_opt_ PULONG moduleSize);

inline void SwapEndianness(PCHAR ptr, size_t size)
{
    struct u16
    {
        UCHAR high;
        UCHAR low;
    };

    for (u16 *pStruct = (u16 *)ptr; pStruct < (u16 *)ptr + size / 2; pStruct++)
    {
        auto tmp = pStruct->low;
        pStruct->low = pStruct->high;
        pStruct->high = tmp;
    }
}

PIMAGE_SECTION_HEADER GetModuleSection(_In_ PIMAGE_NT_HEADERS64 nth, _In_ const char *secName);
PUCHAR FindPattern(PUCHAR rangeStart, PUCHAR rangeEnd, const char *pattern);
PUCHAR FindPattern(_In_ void *moduleAddress, _In_ const char *secName, _In_ const char *pattern);

template <typename T = void *> inline T RVAtoRawAddress(PIMAGE_NT_HEADERS nth, ULONG rva, PUCHAR moduleBase)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nth);

    for (int i = 0; i < nth->FileHeader.NumberOfSections; i++, section++)
    {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
        {
            return T(moduleBase + (rva - section->VirtualAddress + section->PointerToRawData));
        }
    }
    return {};
};

template <typename T = void *> inline T AllocatePoolZero(POOL_TYPE poolType, SIZE_T size, ULONG tag)
{
    void *p = ExAllocatePoolWithTag(poolType, size, tag);
    if (p)
    {
        RtlZeroMemory(p, size);
    }
    return T(p);
}

NTSTATUS MapFileInSystemSpace(_In_ PUNICODE_STRING FileName, _Out_ PVOID *MappedBase, _Out_opt_ SIZE_T *MappedSize);
bool DumpPE(PUCHAR moduleBase, PUNICODE_STRING saveFileName);

_IRQL_requires_max_(PASSIVE_LEVEL)
    _When_(NT_SUCCESS(return), _Outptr_result_buffer_(return) _At_(*systemInfo, __drv_allocatesMem(Mem))) NTSTATUS
    QuerySystemInformation(
        _In_ SYSTEM_INFORMATION_CLASS systemInfoClass,
        _Outptr_result_maybenull_ _At_(*systemInfo, _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(return))
            PVOID *systemInfo);

} // namespace tools
} // namespace masterhide