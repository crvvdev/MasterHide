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

class ReferenceGuard
{
  public:
    constexpr ReferenceGuard() : _count(0L), _event(nullptr) {};

    void IncRef()
    {
        LONG val = InterlockedIncrement(&_count);
        if (val == 0L)
        {
            KeClearEvent(_event);
        }
    }

    void DecRef()
    {
        LONG val = InterlockedDecrement(&_count);
        if (val == 0L)
        {
            KeSetEvent(_event, IO_NO_INCREMENT, FALSE);
        }
    }

    NTSTATUS Wait(_In_ PLARGE_INTEGER timeout = nullptr)
    {
        return KeWaitForSingleObject(_event, Executive, KernelMode, FALSE, timeout);
    }

    void SetEvent(_In_ PKEVENT event)
    {
        _event = event;
    }

  private:
    PKEVENT _event;
    LONG _count;
};

class ScopedReferenceGuard
{
  public:
    explicit ScopedReferenceGuard(ReferenceGuard *refGuard) : _refGuard(refGuard)
    {
        _refGuard->IncRef();
    }

    ~ScopedReferenceGuard()
    {
        _refGuard->DecRef();
    }

    ScopedReferenceGuard(const ScopedReferenceGuard &) = delete;
    ScopedReferenceGuard &operator=(const ScopedReferenceGuard &) = delete;

    ScopedReferenceGuard(ScopedReferenceGuard &&) = delete;
    ScopedReferenceGuard &operator=(ScopedReferenceGuard &&) = delete;

  private:
    ReferenceGuard *_refGuard;
};

namespace mutex
{
/// <summary>
/// Helper class for executive resouces (ERESOUCE)
/// </summary>
class EResource
{
  public:
    /// <summary>
    /// Initialize ERESOURCE class
    /// </summary>
    /// <returns>STATUS_SUCCESS on success, otherwise any NTSTATUS value</returns>
    NTSTATUS Initialize();

    /// <summary>
    /// De-initialize ERESOURCE class
    /// </summary>
    /// <returns>STATUS_SUCCESS on success, otherwise any NTSTATUS value</returns>
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
    KEVENT _event{};
    ReferenceGuard _refCount{};
    PERESOURCE _eresource = nullptr;
};
} // namespace mutex

namespace tools
{
template <class T = void *> CFORCEINLINE T RipToAbsolute(_In_ ULONG_PTR rip, _In_ INT offset, _In_ INT len)
{
    return (T)(rip + len + *reinterpret_cast<INT32 *>(rip + offset));
}

template <typename T = void *>
CFORCEINLINE T RVAtoRawAddress(const PIMAGE_NT_HEADERS nth, const ULONG rva, PUCHAR moduleBase)
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

template <typename T = void *>
CFORCEINLINE T AllocatePoolZero(const POOL_TYPE poolType, const SIZE_T size, const ULONG tag)
{
    PVOID p = ExAllocatePoolWithTag(poolType, size, tag);
    if (p)
    {
        RtlZeroMemory(p, size);
    }
    return T(p);
}

CFORCEINLINE void SwapEndianness(PCHAR ptr, size_t size)
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

/// <summary>
/// Try to find code cave in specified memory area.
/// </summary>
/// <param name="startAddress">Start address to search</param>
/// <param name="searchSize">Total number of bytes to search</param>
/// <param name="sizeNeeded">Total number of bytes needed</param>
/// <returns>Memory address to be used, otherwise nullptr</returns>
UCHAR *FindCodeCave(UCHAR *const startAddress, ULONG searchSize, ULONG sizeNeeded);

/// <summary>
/// Get process id from process handle
/// </summary>
/// <param name="processHandle">Process handle</param>
/// <returns>Process Id</returns>
HANDLE GetProcessIdFromProcessHandle(_In_ HANDLE processHandle);

/// <summary>
/// Get process id from thread handle
/// </summary>
/// <param name="threadHandle">Thread handle</param>
/// <returns>Thread Id</returns>
HANDLE GetProcessIdFromThreadHandle(_In_ HANDLE threadHandle);

/// <summary>
/// Check if current attached process has debug privileges.
/// </summary>
/// <returns>true on success, otherwise false</returns>
bool HasDebugPrivilege();

/// <summary>
/// Delay current thread execution
/// </summary>
/// <param name="milliseconds">Time in milliseconds</param>
/// <param name="alertable">Alertable</param>
void DelayThread(_In_ LONG64 milliseconds, _In_ BOOLEAN alertable = FALSE);

/// <summary>
/// Obtains full file name for PEPROCESS, on success caller has to call RtlFreeUnicodeString on processImageName when
/// not needed anymore.
/// </summary>
/// <param name="process">Process to obtain file name</param>
/// <param name="processImageName">Full file name in NT format</param>
/// <returns>true on success, otherwise false</returns>
_Success_(return != false) bool GetProcessFileName(_In_ PEPROCESS process, _Out_ PUNICODE_STRING processImageName);

/// <summary>
/// Get process file name by process id
/// </summary>
/// <param name="processId">Process id</param>
/// <param name="processImageName">Process image name</param>
/// <returns>true on success, otherwise false</returns>
bool GetProcessFileName(_In_ HANDLE processId, _Out_ PUNICODE_STRING processImageName);

/// <summary>
/// Get PEPROCESS by process name. NOTE: this function increments the object reference count
/// </summary>
/// <param name="processName">Process name</param>
/// <returns>PEPROCESS value, otherwise nullptr</returns>
PEPROCESS GetProcessByName(_In_ LPCWSTR processName);

/// <summary>
/// Get ntoskrnl.exe module base address and size
/// </summary>
/// <param name="moduleBase">Module base</param>
/// <param name="moduleSize">Module size</param>
/// <returns>true on success, otherwise false</returns>
bool GetNtoskrnl(_Out_ PVOID *moduleBase, _Out_opt_ PULONG moduleSize);

/// <summary>
/// Get module section header
/// </summary>
/// <param name="nth">NT Headers</param>
/// <param name="secName">Section name</param>
/// <returns>Pointer to PIMAGE_SECTION_HEADER, otherwise nullptr</returns>
PIMAGE_SECTION_HEADER GetModuleSection(_In_ PIMAGE_NT_HEADERS64 nth, _In_ const char *secName);

/// <summary>
/// Search for pattern in memory by range
/// </summary>
/// <param name="rangeStart">Range start</param>
/// <param name="rangeEnd">Range end</param>
/// <param name="pattern">Pattern</param>
/// <returns>Pointer to first occurence of the pattern in memory, otherwise nullptr</returns>
PUCHAR FindPattern(_In_ PUCHAR rangeStart, _In_ PUCHAR rangeEnd, _In_ const char *pattern);

/// <summary>
/// Search for pattern in memory by module address
/// </summary>
/// <param name="moduleAddress">Module address</param>
/// <param name="secName">Section name</param>
/// <param name="pattern">Pattern</param>
/// <returns>Pointer to first occurence of the pattern in memory, otherwise nullptr</returns>
PUCHAR FindPattern(_In_ void *moduleAddress, _In_ const char *secName, _In_ const char *pattern);

/// <summary>
/// Map file in system space as SEC_IMAGE, on success the caller has to call MmUnmapViewInSystemSpace on mappedBase when
/// not used anymore
/// </summary>
/// <param name="fileName">File name</param>
/// <param name="mappedBase">Mapped base</param>
/// <param name="mappedSize">Mapped size</param>
/// <returns>STATUS_SUCCESS on success, otherwise any NTSTATUS value</returns>
NTSTATUS MapFileInSystemSpace(_In_ PUNICODE_STRING fileName, _Out_ PVOID *mappedBase, _Out_opt_ PSIZE_T mappedSize);

/// <summary>
/// Dump portable executable file from memory to disk
/// </summary>
/// <param name="moduleBase">Module base</param>
/// <param name="saveFileName">Save file name</param>
/// <returns>true on success, otherwise false</returns>
bool DumpPE(_In_ PUCHAR moduleBase, _In_ PUNICODE_STRING saveFileName);

/// <summary>
/// Wrapper for ZwQuerySystemInformation that automatically allocate buffer
/// </summary>
/// <param name="systemInfoClass">System information class</param>
/// <param name="systemInfo">System information buffer</param>
/// <returns>STATUS_SUCCESS on success, otherwise any NTSTATUS value</returns>
NTSTATUS
QuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS systemInfoClass,
                       _Outptr_result_maybenull_ _At_(*systemInfo,
                                                      _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(return))
                           PVOID *systemInfo);

KPROCESSOR_MODE SetPreviousMode(KPROCESSOR_MODE NewMode, ULONG_PTR thread = __readgsqword(0x188));

} // namespace tools
} // namespace masterhide