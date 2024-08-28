#pragma once

namespace masterhide
{
namespace tags
{
static constexpr ULONG TAG_DEFAULT = '00hm';
static constexpr ULONG TAG_HASH_TABLE = '10hm';
} // namespace tags

namespace mutex
{
class EResource
{
  public:
    EResource() = default;
    ~EResource() = default;

    NTSTATUS Initialize() noexcept;
    NTSTATUS Destroy() noexcept;

    BOOLEAN LockExclusive() noexcept;
    BOOLEAN LockShared() noexcept;
    void Unlock() noexcept;

    __forceinline ERESOURCE &Get() noexcept
    {
        return this->_eresource;
    }

  private:
    bool _initialized = false;
    ERESOURCE _eresource{};
};
} // namespace mutex

namespace syscalls
{
/// <summary>
/// Initialize and fill the syscall dynamic hash table.
/// </summary>
/// <returns>true on success otherwise false</returns>
bool Init();

/// <summary>
/// Release the syscall dynamic hash table if initialized.
/// </summary>
void Destroy();

/// <summary>
/// This function returns a syscall index by service name.
/// </summary>
/// <param name="serviceName">Service name to extract syscall index from.</param>
/// <returns></returns>
USHORT GetSyscallIndexByName(_In_ LPCSTR serviceName);
} // namespace syscalls

namespace tools
{
/// <summary>
/// Try to find code cave in specified memory area.
/// </summary>
/// <param name="startAddress">Start address to search</param>
/// <param name="searchSize">Total number of bytes to search</param>
/// <param name="sizeNeeded">Total number of bytes needed</param>
/// <returns>Memory address to be used, otherwise nullptr</returns>
const UCHAR *FindCodeCave(const UCHAR *startAddress, ULONG searchSize, ULONG sizeNeeded);

HANDLE GetProcessIdFromProcessHandle(_In_ HANDLE processHandle);
HANDLE GetProcessIdFromThreadHandle(_In_ HANDLE threadHandle);
bool HasDebugPrivilege();

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
PVOID GetKernelBase();

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
} // namespace tools
} // namespace masterhide