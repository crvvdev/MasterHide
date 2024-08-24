#include "includes.hpp"

PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable = NULL;

ULONGLONG GetKeServiceDescriptorTable64()
{
    PUCHAR pStartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
    PUCHAR pEndSearchAddress = (PUCHAR)(((ULONG_PTR)pStartSearchAddress + PAGE_SIZE) & (~0x0FFF));
    PULONG pFindCodeAddress = NULL;

    while (++pStartSearchAddress < pEndSearchAddress)
    {
        if ((*(PULONG)pStartSearchAddress & 0xFFFFFF00) == 0x83f70000)
        {
            pFindCodeAddress = (PULONG)(pStartSearchAddress - 12);
            return (ULONG_PTR)pFindCodeAddress + (((*(PULONG)pFindCodeAddress) >> 24) + 7) +
                   (ULONG_PTR)(((*(PULONG)(pFindCodeAddress + 1)) & 0x0FFFF) << 8);
        }
    }
    return 0;
}

ULONGLONG GetSSDTFuncCurAddr64(ULONG id)
{
    LONG dwtmp = 0;
    PULONG ServiceTableBase = NULL;
    ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;
    dwtmp = ServiceTableBase[id];
    dwtmp = dwtmp >> 4;
    return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

ULONG GetOffsetAddress(ULONGLONG FuncAddr)
{
    ULONG dwtmp = 0;
    PULONG ServiceTableBase = NULL;
    ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;
    dwtmp = (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
    dwtmp = dwtmp << 4;
    return dwtmp;
}

bool HookSSDT(PUCHAR pCode, ULONG ulCodeSize, PVOID pNewFunction, PVOID *pOldFunction, ULONG SyscallNum)
{
    if (!pNewFunction || !pOldFunction || SyscallNum <= 0)
        return false;

    //
    // Log the Syscall number that we're hooking
    //
    DBGPRINT("[ HookSSDT ] Syscall: 0x%X\n", SyscallNum);

    //
    // Log the Original function address
    //
    *pOldFunction = PVOID(GetSSDTFuncCurAddr64(SyscallNum));
    DBGPRINT("[ HookSSDT ] Original: 0x%p\n", *pOldFunction);

    *(PULONG64)(jmp_trampoline + 3) = ULONG64(pNewFunction);

    //
    // Find a suitable code cave inside the module .text section that we can use to trampoline to our hook
    //
    auto pCodeCave = tools::FindCodeCave(pCode, ulCodeSize, sizeof(jmp_trampoline));
    if (!pCodeCave)
    {
        DBGPRINT("[ HookSSDT ] Failed to find a suitable code cave.\n");
        return false;
    }

    DBGPRINT("[ HookSSDT ] Code Cave: 0x%p\n", pCodeCave);

    //
    // Change page protection
    //
    auto Mdl = IoAllocateMdl(pCodeCave, sizeof(jmp_trampoline), 0, 0, NULL);
    if (Mdl == NULL)
    {
        DBGPRINT("[ HookSSDT ] IoAllocateMdl failed!\n");
        return false;
    }

    MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);

    auto Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (Mapping == NULL)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        DBGPRINT("[ HookSSDT ] MmMapLockedPagesSpecifyCache failed!\n");
        return false;
    }

    //
    // Modify SSDT table
    //
    auto ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;

    // auto irql = utils::WPOFF();

    RtlCopyMemory(Mapping, jmp_trampoline, sizeof(jmp_trampoline));

    auto SsdtEntry = GetOffsetAddress(ULONG64(pCodeCave));
    SsdtEntry &= 0xFFFFFFF0;
    SsdtEntry += ServiceTableBase[SyscallNum] & 0x0F;
    ServiceTableBase[SyscallNum] = SsdtEntry;

    // utils::WPON(irql);

    //
    // Restore protection
    //
    MmUnmapLockedPages(Mapping, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);

    return true;
}

bool UnhookSSDT(PVOID pFunction, ULONG SyscallNum)
{
    if (!pFunction || SyscallNum <= 0)
        return false;

    auto ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;

    // auto irql = utils::WPOFF();

    auto SsdtEntry = GetOffsetAddress(ULONG64(pFunction));
    SsdtEntry &= 0xFFFFFFF0;
    SsdtEntry += ServiceTableBase[SyscallNum] & 0x0F;
    ServiceTableBase[SyscallNum] = SsdtEntry;

    // utils::WPON(irql);

    return true;
}

bool ssdt::Init()
{
#ifndef USE_KASPERSKY
    g_KeServiceDescriptorTable = PSYSTEM_SERVICE_TABLE(GetKeServiceDescriptorTable64());
    DBGPRINT("KeServiceDescriptorTable: 0x%p\n", g_KeServiceDescriptorTable);
    if (!g_KeServiceDescriptorTable)
        return;

    auto KiServiceTable = PULONG(g_KeServiceDescriptorTable->ServiceTableBase);
    DBGPRINT("KeServiceDescriptorTable->ServiceTableBase: 0x%p\n", KiServiceTable);
    if (!KiServiceTable)
        return;

    DBGPRINT("KeServiceDescriptorTable->NumberOfServices: %lld\n", g_KeServiceDescriptorTable->NumberOfServices);

    auto ntoskrnl = ULONG64(tools::GetNtKernelBase());
    DBGPRINT("ntoskrnl: 0x%llx\n", ntoskrnl);
    if (!ntoskrnl)
        return;

    ULONG ulCodeSize = 0;
    auto pCode = PUCHAR(tools::GetImageTextSection(ntoskrnl, &ulCodeSize));
    if (pCode)
    {
        DBGPRINT("ntoskrnl.exe .text section %p\n", pCode);

        if (HookSSDT(pCode, ulCodeSize, &hkNtQuerySystemInformation,
                     reinterpret_cast<PVOID *>(&oNtQuerySystemInformation), SYSCALL_NTQUERYSYSINFO))
        {
            DBGPRINT("NtQuerySystemInformation hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtQuerySystemInformation!\n");

        if (HookSSDT(pCode, ulCodeSize, &hkNtOpenProcess, reinterpret_cast<PVOID *>(&oNtOpenProcess),
                     SYSCALL_NTOPENPROCESS))
        {
            DBGPRINT("NtOpenProcess hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtOpenProcess!\n");

        if (HookSSDT(pCode, ulCodeSize, &hkNtAllocateVirtualMemory,
                     reinterpret_cast<PVOID *>(&oNtAllocateVirtualMemory), SYSCALL_NTALLOCVIRTUALMEM))
        {
            DBGPRINT("NtAllocateVirtualMemory hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtAllocateVirtualMemory!\n");

        if (HookSSDT(pCode, ulCodeSize, &hkNtFreeVirtualMemory, reinterpret_cast<PVOID *>(&oNtFreeVirtualMemory),
                     SYSCALL_NTFREEVIRTUALMEM))
        {
            DBGPRINT("NtFreeVirtualMemory hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtFreeVirtualMemory!\n");

        if (HookSSDT(pCode, ulCodeSize, &hkNtWriteVirtualMemory, reinterpret_cast<PVOID *>(&oNtWriteVirtualMemory),
                     SYSCALL_NTWRITEVIRTUALMEM))
        {
            DBGPRINT("NtWriteVirtualMemory hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtWriteVirtualMemory!\n");

        if (HookSSDT(pCode, ulCodeSize, &hkNtDeviceIoControlFile, reinterpret_cast<PVOID *>(&oNtDeviceIoControlFile),
                     SYSCALL_NTDEVICEIOCTRLFILE))
        {
            DBGPRINT("NtDeviceIoControlFile hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtDeviceIoControlFile!\n");
    }
#else
#define KASPERSKY_HOOK_ROUTINE(name)                                                                                   \
    if (!kaspersky::hook_ssdt_routine(syscalls::GetSyscallIndexByName(#name), hooks::hk##name,                         \
                                      reinterpret_cast<PVOID *>(&hooks::o##name)))                                     \
    {                                                                                                                  \
        DBGPRINT("Failed to hook " #name);                                                                             \
        return false;                                                                                                  \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        DBGPRINT(#name " hooked successfully!");                                                                       \
    }

    KASPERSKY_HOOK_ROUTINE(NtOpenProcess);
    KASPERSKY_HOOK_ROUTINE(NtDeviceIoControlFile);
    KASPERSKY_HOOK_ROUTINE(NtQuerySystemInformation);
    KASPERSKY_HOOK_ROUTINE(NtAllocateVirtualMemory);
    KASPERSKY_HOOK_ROUTINE(NtFreeVirtualMemory);
    KASPERSKY_HOOK_ROUTINE(NtWriteVirtualMemory);
    KASPERSKY_HOOK_ROUTINE(NtLoadDriver);

#endif
    return true;
}

void ssdt::Destroy()
{
#ifndef USE_KASPERSKY
    if (!g_KeServiceDescriptorTable)
        return;

    if (!UnhookSSDT(oNtQuerySystemInformation, SYSCALL_NTQUERYSYSINFO))
        DBGPRINT("Failed to unhook NtQuerySystemInformation!\n");

    if (!UnhookSSDT(oNtOpenProcess, SYSCALL_NTOPENPROCESS))
        DBGPRINT("Failed to unhook NtOpenProcess!\n");

    if (!UnhookSSDT(oNtAllocateVirtualMemory, SYSCALL_NTALLOCVIRTUALMEM))
        DBGPRINT("Failed to unhook NtAllocateVirtualMemory!\n");

    if (!UnhookSSDT(oNtFreeVirtualMemory, SYSCALL_NTFREEVIRTUALMEM))
        DBGPRINT("Failed to unhook NtFreeVirtualMemory!\n");

    if (!UnhookSSDT(oNtWriteVirtualMemory, SYSCALL_NTWRITEVIRTUALMEM))
        DBGPRINT("Failed to unhook NtWriteVirtualMemory!\n");

    if (!UnhookSSDT(oNtDeviceIoControlFile, SYSCALL_NTDEVICEIOCTRLFILE))
        DBGPRINT("Failed to unhook NtDeviceIoControlFile!\n");
#else
    if (!kaspersky::is_klhk_loaded())
        return;

#define KASPERSKY_UNHOOK_ROUTINE(name)                                                                                 \
    if (!kaspersky::unhook_ssdt_routine(syscalls::GetSyscallIndexByName(#name), hooks::o##name))                       \
    {                                                                                                                  \
        DBGPRINT("Failed to unhook " #name);                                                                           \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        DBGPRINT(#name " unhooked successfully!");                                                                     \
    }

    KASPERSKY_UNHOOK_ROUTINE(NtOpenProcess);
    KASPERSKY_UNHOOK_ROUTINE(NtDeviceIoControlFile);
    KASPERSKY_UNHOOK_ROUTINE(NtQuerySystemInformation);
    KASPERSKY_UNHOOK_ROUTINE(NtAllocateVirtualMemory);
    KASPERSKY_UNHOOK_ROUTINE(NtFreeVirtualMemory);
    KASPERSKY_UNHOOK_ROUTINE(NtWriteVirtualMemory);
    KASPERSKY_UNHOOK_ROUTINE(NtLoadDriver);

#undef KASPERSKY_UNHOOK_ROUTINE
#endif
}