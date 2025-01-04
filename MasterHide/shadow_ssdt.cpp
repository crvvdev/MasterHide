#include "includes.hpp"

PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTableShadow = NULL;

ULONGLONG GetKeServiceDescriptorTableShadow64()
{
    PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
    PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
    PUCHAR i = NULL;
    UCHAR b1 = 0, b2 = 0, b3 = 0;
    ULONG templong = 0;
    ULONGLONG addr = 0;
    for (i = StartSearchAddress; i < EndSearchAddress; i++)
    {
        if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
        {
            b1 = *i;
            b2 = *(i + 1);
            b3 = *(i + 2);
            if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d)
            {
                memcpy(&templong, i + 3, 4);
                addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
                return addr;
            }
        }
    }
    return 0;
}

ULONGLONG GetSSSDTFuncCurAddr64(ULONG64 Index)
{
    ULONGLONG W32pServiceTable = 0, qwTemp = 0;
    LONG dwTemp = 0;
    W32pServiceTable = (ULONGLONG)(g_KeServiceDescriptorTableShadow->ServiceTableBase);
    qwTemp = W32pServiceTable + 4 * (Index - 0x1000);
    dwTemp = *(PLONG)qwTemp;
    dwTemp = dwTemp >> 4;
    qwTemp = W32pServiceTable + (LONG64)dwTemp;
    return qwTemp;
}

bool HookSSSDT(PUCHAR pCode, ULONG ulCodeSize, PVOID pNewFunction, PVOID *pOldFunction, ULONG SyscallNum)
{
    if (!pNewFunction || !pOldFunction || SyscallNum <= 0)
        return false;

    ULONGLONG W32pServiceTable = 0, qwTemp = 0;
    LONG dwTemp = 0;

    //
    // Log the Syscall number that we're hooking
    //
    DBGPRINT("[ HookSSSDT ] Syscall: 0x%X\n", SyscallNum);

    //
    // Log the Original function address
    //
    *pOldFunction = PVOID(GetSSSDTFuncCurAddr64(SyscallNum));
    DBGPRINT("[ HookSSSDT ] Original: 0x%p\n", *pOldFunction);

    *(PULONG64)(jmp_trampoline + 3) = ULONG64(pNewFunction);

    //
    // Find a suitable code cave inside the module .text section that we can use to trampoline to our hook
    //
    auto pCodeCave = tools::FindCodeCave(pCode, ulCodeSize, sizeof(jmp_trampoline));
    if (!pCodeCave)
    {
        DBGPRINT("[ HookSSSDT ] Failed to find a suitable code cave.\n");
        return false;
    }

    DBGPRINT("[ HookSSSDT ] Code Cave: 0x%p\n", pCodeCave);

    //
    // Change page protection
    //
    auto Mdl = IoAllocateMdl(pCodeCave, sizeof(jmp_trampoline), 0, 0, NULL);
    if (Mdl == NULL)
    {
        DBGPRINT("[ HookSSSDT ] IoAllocateMdl failed!\n");
        return false;
    }

    MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);

    auto Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (Mapping == NULL)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        DBGPRINT("[ HookSSSDT ] MmMapLockedPagesSpecifyCache failed!\n");
        return false;
    }

    //
    // Modify SSSDT table
    //
    // irql = utils::WPOFF();

    RtlCopyMemory(Mapping, jmp_trampoline, sizeof(jmp_trampoline));

    W32pServiceTable = (ULONGLONG)(g_KeServiceDescriptorTableShadow->ServiceTableBase);
    qwTemp = W32pServiceTable + 4 * (SyscallNum - 0x1000);
    dwTemp = (LONG)((ULONG64)pCodeCave - W32pServiceTable);
    dwTemp = dwTemp << 4;

    *(PLONG)qwTemp = dwTemp;

    // utils::WPON(irql);

    //
    // Restore protection
    //
    MmUnmapLockedPages(Mapping, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);

    return true;
}

bool UnhookSSSDT(PVOID pFunction, ULONG SyscallNum)
{
    if (!pFunction || SyscallNum <= 0)
        return false;

    ULONGLONG W32pServiceTable = 0, qwTemp = 0;
    LONG dwTemp = 0;

    // irql = utils::WPOFF();

    W32pServiceTable = (ULONGLONG)(g_KeServiceDescriptorTableShadow->ServiceTableBase);
    qwTemp = W32pServiceTable + 4 * (SyscallNum - 0x1000);
    dwTemp = (LONG)((ULONG64)pFunction - W32pServiceTable);
    dwTemp = dwTemp << 4;

    *(PLONG)qwTemp = dwTemp;

    // utils::WPON(irql);

    return true;
}

bool sssdt::Init()
{
#ifndef USE_KASPERSKY
    g_KeServiceDescriptorTableShadow =
        PSYSTEM_SERVICE_TABLE(GetKeServiceDescriptorTableShadow64() + sizeof(SYSTEM_SERVICE_TABLE));
    DBGPRINT("KeServiceDescriptorTableShadow: 0x%p\n", g_KeServiceDescriptorTableShadow);

    if (!g_KeServiceDescriptorTableShadow)
        return;

    auto W32pServiceTable = PULONG(g_KeServiceDescriptorTableShadow->ServiceTableBase);
    DBGPRINT("KeServiceDescriptorTableShadow->ServiceTableBase: 0x%p\n", W32pServiceTable);

    if (!W32pServiceTable)
        return;

    DBGPRINT("KeServiceDescriptorTableShadow->NumberOfServices: %lld\n",
             g_KeServiceDescriptorTableShadow->NumberOfServices);

    auto Csrss = GetCsrssPid();

    PEPROCESS Process = nullptr;
    auto res = PsLookupProcessByProcessId(Csrss, &Process);
    if (!NT_SUCCESS(res))
    {
        DBGPRINT("[ ShadowSSDT ] PsLookupProcessByProcessId failed 0x%X\n", res);
        return;
    }

    //
    // Save csrss.exe PID for later
    //
    hCsrssPID = Csrss;

    KAPC_STATE apc{};
    KeStackAttachProcess(Process, &apc);

    auto win32k = ULONG64(tools::GetModuleBase("\\SystemRoot\\System32\\win32k.sys"));
    DBGPRINT("win32k: 0x%llx\n", win32k);
    if (!win32k)
        return;

    ULONG ulCodeSize = 0;
    auto pCode = PUCHAR(tools::GetImageTextSection(win32k, &ulCodeSize));
    if (pCode)
    {
        DBGPRINT("win32k.sys .text section 0x%p\n", pCode);

        if (HookSSSDT(pCode, ulCodeSize, &hkNtUserQueryWindow, reinterpret_cast<PVOID *>(&oNtUserQueryWindow),
                      SYSCALL_NTUSERQUERYWND))
        {
            DBGPRINT("NtUserQueryWindow hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtUserQueryWindow!\n");

        if (HookSSSDT(pCode, ulCodeSize, &hkNtUserFindWindowEx, reinterpret_cast<PVOID *>(&oNtUserFindWindowEx),
                      SYSCALL_NTUSERFINDWNDEX))
        {
            DBGPRINT("NtUserFindWindowEx hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtUserFindWindowEx!\n");

        if (HookSSSDT(pCode, ulCodeSize, &hkNtUserWindowFromPoint, reinterpret_cast<PVOID *>(&oNtUserWindowFromPoint),
                      SYSCALL_NTUSERWNDFROMPOINT))
        {
            DBGPRINT("NtUserWindowFromPoint hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtUserWindowFromPoint!\n");

        if (HookSSSDT(pCode, ulCodeSize, &hkNtUserBuildHwndList, reinterpret_cast<PVOID *>(&oNtUserBuildHwndList),
                      SYSCALL_NTUSERBUILDWNDLIST))
        {
            DBGPRINT("NtUserBuildHwndList hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtUserBuildHwndList!\n");

        if (HookSSSDT(pCode, ulCodeSize, &hkNtUserGetForegroundWindow,
                      reinterpret_cast<PVOID *>(&oNtUserGetForegroundWindow), SYSCALL_NTGETFOREGROUNDWND))
        {
            DBGPRINT("NtUserGetForegroundWindow hooked successfully!\n");
        }
        else
            DBGPRINT("Failed to hook NtUserGetForegroundWindow!\n");
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(Process);
#else
#define KASPERSKY_HOOK_ROUTINE(name)                                                                                   \
    if (!kaspersky::hook_shadow_ssdt_routine(syscalls::GetSyscallIndexByName(#name) + 0x1000, hooks::hk##name,         \
                                             reinterpret_cast<PVOID *>(&hooks::o##name)))                              \
    {                                                                                                                  \
        DBGPRINT("Failed to hook " #name);                                                                             \
        return false;                                                                                                  \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        DBGPRINT(#name " hooked successfully!");                                                                       \
    }

    hooks::NtUserGetThreadState = reinterpret_cast<decltype(hooks::NtUserGetThreadState)>(
        kaspersky::get_shadow_ssdt_routine(syscalls::GetSyscallIndexByName("NtUserGetThreadState") + 0x1000));

    if (!hooks::NtUserGetThreadState)
    {
        DBGPRINT("NtUserGetThreadState not found!");
        return false;
    }

    KASPERSKY_HOOK_ROUTINE(NtUserQueryWindow);
    KASPERSKY_HOOK_ROUTINE(NtUserFindWindowEx);
    KASPERSKY_HOOK_ROUTINE(NtUserWindowFromPoint);
    KASPERSKY_HOOK_ROUTINE(NtUserBuildHwndList);
    KASPERSKY_HOOK_ROUTINE(NtUserGetForegroundWindow);

    // NtUserGetThreadState

#undef KASPERSKY_HOOK_ROUTINE
#endif
    return true;
}

void sssdt::Destroy()
{
#ifndef USE_KASPERSKY
    if (!g_KeServiceDescriptorTableShadow)
        return;

    PEPROCESS Process = nullptr;
    auto res = PsLookupProcessByProcessId(hCsrssPID, &Process);
    if (!NT_SUCCESS(res))
    {
        DBGPRINT("[ DestroyShadowSSDT ] PsLookupProcessByProcessId failed 0x%X\n", res);
        return;
    }

    KAPC_STATE apc{};
    KeStackAttachProcess(Process, &apc);

    if (!UnhookSSSDT(oNtUserFindWindowEx, SYSCALL_NTUSERFINDWNDEX))
        DBGPRINT("Failed to unhook NtUserFindWindowEx!\n");

    if (!UnhookSSSDT(oNtUserWindowFromPoint, SYSCALL_NTUSERWNDFROMPOINT))
        DBGPRINT("Failed to unhook NtUserWindowFromPoint!\n");

    if (!UnhookSSSDT(oNtUserBuildHwndList, SYSCALL_NTUSERBUILDWNDLIST))
        DBGPRINT("Failed to unhook NtUserBuildHwndList!\n");

    if (!UnhookSSSDT(oNtUserGetForegroundWindow, SYSCALL_NTGETFOREGROUNDWND))
        DBGPRINT("Failed to unhook NtUserGetForegroundWindow!\n");

    if (!UnhookSSSDT(oNtUserQueryWindow, SYSCALL_NTUSERQUERYWND))
        DBGPRINT("Failed to unhook NtUserQueryWindow!\n");

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(Process);
#else
    if (!kaspersky::is_klhk_loaded())
        return;

#define KASPERSKY_UNHOOK_ROUTINE(name)                                                                                 \
    if (!kaspersky::unhook_shadow_ssdt_routine(syscalls::GetSyscallIndexByName(#name) + 0x1000, hooks::o##name))       \
    {                                                                                                                  \
        DBGPRINT("Failed to unhook " #name);                                                                           \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        DBGPRINT(#name " unhooked successfully!");                                                                     \
    }

    KASPERSKY_UNHOOK_ROUTINE(NtUserQueryWindow);
    KASPERSKY_UNHOOK_ROUTINE(NtUserFindWindowEx);
    KASPERSKY_UNHOOK_ROUTINE(NtUserWindowFromPoint);
    KASPERSKY_UNHOOK_ROUTINE(NtUserBuildHwndList);
    KASPERSKY_UNHOOK_ROUTINE(NtUserGetForegroundWindow);
#endif
}