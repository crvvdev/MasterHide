#include "includes.hpp"

namespace masterhide
{
namespace process
{
bool IsProtectedProcess(_In_ HANDLE processId)
{
    UNREFERENCED_PARAMETER(processId);
    // TODO: implement
    return false;
}

bool IsProtectedProcess(_In_ LPCWSTR processName)
{
    UNREFERENCED_PARAMETER(processName);
    // TODO: implement
    return false;
}

bool IsProtectedProcess(_In_ PEPROCESS process)
{
    UNREFERENCED_PARAMETER(process);
    // TODO: implement
    return false;
}

bool IsMonitoredProcess(_In_ HANDLE processId)
{
    UNREFERENCED_PARAMETER(processId);
    // TODO: implement
    return false;
}

bool IsMonitoredProcess(_In_ PEPROCESS process)
{
    UNREFERENCED_PARAMETER(process);
    // TODO: implement
    return false;
}

bool IsBlacklistedProcess(_In_ HANDLE processId)
{
    UNREFERENCED_PARAMETER(processId);
    // TODO: implement
    return false;
}

bool IsBlacklistedProcess(_In_ PEPROCESS process)
{
    UNREFERENCED_PARAMETER(process);
    // TODO: implement
    return false;
}

enum EProcessPolicyFlags
{
    ProcessPolicyFlagProtected,
    ProcessPolicyFlagSystem,
};

ULONG g_processPolicyFlags = 0;

bool IsProcessInPolicy(_In_ PEPROCESS process)
{
    if (PsIsProtectedProcess(process) && !BooleanFlagOn(g_processPolicyFlags, ProcessPolicyFlagProtected))
    {
        // Ignore protected processes
        return false;
    }

    if (PsIsSystemProcess(process) && !BooleanFlagOn(g_processPolicyFlags, ProcessPolicyFlagSystem))
    {
        // Ignore system processes
        return false;
    }

    return process::IsProtectedProcess(process);
}

bool IsProcessInPolicy(_In_ HANDLE processHandle)
{
    PEPROCESS process = nullptr;

    const NTSTATUS status = ObReferenceObjectByHandle(processHandle, 0, *PsProcessType, KernelMode,
                                                      reinterpret_cast<PVOID *>(&process), nullptr);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("Err: ObReferenceObjectByHandle returned 0x%08X", status);
        return false;
    }

    SCOPE_EXIT
    {
        ObDereferenceObject(process);
    };

    return IsProcessInPolicy(process);
}
} // namespace process

namespace hooks
{
volatile LONG g_refCount = 0;

void WaitForHooksCompletion()
{
    DBGPRINT("%d ref counts", g_refCount);

    while (InterlockedCompareExchange(&g_refCount, 0, 0) != 0)
    {
        DBGPRINT("%d references left", g_refCount);
        YieldProcessor();
    }
}

NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                               PCLIENT_ID ClientId)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    if (!process::IsProcessInPolicy(currentProcess))
    {
        // Process is not meant to be monitored.
        return oNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    const NTSTATUS status = oNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    if (NT_SUCCESS(status))
    {
        if (process::IsBlacklistedProcess(PsGetCurrentProcessId()))
        {
            if (process::IsProtectedProcess(ClientId->UniqueProcess))
            {
                DBGPRINT("Denying access from PID %p to PID %p\n", PsGetCurrentProcessId(), ClientId->UniqueProcess);
                ZwClose(*ProcessHandle);
                *ProcessHandle = HANDLE(-1);
                return STATUS_ACCESS_DENIED;
            }
        }

        if (process::IsMonitoredProcess(ClientId->UniqueProcess))
        {
            // TODO: implement
        }
    }
    return status;
}

NTSTATUS NTAPI hkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,
                                      PULONG NumberOfBytesWritten)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    if (!process::IsProcessInPolicy(currentProcess))
    {
        // Process is not meant to be monitored.
        return oNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }

    const NTSTATUS status =
        oNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    if (NT_SUCCESS(status))
    {
        PEPROCESS Process = nullptr;
        auto ret = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&Process,
                                             nullptr);
        if (!NT_SUCCESS(ret))
        {
            return status;
        }

        if (process::IsMonitoredProcess(Process))
        {
            // TODO: implement
        }

        ObDereferenceObject(Process);
    }
    return status;
}

NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
                                         PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    if (!process::IsProcessInPolicy(currentProcess))
    {
        // Process is not meant to be monitored.
        return oNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }

    const NTSTATUS status =
        oNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    if (NT_SUCCESS(status) && BaseAddress && RegionSize && *RegionSize >= 0x1000)
    {
        //
        // Get Name from handle
        //
        PEPROCESS Process = nullptr;
        auto ret = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&Process,
                                             nullptr);
        if (!NT_SUCCESS(ret))
            return status;

        if (process::IsMonitoredProcess(Process))
        {
            // TODO: implement
        }

        ObDereferenceObject(Process);
    }
    return status;
}

NTSTATUS NTAPI hkNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const auto res = oNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);

    // TODO: move this check to a function
    if (PsIsProtectedProcess(PsGetCurrentProcess()) || PsIsSystemProcess(PsGetCurrentProcess()) ||
        process::IsProtectedProcess(PsGetCurrentProcessId()))
    {
        return res;
    }

    if (NT_SUCCESS(res) && BaseAddress && RegionSize && *RegionSize >= 0x1000)
    {
        //
        // Get Name from handle
        //
        PEPROCESS Process = nullptr;
        auto ret = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID *)&Process,
                                             nullptr);
        if (!NT_SUCCESS(ret))
            return res;

        if (process::IsMonitoredProcess(Process))
        {
            // TODO: implement
        }

        ObDereferenceObject(Process);
    }
    return res;
}

NTSTATUS NTAPI hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                       PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
                                       ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS status = oNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
                                             InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

    const PEPROCESS currentProcess = PsGetCurrentProcess();
    const HANDLE currentPid = PsGetCurrentProcessId();

    //
    // perform actions in case it's a blacklisted process.
    //
    if (process::IsBlacklistedProcess(currentPid))
    {
        UNICODE_STRING processImageName{};
        if (!tools::GetProcessFileName(currentProcess, &processImageName))
        {
            DBGPRINT("Failed to get process %d file name\n", HandleToUlong(currentPid));
            goto Exit;
        }

        SCOPE_EXIT
        {
            RtlFreeUnicodeString(&processImageName);
        };

        // This is safe because GetProcessFileName gives us a null terminated string.
        LPWSTR moduleName = wcsrchr(processImageName.Buffer, '\\');

        //
        // Hardware Spoofing
        //
        if (NT_SUCCESS(status))
        {
            __try
            {
                static constexpr char newSerialNumber[] = "XKH2A83XVALP766";
                static constexpr char newModelNumber[] = "Kingston";
                static constexpr UCHAR newMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

                switch (IoControlCode)
                {

                case IOCTL_STORAGE_QUERY_PROPERTY: {
                    PSTORAGE_PROPERTY_QUERY Query = PSTORAGE_PROPERTY_QUERY(InputBuffer);
                    if (Query && Query->PropertyId == StorageDeviceProperty)
                    {
                        if (OutputBufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
                        {
                            PSTORAGE_DEVICE_DESCRIPTOR Desc = PSTORAGE_DEVICE_DESCRIPTOR(OutputBuffer);
                            if (Desc)
                            {
                                if (Desc->SerialNumberOffset)
                                {
                                    auto serialNumber = PCHAR(Desc) + Desc->SerialNumberOffset;
                                    const size_t serialNumberLen = strlen(serialNumber);

                                    if (serialNumberLen > 0)
                                    {
                                        DBGPRINT(
                                            "[Process: %ls] [IOCTL_STORAGE_QUERY_PROPERTY] spoofing serial %s to %s\n",
                                            moduleName, serialNumber, newSerialNumber);

                                        RtlZeroMemory(serialNumber, serialNumberLen);
                                        strcpy(serialNumber, newSerialNumber);
                                    }
                                }

                                if (Desc->ProductIdOffset)
                                {
                                    auto modelNumber = PCHAR(Desc) + Desc->ProductIdOffset;
                                    const size_t modelNumberLen = strlen(modelNumber);

                                    if (modelNumberLen > 0)
                                    {
                                        DBGPRINT(
                                            "[Process: %ls] [IOCTL_STORAGE_QUERY_PROPERTY] spoofing model %s to %s\n",
                                            moduleName, modelNumber, newModelNumber);

                                        RtlZeroMemory(modelNumber, modelNumberLen);
                                        strcpy(modelNumber, newModelNumber);
                                    }
                                }
                            }
                        }
                    }
                    break;
                }

                case IOCTL_ATA_PASS_THROUGH: {
                    if (OutputBufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))
                    {
                        PATA_PASS_THROUGH_EX Ata = PATA_PASS_THROUGH_EX(OutputBuffer);
                        if (Ata && Ata->DataBufferOffset)
                        {
                            PIDENTIFY_DEVICE_DATA Identify =
                                PIDENTIFY_DEVICE_DATA(PCHAR(OutputBuffer) + Ata->DataBufferOffset);
                            if (Identify)
                            {
                                auto Serial = PCHAR(Identify->SerialNumber);
                                if (strlen(Serial) > 0)
                                {
                                    tools::SwapEndianness(Serial, sizeof(Identify->SerialNumber));

                                    DBGPRINT("%ls Spoofing Serial ( 0x%X ) Old: %s New: %s\n", moduleName,
                                             IoControlCode, Serial, newSerialNumber);

                                    RtlZeroMemory(Serial, strlen(Serial));
                                    strcpy(Serial, newSerialNumber);

                                    tools::SwapEndianness(Serial, sizeof(Identify->SerialNumber));
                                }

                                auto Model = PCHAR(Identify->ModelNumber);
                                if (strlen(Model) > 0)
                                {
                                    // Fix invalid characters.
                                    Model[sizeof(Identify->ModelNumber) - 1] = 0;
                                    Model[sizeof(Identify->ModelNumber) - 2] = 0;

                                    tools::SwapEndianness(Model, sizeof(Identify->ModelNumber) - 2);

                                    DBGPRINT("$ls Spoofing Model ( 0x%X ) Old: %s New: %s\n", moduleName, IoControlCode,
                                             Model, newModelNumber);

                                    RtlZeroMemory(Model, strlen(Model));
                                    strcpy(Model, newModelNumber);

                                    tools::SwapEndianness(Model, sizeof(Identify->ModelNumber) - 2);
                                }
                            }
                        }
                    }
                    break;
                }

                case SMART_RCV_DRIVE_DATA: {
                    if (OutputBufferLength >= sizeof(SENDCMDOUTPARAMS))
                    {
                        PSENDCMDOUTPARAMS sendCmdOutParams = PSENDCMDOUTPARAMS(OutputBuffer);
                        if (sendCmdOutParams)
                        {
                            PIDSECTOR sector = PIDSECTOR(sendCmdOutParams->bBuffer);
                            if (sector)
                            {
                                auto serialNumber = PCHAR(sector->sSerialNumber);
                                const size_t serialNumberLen = strlen(serialNumber);

                                if (serialNumberLen > 0)
                                {
                                    tools::SwapEndianness(serialNumber, sizeof(sector->sSerialNumber));

                                    DBGPRINT("[Process: %ls] [SMART_RCV_DRIVE_DATA] spoofing serial %s to %s\n",
                                             moduleName, serialNumber, newSerialNumber);

                                    RtlZeroMemory(serialNumber, serialNumberLen);
                                    strcpy(serialNumber, newSerialNumber);

                                    tools::SwapEndianness(serialNumber, sizeof(sector->sSerialNumber));
                                }

                                auto moduleNumber = reinterpret_cast<PCHAR>(sector->sModelNumber);
                                const size_t moduleNumberLen = strlen(moduleNumber);

                                if (moduleNumberLen > 0)
                                {
                                    // Fix invalid characters.
                                    moduleNumber[sizeof(sector->sModelNumber) - 1] = 0;
                                    moduleNumber[sizeof(sector->sModelNumber) - 2] = 0;

                                    tools::SwapEndianness(moduleNumber, sizeof(sector->sModelNumber) - 2);

                                    DBGPRINT("[Process: %ls] [SMART_RCV_DRIVE_DATA] spoofing model %s to %s\n",
                                             moduleName, moduleNumber, newModelNumber);

                                    RtlZeroMemory(moduleNumber, moduleNumberLen);
                                    strcpy(moduleNumber, newModelNumber);

                                    tools::SwapEndianness(moduleNumber, sizeof(sector->sModelNumber) - 2);
                                }
                            }
                        }
                    }
                    break;
                }

                case IOCTL_DISK_GET_PARTITION_INFO_EX: {
                    if (OutputBufferLength >= sizeof(PARTITION_INFORMATION_EX))
                    {
                        PPARTITION_INFORMATION_EX PartInfo = PPARTITION_INFORMATION_EX(OutputBuffer);
                        if (PartInfo && PartInfo->PartitionStyle == PARTITION_STYLE_GPT)
                        {
                            DBGPRINT("%ls Zero'ing partition GUID (EX)\n", moduleName);
                            memset(&PartInfo->Gpt.PartitionId, 0, sizeof(GUID));
                        }
                    }
                    break;
                }

                case IOCTL_DISK_GET_DRIVE_LAYOUT_EX: {
                    if (OutputBufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX))
                    {
                        PDRIVE_LAYOUT_INFORMATION_EX LayoutInfo = PDRIVE_LAYOUT_INFORMATION_EX(OutputBuffer);
                        if (LayoutInfo && LayoutInfo->PartitionStyle == PARTITION_STYLE_GPT)
                        {
                            DBGPRINT("%ls Zero'ing partition GUID\n", moduleName);
                            memset(&LayoutInfo->Gpt.DiskId, 0, sizeof(GUID));
                        }
                    }
                    break;
                }

                case IOCTL_MOUNTMGR_QUERY_POINTS: {
                    if (OutputBufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS))
                    {
                        PMOUNTMGR_MOUNT_POINTS Points = PMOUNTMGR_MOUNT_POINTS(OutputBuffer);
                        if (Points)
                        {
                            DBGPRINT("%ls Spoofing mounted points\n", moduleName);
                            for (unsigned i = 0; i < Points->NumberOfMountPoints; ++i)
                            {
                                auto Point = &Points->MountPoints[i];

                                if (Point->UniqueIdOffset)
                                    Point->UniqueIdLength = 0;

                                if (Point->SymbolicLinkNameOffset)
                                    Point->SymbolicLinkNameLength = 0;
                            }
                        }
                    }
                    break;
                }

                case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID: {
                    if (OutputBufferLength >= sizeof(MOUNTDEV_UNIQUE_ID))
                    {
                        PMOUNTDEV_UNIQUE_ID UniqueId = PMOUNTDEV_UNIQUE_ID(OutputBuffer);
                        if (UniqueId)
                        {
                            DBGPRINT("%ls Spoofing mounted unique id\n", moduleName);
                            UniqueId->UniqueIdLength = 0;
                        }
                    }
                    break;
                }

                case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
                    switch (*(PDWORD)InputBuffer)
                    {
                    case OID_802_3_PERMANENT_ADDRESS:
                    case OID_802_3_CURRENT_ADDRESS:
                    case OID_802_5_PERMANENT_ADDRESS:
                    case OID_802_5_CURRENT_ADDRESS:
                        DBGPRINT("%ls Spoofing permanent MAC\n", moduleName);

                        RtlCopyMemory(OutputBuffer, newMac, sizeof(newMac));
                        break;
                    }
                }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }
    }
Exit:
    return status;
}

NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID Buffer, ULONG Length,
                                          PULONG ReturnLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const auto ret = oNtQuerySystemInformation(SystemInformationClass, Buffer, Length, ReturnLength);

    //
    // If the callee process is a protected process we ignore it
    //
    if (process::IsProtectedProcess(PsGetCurrentProcessId()))
    {
        return ret;
    }

    if (NT_SUCCESS(ret))
    {
        //
        // Hide from Driver list
        //
        if (SystemInformationClass == SystemModuleInformation)
        {
            const auto pModule = PRTL_PROCESS_MODULES(Buffer);
            const auto pEntry = &pModule->Modules[0];

            for (unsigned i = 0; i < pModule->NumberOfModules; ++i)
            {
                if (pEntry[i].ImageBase && pEntry[i].ImageSize && strlen((char *)pEntry[i].FullPathName) > 2)
                {
                    // TODO: implement
#if 0
                    {
                        const auto next_entry = i + 1;

                        if (next_entry < pModule->NumberOfModules)
                        {
                            RtlCopyMemory(&pEntry[i], &pEntry[next_entry], sizeof(RTL_PROCESS_MODULE_INFORMATION));
                        }
                        else
                        {
                            RtlZeroMemory(&pEntry[i], sizeof(RTL_PROCESS_MODULE_INFORMATION));
                            pModule->NumberOfModules--;
                        }
                    }
#endif
                }
            }
        }
        //
        // Hide from Process list
        //
        else if (SystemInformationClass == SystemProcessInformation ||
                 SystemInformationClass == SystemSessionProcessInformation ||
                 SystemInformationClass == SystemExtendedProcessInformation)
        {
            PSYSTEM_PROCESS_INFO pCurr = NULL;
            PSYSTEM_PROCESS_INFO pNext = PSYSTEM_PROCESS_INFO(Buffer);

            while (pNext->NextEntryOffset != 0)
            {
                pCurr = pNext;
                pNext = (PSYSTEM_PROCESS_INFO)((PUCHAR)pCurr + pCurr->NextEntryOffset);

                //
                // Erase our protected processes from the list
                //
                if (pNext->ImageName.Buffer && process::IsProtectedProcess(pNext->ImageName.Buffer))
                {
                    if (pNext->NextEntryOffset == 0)
                    {
                        pCurr->NextEntryOffset = 0;
                    }
                    else
                    {
                        pCurr->NextEntryOffset += pNext->NextEntryOffset;
                    }

                    pNext = pCurr;
                }
            }
        }
        //
        // Hide from handle list
        //
        else if (SystemInformationClass == SystemHandleInformation)
        {
            if (process::IsBlacklistedProcess(PsGetCurrentProcessId()))
            {
                const auto pHandle = PSYSTEM_HANDLE_INFORMATION(Buffer);
                const auto pEntry = &pHandle->Information[0];

                for (unsigned i = 0; i < pHandle->NumberOfHandles; ++i)
                {
                    if (process::IsProtectedProcess(ULongToHandle(pEntry[i].ProcessId)))
                    {
                        const auto next_entry = i + 1;

                        if (next_entry < pHandle->NumberOfHandles)
                        {
                            RtlCopyMemory(&pEntry[i], &pEntry[next_entry], sizeof(SYSTEM_HANDLE));
                        }
                        else
                        {
                            memset(&pEntry[i], 0, sizeof(SYSTEM_HANDLE));
                            pHandle->NumberOfHandles--;
                        }
                    }
                }
            }
        }
        else if (SystemInformationClass == SystemExtendedHandleInformation)
        {
            if (process::IsBlacklistedProcess(PsGetCurrentProcessId()))
            {
                const auto pHandle = PSYSTEM_HANDLE_INFORMATION_EX(Buffer);
                const auto pEntry = &pHandle->Information[0];

                for (unsigned i = 0; i < pHandle->NumberOfHandles; ++i)
                {
                    if (process::IsProtectedProcess(ULongToHandle(pEntry[i].ProcessId)))
                    {
                        const auto next_entry = i + 1;

                        if (next_entry < pHandle->NumberOfHandles)
                        {
                            RtlCopyMemory(&pEntry[i], &pEntry[next_entry], sizeof(SYSTEM_HANDLE));
                        }
                        else
                        {
                            memset(&pEntry[i], 0, sizeof(SYSTEM_HANDLE));
                            pHandle->NumberOfHandles--;
                        }
                    }
                }
            }
        }
        //
        // Spoof code integrity status
        //
        else if (SystemInformationClass == SystemCodeIntegrityInformation)
        {
            auto info = PSYSTEM_CODEINTEGRITY_INFORMATION(Buffer);

            ULONG options = info->CodeIntegrityOptions;

            // fix flags
            options &= ~CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;
            options &= ~CODEINTEGRITY_OPTION_TESTSIGN;
            options |= CODEINTEGRITY_OPTION_ENABLED;

            info->CodeIntegrityOptions = options;
        }
    }
    return ret;
}

NTSTATUS NTAPI hkNtLoadDriver(PUNICODE_STRING DriverServiceName)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    NTSTATUS ret = STATUS_UNSUCCESSFUL;
    bool bLoad = true;

    if (DriverServiceName && DriverServiceName->Buffer)
    {
        /*

        For example:

        if ( wcsstr( DriverServiceName->Buffer, L"BEDaisy.sys" ) )
            bLoad = false;

        Loading will be blocked.
        */
    }

    if (bLoad)
    {
        ret = oNtLoadDriver(DriverServiceName);
        if (NT_SUCCESS(ret))
            DBGPRINT("Loading Driver: %ws\n", DriverServiceName->Buffer);
    }
    return ret;
}

HWND NTAPI hkNtUserWindowFromPoint(LONG x, LONG y)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    // TODO: implement

    return oNtUserWindowFromPoint(x, y);
}

HANDLE NTAPI hkNtUserQueryWindow(HWND WindowHandle, HANDLE TypeInformation)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    // TODO: implement

    return oNtUserQueryWindow(WindowHandle, TypeInformation);
}

HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass,
                                PUNICODE_STRING lpszWindow, DWORD dwType)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    // TODO: implement

    return oNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
}

NTSTATUS NTAPI hkNtUserBuildHwndList(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax,
                                     HWND *phwndFirst, ULONG *pcHwndNeeded)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const auto res = oNtUserBuildHwndList(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        //
        // Hide protected process window from blacklisted process
        //
        if (fEnumChildren == 1)
        {
            const HANDLE processId = oNtUserQueryWindow(hwndNext, 0);
            if (process::IsProtectedProcess(processId))
            {
                return STATUS_UNSUCCESSFUL;
            }
        }

        if (NT_SUCCESS(res))
        {
            ULONG i = 0;
            ULONG j;

            while (i < *pcHwndNeeded)
            {
                const HANDLE processId = oNtUserQueryWindow(phwndFirst[i], 0);
                if (process::IsProtectedProcess(processId))
                {
                    for (j = i; j < (*pcHwndNeeded) - 1; j++)
                        phwndFirst[j] = phwndFirst[j + 1];
                    phwndFirst[*pcHwndNeeded - 1] = 0;
                    (*pcHwndNeeded)--;
                    continue;
                }
                i++;
            }
        }
    }
    return res;
}

HWND NTAPI hkNtUserGetForegroundWindow(VOID)
{
    PAGED_CODE();

    InterlockedIncrement(&g_refCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_refCount);
    };

    const HWND result = oNtUserGetForegroundWindow();

    if (process::IsBlacklistedProcess(PsGetCurrentProcess()))
    {
        //
        // Hide protected process window from blacklisted process
        //
        const HANDLE processId = oNtUserQueryWindow(result, 0);

        static HWND lastHwnd = nullptr;

        if (process::IsProtectedProcess(processId))
        {
            return lastHwnd;
        }
        else
        {
            // store a copy of the last HWND
            lastHwnd = result;
        }
    }

    return result;
}
} // namespace hooks
} // namespace masterhide