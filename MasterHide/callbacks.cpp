#include "includes.hpp"

namespace masterhide
{
using namespace process;
using namespace rules;

namespace callbacks
{
VOID CreateProcessNotifyRoutineEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                                  _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

inline bool g_initialized = false;

NTSTATUS Initialize()
{
    PAGED_CODE();
    NT_ASSERT(!g_initialized);

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    const NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(&CreateProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status))
    {
        WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "PsSetCreateProcessNotifyRoutineEx returned %!STATUS!", status);
        return STATUS_UNSUCCESSFUL;
    }

    g_initialized = true;

    return STATUS_SUCCESS;
}

void Deinitialize()
{
    PAGED_CODE();

    if (!g_initialized)
    {
        return;
    }

    PsSetCreateProcessNotifyRoutineEx(&CreateProcessNotifyRoutineEx, TRUE);

    g_initialized = false;

    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Successfully de-initialized callbacks interface!");
    return;
}

VOID CreateProcessNotifyRoutineEx(_Inout_ PEPROCESS process, _In_ HANDLE processId,
                                  _In_opt_ PPS_CREATE_NOTIFY_INFO createInfo)
{
    UNREFERENCED_PARAMETER(processId);

    if (createInfo != NULL)
    {
        if (createInfo->ImageFileName)
        {
            PPROCESS_RULE_ENTRY processRuleEntry = GetProcessRuleEntry(createInfo->ImageFileName);

            // If there's a rule for the creating process
            //
            if (processRuleEntry)
            {
                // Proceed to create a process entry
                //
                const NTSTATUS status = AddProcessEntry(process, processRuleEntry->PolicyFlags);
                if (NT_SUCCESS(status))
                {
                    WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL,
                                  "Successfully added process rule entry imageName:%wZ pid:%d",
                                  createInfo->ImageFileName, HandleToUlong(processId));
                }
                else
                {
                    WppTracePrint(TRACE_LEVEL_ERROR, GENERAL, "Failed to add process entry %!STATUS!", status);
                }

                object::DereferenceObject(processRuleEntry);
            }
        }
    }
    else
    {
        // Will remove if on list
        //
        if (NT_SUCCESS(RemoveProcessEntry(processId)))
        {
            WppTracePrint(TRACE_LEVEL_VERBOSE, GENERAL, "Removed process entry pid:%d", HandleToUlong(processId));
        }
    }
}

} // namespace callbacks
} // namespace masterhide