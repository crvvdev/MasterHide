#pragma once

namespace masterhide
{
namespace callbacks
{
VOID CreateProcessNotifyRoutineEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                                  _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/// <summary>
/// Initialize callbacks.
/// </summary>
/// <returns>STATUS_SUCCESS on success, otherwise any NTSTATUS value</returns>
NTSTATUS Initialize();

/// <summary>
/// De-initialize callbacks.
/// </summary>
void Deinitialize();
}
} // namespace masterhide