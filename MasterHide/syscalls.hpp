#pragma once

namespace masterhide
{
namespace syscalls
{
/// <summary>
/// Initialize and fill the syscall dynamic hash table.
/// </summary>
/// <returns>STATUS_SUCCESS on succes, otherwise any NTSTATUS value</returns>
NTSTATUS Initialize();

/// <summary>
/// De-initialize the syscall dynamic hash table if initialized.
/// </summary>
void Deinitialize();

/// <summary>
/// Obtain syscall index by service name
/// </summary>
/// <param name="serviceName">Service name</param>
/// <returns>MAXUSHORT on failure, otherwise syscall index</returns>
USHORT GetSyscallIndexByName(_In_ LPCSTR serviceName);

/// <summary>
/// Obtain syscall routine address by service name
/// </summary>
/// <param name="serviceName">Service routine name</param>
/// <param name="win32k">Is Win32k table?</param>
/// <returns>nullptr on failure, otherwise syscall routine address</returns>
PVOID GetSyscallRoutineByName(_In_ LPCSTR serviceName, _In_ bool win32k);
} // namespace syscalls
} // namespace masterhide