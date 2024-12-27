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
} // namespace syscalls
} // namespace masterhide