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
/// This function returns a syscall index by service name.
/// </summary>
/// <param name="serviceName">Service name to extract syscall index from.</param>
/// <returns></returns>
USHORT GetSyscallIndexByName(_In_ LPCSTR serviceName);
} // namespace syscalls
} // namespace masterhide