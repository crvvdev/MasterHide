#pragma once

namespace masterhide
{
namespace syscalls
{
static UNICODE_STRING g_NtdllPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
static UNICODE_STRING g_Win32UPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\win32u.dll");

/// <summary>
/// Initialize and fill the syscall dynamic hash table.
/// </summary>
/// <returns>STATUS_SUCCESS on succes, otherwise any NTSTATUS value</returns>
NTSTATUS Initialize();

/// <summary>
/// De-initialize the syscall dynamic hash table if initialized.
/// </summary>
void Deinitialize();

USHORT GetSyscallIndexByName(_In_ LPCSTR serviceName);
} // namespace syscalls
} // namespace masterhide