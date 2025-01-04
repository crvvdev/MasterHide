#pragma once

namespace masterhide
{
namespace service
{
bool Start(_In_ SC_HANDLE serviceHandle);
bool Delete(_In_ SC_HANDLE serviceHandle);
bool Stop(_In_ SC_HANDLE serviceHandle, LPSERVICE_STATUS serviceStatus);
SC_HANDLE CreateOrOpen(_In_ const std::string &name, _In_ const std::string &displayName, _In_ const std::string &path);
} // namespace service
} // namespace masterhide