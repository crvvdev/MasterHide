#pragma once

namespace masterhide
{
namespace service
{
bool Start(SC_HANDLE serviceHandle);
bool Delete(SC_HANDLE serviceHandle);
bool Stop(SC_HANDLE serviceHandle, LPSERVICE_STATUS serviceStatus);
SC_HANDLE CreateOrOpen(const std::string &name, const std::string &displayName, const std::string &path);
} // namespace service
} // namespace masterhide