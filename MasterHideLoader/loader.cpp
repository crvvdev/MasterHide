#include "includes.hpp"

namespace masterhide
{
namespace loader
{
SC_HANDLE g_serviceHandle = nullptr;

void Load()
{
    char buf[MAX_PATH]{};
    GetCurrentDirectoryA(sizeof(buf), buf);

    const auto path = std::string{buf} + "\\MasterHide.sys";

    g_serviceHandle = service::CreateOrOpen("MasterHide", "MasterHide", path);
    if (!g_serviceHandle)
    {
        throw std::runtime_error("Failed to create or open MasterHide service!");
    }

    if (!service::Start(g_serviceHandle))
    {
        CloseServiceHandle(g_serviceHandle);

        throw std::runtime_error("Failed to start MasterHide service!");
    }
}

bool Unload()
{
    SERVICE_STATUS serviceStatus{};

    bool success = service::Stop(g_serviceHandle, &serviceStatus);
    if (!success && GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
    {
        success = true;
    }

    if (success)
    {
        // in case service successfully stopped...
        success = service::Delete(g_serviceHandle);
    }

    CloseServiceHandle(g_serviceHandle);
    g_serviceHandle = nullptr;

    return success;
}
} // namespace loader
} // namespace masterhide