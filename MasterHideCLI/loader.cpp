#include "includes.hpp"

namespace masterhide
{
namespace loader
{
SC_HANDLE g_serviceHandle = nullptr;
HKEY g_parametersKey = nullptr;

void Load(_In_ DWORD hookType)
{
    char buf[MAX_PATH]{};
    GetCurrentDirectoryA(ARRAYSIZE(buf), buf);
    const auto path = std::string{buf} + "\\MasterHide.sys";

    GetSystemDirectoryA(buf, ARRAYSIZE(buf));
    const auto destination = std::string{buf} + "\\drivers\\MasterHide.sys";

    if (!CopyFileA(path.c_str(), destination.c_str(), FALSE))
    {
        throw std::runtime_error("Failed to install MasterHide.sys!");
    }

    g_serviceHandle = service::CreateOrOpen("MasterHide", "MasterHide", path);
    if (!g_serviceHandle)
    {
        throw std::runtime_error("Failed to create or open MasterHide service!");
    }

    LSTATUS errorCode =
        RegCreateKeyEx(HKEY_LOCAL_MACHINE, TEXT("System\\CurrentControlSet\\Services\\MasterHide\\Parameters"), 0,
                       nullptr, 0, KEY_ALL_ACCESS, nullptr, &g_parametersKey, nullptr);
    if (errorCode != ERROR_SUCCESS)
    {
        service::Delete(g_serviceHandle);
        CloseServiceHandle(g_serviceHandle);

        throw std::runtime_error("Failed to create MasterHide registry parameters!");
    }

    errorCode = RegSetValueEx(g_parametersKey, TEXT("HookType"), 0, REG_DWORD,
                              reinterpret_cast<const BYTE *>(&hookType), sizeof(hookType));
    if (errorCode != ERROR_SUCCESS)
    {
        RegDeleteKey(HKEY_LOCAL_MACHINE, TEXT("System\\CurrentControlSet\\Services\\MasterHide\\Parameters"));
        RegCloseKey(g_parametersKey);

        CloseServiceHandle(g_serviceHandle);

        throw std::runtime_error("Failed to set klhk parameters in registry!");
    }

    if (!service::Start(g_serviceHandle))
    {
        RegDeleteValue(g_parametersKey, TEXT("HookType"));
        RegDeleteKey(HKEY_LOCAL_MACHINE, TEXT("System\\CurrentControlSet\\Services\\klhk\\Parameters"));
        RegCloseKey(g_parametersKey);

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