#include "includes.hpp"

namespace masterhide
{
namespace kaspersky
{
SC_HANDLE g_serviceHandle = nullptr;
HKEY g_parametersKey = nullptr;

void Load()
{
    char buf[MAX_PATH]{};
    GetSystemDirectoryA(buf, ARRAYSIZE(buf));
    const auto driverPath = std::string{buf} + "\\drivers\\klhk.sys";

    g_serviceHandle = service::CreateOrOpen("klhk", "Kaspersky Lab service driver", driverPath);
    if (!g_serviceHandle)
    {
        throw std::runtime_error("Failed to create klhk service!");
    }

    LSTATUS errorCode =
        RegCreateKeyEx(HKEY_LOCAL_MACHINE, TEXT("System\\CurrentControlSet\\Services\\klhk\\Parameters"), 0, nullptr, 0,
                       KEY_ALL_ACCESS, nullptr, &g_parametersKey, nullptr);
    if (errorCode != ERROR_SUCCESS)
    {
        service::Delete(g_serviceHandle);
        CloseServiceHandle(g_serviceHandle);

        throw std::runtime_error("Failed to create klhk registry parameters!");
    }

    DWORD useHvm = 1;
    errorCode = RegSetValueEx(g_parametersKey, TEXT("UseHvm"), 0, REG_DWORD, reinterpret_cast<const BYTE *>(&useHvm),
                              sizeof(useHvm));
    if (errorCode != ERROR_SUCCESS)
    {
        RegDeleteKey(HKEY_LOCAL_MACHINE, TEXT("System\\CurrentControlSet\\Services\\klhk\\Parameters"));
        RegCloseKey(g_parametersKey);

        service::Delete(g_serviceHandle);
        CloseServiceHandle(g_serviceHandle);

        throw std::runtime_error("Failed to set klhk parameters in registry!");
    }

    const auto success = service::Start(g_serviceHandle);
    if (!success)
    {
        RegDeleteValue(g_parametersKey, TEXT("UseHvm"));
        RegDeleteKey(HKEY_LOCAL_MACHINE, TEXT("System\\CurrentControlSet\\Services\\klhk\\Parameters"));
        RegCloseKey(g_parametersKey);

        service::Delete(g_serviceHandle);
        CloseServiceHandle(g_serviceHandle);

        throw std::runtime_error("Failed to start klhk service!");
    }
}

void Unload(bool deleteService)
{
    if (g_parametersKey)
    {
        RegCloseKey(g_parametersKey);
        g_parametersKey = nullptr;
    }

    if (g_serviceHandle)
    {
        if (deleteService)
        {
            service::Delete(g_serviceHandle);
        }

        CloseServiceHandle(g_serviceHandle);
        g_serviceHandle = nullptr;
    }
}
} // namespace kaspersky
} // namespace masterhide