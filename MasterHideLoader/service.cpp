#include "includes.hpp"

namespace masterhide
{
namespace service
{
bool Start(SC_HANDLE serviceHandle)
{
    const auto success = static_cast<bool>(StartService(serviceHandle, 0, nullptr));

    return success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool Delete(SC_HANDLE serviceHandle)
{
    const auto success = static_cast<bool>(DeleteService(serviceHandle));

    return success || GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE;
}

bool Stop(SC_HANDLE serviceHandle, LPSERVICE_STATUS serviceStatus)
{
    return static_cast<bool>(ControlService(serviceHandle, SERVICE_CONTROL_STOP, serviceStatus));
}

SC_HANDLE CreateOrOpen(const std::string &name, const std::string &displayName, const std::string &path)
{
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        return nullptr;
    }

    SC_HANDLE svcHandle = CreateServiceA(scm, name.c_str(), displayName.c_str(), SERVICE_ALL_ACCESS,
                                         SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                         path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svcHandle && GetLastError() == ERROR_SERVICE_EXISTS)
    {
        svcHandle = OpenServiceA(scm, name.c_str(), SERVICE_ALL_ACCESS);
    }

    CloseServiceHandle(scm);
    return svcHandle;
}
} // namespace service
} // namespace masterhide