#include "includes.hpp"

namespace masterhide
{
namespace service
{
bool Start(_In_ SC_HANDLE serviceHandle)
{
    const auto success = static_cast<bool>(StartServiceA(serviceHandle, 0, nullptr));

    return success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

bool Delete(_In_ SC_HANDLE serviceHandle)
{
    const auto success = static_cast<bool>(DeleteService(serviceHandle));

    return success || GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE;
}

bool Stop(_In_ SC_HANDLE serviceHandle, _In_ LPSERVICE_STATUS serviceStatus)
{
    return static_cast<bool>(ControlService(serviceHandle, SERVICE_CONTROL_STOP, serviceStatus));
}

SC_HANDLE CreateOrOpen(_In_ const std::string &name, _In_ const std::string &displayName, _In_ const std::string &path)
{
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
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