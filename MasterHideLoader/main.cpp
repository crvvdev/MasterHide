#include <Windows.h>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

#include "service.hpp"
#include "loader.hpp"
#include "klhk.hpp"

using namespace masterhide;

int main()
{
    SetConsoleTitleA("MasterHide Loader");

    try
    {
#if (MASTERHIDE_MODE == MASTERHIDE_MODE_KASPERSKYHOOK)
        kaspersky::Load();
        printf("Kaspersky loaded!\n");
#endif

        loader::Load();
        printf("MasterHide loaded!\n");

        printf("Press END key to unload all drivers.\n");

        while (!(GetAsyncKeyState(VK_END) & 1))
        {
            Sleep(10);
        }

        loader::Cleanup();

#if (MASTERHIDE_MODE == MASTERHIDE_MODE_KASPERSKYHOOK)
        kaspersky::Cleanup(false);
#endif
    }
    catch (const std::exception &e)
    {
#if (MASTERHIDE_MODE == MASTERHIDE_MODE_KASPERSKYHOOK)
        kaspersky::Cleanup(false);
#endif

        printf("Exception: %s\n", e.what());
        getchar();
    }

    return ERROR_SUCCESS;
}