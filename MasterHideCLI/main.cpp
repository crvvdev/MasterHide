#include "includes.hpp"

int main()
{
    SetConsoleTitleA("MasterHide CLI");

    try
    {
        kaspersky::Load();
        printf("Kaspersky loaded!\n");

        loader::Load(HookTypeInfinityHook);
        printf("MasterHide loaded!\nPress END key to unload all drivers.\n");

        while (!(GetAsyncKeyState(VK_END) & 1))
        {
            Sleep(10);
        }

        loader::Unload();
        kaspersky::Unload();
    }
    catch (const std::exception &e)
    {
        kaspersky::Unload();

        printf("Exception: %s\n", e.what());
        getchar();
    }

    return ERROR_SUCCESS;
}