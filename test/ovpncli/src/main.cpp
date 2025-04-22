#include "ovpncli.hpp"
#include <iostream>

#ifndef OPENVPN_OVPNCLI_OMIT_MAIN

int main(int argc, char *argv[])
{
    int ret = 0;

#ifdef OPENVPN_LOG_LOGBASE_H
    LogBaseSimple log;
#endif

#if defined(OPENVPN_PLATFORM_WIN)
    SetConsoleOutputCP(CP_UTF8);
#endif

    try
    {
        ret = openvpn_client(argc, argv, nullptr);
    }
    catch (const std::exception &e)
    {
        std::cout << "Main thread exception: " << e.what() << std::endl;
        ret = 1;
    }
    return ret;
}

#endif