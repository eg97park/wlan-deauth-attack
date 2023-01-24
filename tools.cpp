#include "pch.h"
#include "tools.h"


void usage(char* argv[])
{
    printf("syntax: %s <interface> <ap mac> [<station mac> [-auth]]\n", argv[0]);
    printf("sample: %s wlp45s0 00:11:22:33:44:55 66:77:88:99:AA:BB\n", argv[0]);
}


bool parse(Param* param, int argc, char* argv[])
{
    const char* AUTH_OPT = "-auth";
    
    if (argc < 3 || 5 < argc)
    {
        usage(argv);
        return false;
    }
    param->if_ = argv[1];
    param->ap_mac_ = argv[2];
    param->auth_opt_ = false;

    switch (argc)
    {
    case 4:
        param->st_mac_ = argv[3];
        break;
    case 5:
        param->st_mac_ = argv[3];
        if (std::strlen(argv[4]) == std::strlen(AUTH_OPT) &&
            std::strncmp(argv[4], AUTH_OPT, std::strlen(AUTH_OPT)) == 0)
        {
            param->auth_opt_ = true;
        }
        else
        {
            return false;
        }
        break;
    default:
        break;
    }
    return true;
}


void dump(void* p, size_t n)
{
    uint8_t* u8 = static_cast<uint8_t*>(p);
    size_t i = 0;
    while (true) {
        printf("%02X ", *u8++);
        if (++i >= n) break;
        if (i % 8 == 0) printf(" ");
        if (i % 16 == 0) printf("\n");
    }
    printf("\n");
}
