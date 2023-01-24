#include "pch.h"
#include "wlanhdr.h"

const int DEAUTH_ATTACK_AP_TO_BROADCAST = 0;
const int DEAUTH_ATTACK_AP_TO_STATION = 1;
const int DEAUTH_ATTACK_STATION_TO_AP = 2;
const int AUTH_ATTTACK_STATION_TO_AP_AUTH = 3;
const int AUTH_ATTTACK_STATION_TO_AP_ASSO_REQ = 4;

const uint16_t ASSO_REQ_FRAME = 0x0000;
const uint16_t AUTH_FRAME = 0x00b0;
const uint16_t DEAUTH_FRAME = 0x00c0;
const uint16_t HANDSHAKE_TIMEOUT = 0x000f;
const uint16_t CLASS3_NONASSOCIATED_STA = 0x0007;


/**
 * @brief class DeauthAttack 반환 값에 사용될 구조체.
*/
typedef struct WLAN_DEAUTH_ATTACK_PAKCET {
    u_char* packet;
    uint64_t size;
} __attribute__((__packed__)) wlan_attack_pkt;
typedef wlan_attack_pkt wlan_auth_pkt;


/**
 * @brief Deauth attack 패킷 생성용 클래스.
*/
class DeauthAttack
{
private:
    int mode;
    static const dot11_radiotap_hdr rtap_hdr;
    dot11_deauth_fhdr deauth_fhdr;
    dot11_wlm_auth_hdr wlm_auth_hdr;
    dot11_wlm_deauth_hdr wlm_deauth_hdr;
    dot11_wlm_asso_req_hdr wlm_asso_req_hdr;

    wlan_attack_pkt* assemble_pkt();
    wlan_attack_pkt* assemble_auth_attack_pkt();
    wlan_attack_pkt* assemble_auth_attack_auth_pkt();
    wlan_attack_pkt* assemble_auth_attack_asso_req_pkt();
    wlan_attack_pkt* assemble_deauth_attack_pkt();

    void init_pkt(const uint8_t* ap_mac_addr, const uint8_t* st_mac_addr);
public:
    DeauthAttack(const uint8_t* ap_mac_addr, const uint8_t* st_mac_addr, const int mode);
    ~DeauthAttack();

    wlan_attack_pkt* get_pkt();
};
