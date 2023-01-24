#include "pch.h"
#include "wlanhdr.h"


const uint16_t DEAUTH_FRAME = 0x00c0;
const uint16_t HANDSHAKE_TIMEOUT = 0x000f;


/**
 * @brief class DeauthAttack 반환 값에 사용될 구조체.
*/
typedef struct WLAN_DEAUTH_ATTACK_PAKCET {
    u_char* packet;
    uint64_t size;
} wlan_deauth_pkt;

/**
 * @brief deauth attack 패킷 생성용 클래스.
*/
class DeauthAttack
{
private:
    static const dot11_radiotap_hdr rtap_hdr;
    dot11_deauth_fhdr deauth_fhdr;
    dot11_wlm_deauth_hdr wlm_hdr;

    wlan_deauth_pkt* assemble_pkt();
    void init_pkt(const uint8_t ap_mac_addr[6]);
public:
    DeauthAttack(const uint8_t ap_mac_addr[6]);
    DeauthAttack(const uint8_t ap_mac_addr[6], const uint8_t st_mac_addr[6]);
    ~DeauthAttack();

    wlan_deauth_pkt* get_pkt();
};
