#include "pch.h"


/**
 * @brief 사용법을 출력하는 함수.
 * 
 * @param argv 
 */
void usage(char* argv[]);


/**
 * @brief 인자 저장용 구조체.
 * 
 */
typedef struct {
    char* if_;
    uint8_t* ap_mac_;
    uint8_t* st_mac_;
    bool auth_opt_;
} __attribute__((__packed__)) Param;


/**
 * @brief 주어진 인자를 파싱하여 처리하는 함수.
 * 
 * @param param ?
 * @param argc 인자 개수
 * @param argv 인자 배열
 * @return true 
 * @return false 
 */
bool parse(Param* param, int argc, char* argv[]);


/**
 * @brief 주어진 주소로부터 메모리 값을 주어진 만큼 읽어 출력하는 함수.
 * 
 * @param p 읽을 주소
 * @param n 읽을 크기
 * 
 * @ref https://gitlab.com/gilgil/sns/-/wikis/byte-order/byte-order
 */
void dump(void* p, size_t n);


/**
 * @brief 주어진 MAC 주소의 자료형을 문자열로부터 uint8_t*로 바꾸어 반환하는 함수.
 * 
 * @param mac_addr 00:01:02:03:04:05와 같이 주어진 MAC 주소 문자열.
 * 
 * @return uint8_t* 6개의 uint8_t 값으로 이루어진 배열의 첫 번째 원소의 주소.
 */
uint8_t* parse_mac_addr(const char* mac_addr);