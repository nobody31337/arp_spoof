#pragma once

#include <stdint.h>

#define ICMP_PINGREPLY      0
#define ICMP_PINGREQUEST    8

struct icmp_header{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum;
};