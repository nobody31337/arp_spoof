#pragma once

#include <stdint.h>
#include "ip.h"

struct udp_header
{
	uint16_t udp_srcport;
	uint16_t udp_dstport;
	uint16_t udp_len;
	uint16_t udp_sum;
};