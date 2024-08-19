#pragma once

#include <stdint.h>
#include "ethernet.h"
#include "ip.h"

/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM		0		/* from KA9Q: NET/ROM pseudo	*/
#define ARPHRD_ETHER 		1		/* Ethernet 10Mbps				*/
#define	ARPHRD_EETHER		2		/* Experimental Ethernet		*/
#define	ARPHRD_AX25			3		/* AX.25 Level 2				*/
#define	ARPHRD_PRONET		4		/* PROnet token ring			*/
#define	ARPHRD_CHAOS		5		/* Chaosnet						*/
#define	ARPHRD_IEEE802		6		/* IEEE 802.2 Ethernet/TR/TB	*/
#define	ARPHRD_ARCNET		7		/* ARCnet						*/
#define	ARPHRD_APPLETLK		8		/* APPLEtalk					*/
#define ARPHRD_DLCI			15		/* Frame Relay DLCI				*/
#define ARPHRD_ATM			19		/* ATM 							*/
#define ARPHRD_METRICOM		23		/* Metricom STRIP (new IANA id)	*/
#define	ARPHRD_IEEE1394		24		/* IEEE 1394 IPv4 - RFC 2734	*/
#define ARPHRD_EUI64		27		/* EUI-64                       */
#define ARPHRD_INFINIBAND 	32		/* InfiniBand					*/

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST		1		/* ARP request			        */
#define	ARPOP_REPLY			2		/* ARP reply			        */
#define	ARPOP_RREQUEST		3		/* RARP request			        */
#define	ARPOP_RREPLY		4		/* RARP reply			        */
#define	ARPOP_InREQUEST		8		/* InARP request		        */
#define	ARPOP_InREPLY		9		/* InARP reply			        */
#define	ARPOP_NAK			10		/* (ATM)ARP NAK			        */

struct arp_header
{
	uint16_t arp_hwtype;
	uint16_t arp_prtype;
	uint8_t arp_hwsize;
	uint8_t arp_prsize;
	uint16_t arp_opcode;
	mac_addr arp_srcmac;
	ip_addr arp_srcip;
	mac_addr arp_dstmac;
	ip_addr arp_dstip;
};