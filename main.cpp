#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <linux/if.h>
#include "protocol/ethernet.h"
#include "protocol/ip.h"
#include "protocol/arp.h"

void printMACAddr(mac_addr mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printIPAddr(ip_addr ip)
{
    printf("%u.%u.%u.%u\n", ip.a, ip.b, ip.c, ip.d);
}

bool arpSend(pcap_t *handle,      /* Network handle                                */
             mac_addr eth_src,    /* Source MAC address for ethernet header        */
             mac_addr eth_dst,    /* Destination MAC address for ethernet header   */
             mac_addr arp_srcmac, /* Source MAC address for arp header             */
             ip_addr arp_srcip,   /* Source IP address for arp header              */
             mac_addr arp_dstmac, /* Destination MAC address for arp header        */
             ip_addr arp_dstip,   /* Destination IP address for arp header         */
             uint16_t arp_opcode) /* Opereation code for arp header                */
{
    u_char packet[42];
    int packetIndex = 0;
    ether_header eth;
    eth.dst = eth_dst;
    eth.src = eth_src;
    eth.ether_type = hexswap(ETHERTYPE_ARP);
    memcpy(packet, &eth, sizeof(ether_header));
    packetIndex += sizeof(ether_header);

    arp_header arp;
    arp.arp_hwtype = hexswap(ARPHRD_ETHER);
    arp.arp_prtype = hexswap(ETHERTYPE_IP);
    arp.arp_hwsize = 6;
    arp.arp_prsize = 4;
    arp.arp_opcode = hexswap(arp_opcode);
    arp.arp_srcmac = arp_srcmac;
    arp.arp_srcip = arp_srcip;
    arp.arp_dstmac = arp_dstmac;
    arp.arp_dstip = arp_dstip;
    memcpy(packet + packetIndex, &arp, sizeof(arp_header));
    packetIndex += sizeof(arp_header);

    while (1)
    {
        if (pcap_sendpacket(handle, packet, packetIndex))
            puts("send fail");
        else
            puts("sended");
        sleep(1);
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int mode;
    int i;
    char interface[IFNAMSIZ];

    system("clear");

    printf("Enter the interface\n\n\t\t> ");
    fgets(interface, IFNAMSIZ, stdin);

    for (i = 0; i < strlen(interface); i++)
        if (interface[i] == '\n')
            interface[i] = NULL;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

    system("clear");

    ip_addr targetIP;
    ip_addr senderIP;
    mac_addr senderMAC;
    mac_addr targetMAC;
    mac_addr ethernetDstMAC;
    mac_addr ethernetSrcMAC;
    uint16_t opcode;

    printf("Select mode\n1. ARP request\n2. ARP reply\n\n\t\t> ");
    scanf("%d", &mode);
    switch (mode)
    {
    case 1:
        opcode = ARPOP_REQUEST;
        break;
    case 2:
        opcode = ARPOP_REPLY;
        break;
    default:
        printf("Wrong input\n");
        return -1;
    }
    system("clear");
    printf("Select mode\n1. UNICAST\n2. BROADCAST\n\n\t\t> ");
    scanf("%d", &mode);
    switch (mode)
    {
    case 1:
        printf("\nEnter source mac address\n\n\t\t> ");
        scanf("%x:%x:%x:%x:%x:%x", &ethernetSrcMAC.oui[0], &ethernetSrcMAC.oui[1], &ethernetSrcMAC.oui[2],
              &ethernetSrcMAC.nic[0], &ethernetSrcMAC.nic[1], &ethernetSrcMAC.nic[2]);
        senderMAC = ethernetSrcMAC;
        printMACAddr(ethernetSrcMAC);
        printMACAddr(senderMAC);

        printf("\nEnter destination mac address\n\n\t\t> ");
        scanf("%x:%x:%x:%x:%x:%x", &ethernetDstMAC.oui[0], &ethernetDstMAC.oui[1], &ethernetDstMAC.oui[2],
              &ethernetDstMAC.nic[0], &ethernetDstMAC.nic[1], &ethernetDstMAC.nic[2]);
        targetMAC = ethernetDstMAC;
        printMACAddr(ethernetSrcMAC);
        printMACAddr(senderMAC);
        printMACAddr(ethernetDstMAC);
        printMACAddr(targetMAC);

        printf("\nEnter sender IP\n\n\t\t> ");
        scanf("%u.%u.%u.%u", &senderIP.a, &senderIP.b, &senderIP.c, &senderIP.d);
        printMACAddr(ethernetSrcMAC);
        printMACAddr(senderMAC);
        printMACAddr(ethernetDstMAC);
        printMACAddr(targetMAC);
        printIPAddr(senderIP);

        printf("\nEnter target IP\n\n\t\t> ");
        scanf("%u.%u.%u.%u", &targetIP.a, &targetIP.b, &targetIP.c, &targetIP.d);
        printMACAddr(ethernetSrcMAC);
        printMACAddr(senderMAC);
        printMACAddr(ethernetDstMAC);
        printMACAddr(targetMAC);
        printIPAddr(senderIP);
        printIPAddr(targetIP);
        break;
    case 2:
        printf("\nEnter source mac address\n\n\t\t> ");
        scanf("%x:%x:%x:%x:%x:%x", &ethernetSrcMAC.oui[0], &ethernetSrcMAC.oui[1], &ethernetSrcMAC.oui[2],
              &ethernetSrcMAC.nic[0], &ethernetSrcMAC.nic[1], &ethernetSrcMAC.nic[2]);
        senderMAC = ethernetSrcMAC;

        ethernetDstMAC = {{0xff, 0xff, 0xff}, {0xff, 0xff, 0xff}};
        targetMAC = {{0x00, 0x00, 0x00}, {0x00, 0x00, 0x00}};

        printf("\nEnter sender IP\n\n\t\t> ");
        scanf("%u.%u.%u.%u", &senderIP.a, &senderIP.b, &senderIP.c, &senderIP.d);

        if (opcode == ARPOP_REQUEST)
        {
            printf("\nEnter target IP\n\n\t\t> ");
            scanf("%u.%u.%u.%u", &targetIP.a, &targetIP.b, &targetIP.c, &targetIP.d);
        }
        else
            targetIP = {0, 0, 0, 0};
        break;
    default:
        printf("Wrong input\n");
        return -1;
    }

    printf("Ethernet source MAC address: ");
    printMACAddr(ethernetSrcMAC);
    printf("Ethernet destination MAC address: ");
    printMACAddr(ethernetDstMAC);
    printf("ARP sender MAC: ");
    printMACAddr(senderMAC);
    printf("ARP sender IP: ");
    printIPAddr(senderIP);
    printf("ARP target MAC: ");
    printMACAddr(targetMAC);
    printf("ARP target IP: ");
    printIPAddr(targetIP);
    printf("ARP opcode: ");
    printf(opcode - 1 ? "ARP REPLY\n" : "ARP REQUEST\n");

    arpSend(handle, ethernetSrcMAC, ethernetDstMAC, senderMAC, senderIP, targetMAC, targetIP, opcode);

    pcap_close(handle);

    return 0;
}