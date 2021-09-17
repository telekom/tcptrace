#ifndef TINY_PCAP_H
#define TINY_PCAP_H

#include <stdint.h>
#include <stdio.h>

#define PCAP_MAX_PACKET_SIZE 65535

#define PCAP_MAGIC_NATIVE       0xa1b2c3d4
#define PCAP_MAGIC_SWAPPED      0xd4c3b2a1
#define PCAP_MAGIC_NATIVE_NANO  0xa1b23c4d
#define PCAP_MAGIC_SWAPPED_NANO 0x4d3cb2a1

/* currently supported */
#define PCAP_DLT_NULL		0	/* no link-layer encapsulation */
#define PCAP_DLT_EN10MB		1	/* Ethernet (10Mb) */
#define PCAP_DLT_IEEE802	6	/* IEEE 802 Networks */
#define PCAP_DLT_SLIP		8	/* Serial Line IP */
#define PCAP_DLT_PPP            9       /* Point-to-Point Protocol */
#define PCAP_DLT_FDDI		10	/* FDDI */
#define PCAP_DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define PCAP_DLT_RAW		12	/* raw IP */
#define PCAP_DLT_RAW_NEW        101
#define PCAP_DLT_C_HDLC         104     /* Cisco HDLC */
#define PCAP_DLT_IEEE802_11     105     /* IEEE 802.11 wireless */
#define PCAP_DLT_LINUX_SLL      113     /* Linux cooked socket */
#define PCAP_DLT_PRISM2         119     /* Prism2 raw capture header */
#define PCAP_DLT_IEEE802_11_RADIO 127   /* 802.11 plus WLAN header */
#define PCAP_DLT_ERF            197     /* Extensible record format */
#define PCAP_DLT_LINUX_SLL2     276     /* Linux cooked capture v2 */

/* NOT currently supported */
/* (mostly because I don't have an example file, send me one...) */
#define PCAP_DLT_EN3MB		2	/* Experimental Ethernet (3Mb) */
#define PCAP_DLT_AX25		3	/* Amateur Radio AX.25 */
#define PCAP_DLT_PRONET		4	/* Proteon ProNET Token Ring */
#define PCAP_DLT_CHAOS		5	/* Chaos */
#define PCAP_DLT_ARCNET		7	/* ARCNET */
#define PCAP_DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define PCAP_DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */

#ifndef SWAPLONG
#define	SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#endif /* SWAPLONG */

#ifndef SWAPSHORT
#define	SWAPSHORT(y) \
	( (((y)&0xff)<<8) | (((y)&0xff00)>>8) )
#endif /* SWAPSHORT */

#define ETHER_HEADER_SIZE 14
#define IPV4_HEADER_SIZE 20
#define VLAN_HEADER_SIZE 2

struct tiny_pcap_file_header {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t thiszone;	/* gmt to local correction */
  uint32_t sigfigs;	/* accuracy of timestamps */
  uint32_t snaplen;	/* max length saved portion of each pkt */
  uint32_t linktype;	/* data link type (LINKTYPE_*) */
};

struct tiny_pcap_pkthdr {
	uint32_t tv_sec;
	uint32_t tv_usec;	
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
};


struct pcap_file {
  uint8_t packet_buf[PCAP_MAX_PACKET_SIZE];
  FILE *fp;
  struct tiny_pcap_file_header pcap_header;
  int is_swapped;
  int is_nano_second;
};

#endif /* TINY_PCAP_H */
