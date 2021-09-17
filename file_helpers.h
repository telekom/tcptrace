#ifndef FILE_HELPERS_H
#define FILE_HELPERS_H

#include <stdint.h>
#include "tcptrace.h"

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
#define PPPOE_HEADER_SIZE 6

#define ETHERTYPE_PPPOE 0x8864

#define PPPOETYPE_IPV4 0x0021
#define PPPOETYPE_IPV6 0x0057

struct ip *find_ip_header_eth(uint8_t *packet_buf, size_t num_bytes);
struct ip *find_ip_header_netmon_dot11(uint8_t *packet_buf, size_t num_bytes);
struct ip *find_ip_header_sll(uint8_t *packet_buf, size_t num_bytes);
struct ip *find_ip_header_sll2(uint8_t *packet_buf, size_t num_bytes);
struct ip *find_ip_header_802_1q(uint8_t *packet_buf, size_t num_bytes); 
struct ip *find_ip_header_pppoe(uint8_t *packet_buf, size_t num_bytes); 
struct ip *find_ip_header_erf(uint8_t *packet_buf, size_t num_bytes);


#define SLL_HDR_LEN	16		/* total header length */
#define SLL_ADDRLEN	8		/* length of address field */

#define SLL2_HDR_LEN	20		/* total header length */
#define SLL2_ADDRLEN	8		/* length of address field */

struct sll_header {
	u_int16_t sll_pkttype;		/* packet type */
	u_int16_t sll_hatype;		/* link-layer address type */
	u_int16_t sll_halen;		/* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t sll_protocol;		/* protocol */
};

struct sll2_header {
  u_int16_t sll2_protocol;		/* protocol */
  u_int16_t sll2_zero1;
  u_int32_t sll2_if_index;
  u_int16_t sll2_hatype;
  u_int8_t ssl2_pkttype;
  u_int8_t ssl2_halen;
  u_int8_t sll_addr[SLL_ADDRLEN];
};

struct erf_header {
  u_int64_t erf_timestamp;
  u_int8_t erf_type;
  u_int8_t erf_flags;
  u_int16_t erf_rlen;
  u_int16_t erf_lcr_color;
  u_int16_t erf_wlen;
};


#endif /* FILE_HELPERS_H */
