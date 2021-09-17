#include <stdint.h>
#include "ieee_dot11.h"
#include "netmon_dot11.h"
#include "file_helpers.h"


struct ip *find_ip_header_eth(uint8_t *packet_buf, 
			      size_t num_bytes)
{
  struct ether_header *eth_hdr_ptr = (struct ether_header *) packet_buf;
  uint16_t ether_type;

  if (num_bytes < ETHER_HEADER_SIZE + IPV4_HEADER_SIZE)
    return NULL;

  ether_type = ntohs(eth_hdr_ptr->ether_type);

  switch (ether_type) {
  case ETHERTYPE_IP:
    /* fall through */
  case ETHERTYPE_IPV6:
    return (struct ip *) (packet_buf + ETHER_HEADER_SIZE);
  case ETHERTYPE_VLAN:
    return find_ip_header_802_1q(packet_buf + ETHER_HEADER_SIZE, num_bytes - ETHER_HEADER_SIZE);
  case ETHERTYPE_S_VLAN:
    return find_ip_header_802_1q(packet_buf + ETHER_HEADER_SIZE, num_bytes - ETHER_HEADER_SIZE);    
  case ETHERTYPE_PPPOE:
    return find_ip_header_pppoe(packet_buf + ETHER_HEADER_SIZE, num_bytes - ETHER_HEADER_SIZE);
  }
  return NULL;
}


struct ip *find_ip_header_802_1q(uint8_t *packet_buf, 
				 size_t num_bytes)
{

  uint16_t ether_type;

  if (num_bytes < 2 + VLAN_HEADER_SIZE + IPV4_HEADER_SIZE)
    return NULL;

  ether_type = ntohs(*(uint16_t *) (packet_buf + VLAN_HEADER_SIZE));
  size_t off = 2 + VLAN_HEADER_SIZE;

  switch (ether_type) {
  case ETHERTYPE_IP:
    /* fall through */
  case ETHERTYPE_IPV6:
    return (struct ip *) (packet_buf + off);
  case ETHERTYPE_VLAN:
    return find_ip_header_802_1q(packet_buf + off, num_bytes - off);
  case ETHERTYPE_PPPOE:
    return find_ip_header_pppoe(packet_buf + off, num_bytes - off);
  }
  return NULL;
}


struct ip *find_ip_header_pppoe(uint8_t *packet_buf, 
				 size_t num_bytes)
{

  uint16_t pppoe_type;

  if (num_bytes < 2 + PPPOE_HEADER_SIZE + IPV4_HEADER_SIZE)
    return NULL;

  pppoe_type = ntohs(*(uint16_t *) (packet_buf + PPPOE_HEADER_SIZE));
  size_t off = 2 + PPPOE_HEADER_SIZE;

  switch (pppoe_type) {
  case PPPOETYPE_IPV4:
    /* fall through */
  case PPPOETYPE_IPV6:
    return (struct ip *) (packet_buf + off);
  }
  return NULL;
}


struct ip *find_ip_header_netmon_dot11(uint8_t *packet_buf, 
				       size_t num_bytes)
{
  struct netmon_802_11_capture_header *netmon_hdr_ptr = (struct netmon_802_11_capture_header *) packet_buf;
  struct ieee_dot11_header *dot11_hdr_ptr;
  struct ieee_dot2_snap_header *snap_hdr_ptr;
  int off = 0;
  uint16_t ether_type;

  if (off + sizeof(struct netmon_802_11_capture_header) >= num_bytes) {
    return NULL;
  }

  off +=  netmon_hdr_ptr->header_len_hi * 256 + netmon_hdr_ptr->header_len_lo;

  if (off + sizeof(struct ieee_dot11_header) >= num_bytes) {
    return NULL;
  }

  dot11_hdr_ptr = (struct ieee_dot11_header *) (packet_buf + off);

  uint16_t fc = ntohs(dot11_hdr_ptr->fc);

  if ((fc & IEEE_DOT11_FC_TYPE_MASK) != IEEE_DOT11_FC_TYPE_DATA) {
    return NULL;
  }

  off += IEEE_DOT11_HEADER_LEN;

  if ((fc & IEEE_DOT11_FC_SUBTYPE_MASK) == IEEE_DOT11_FC_SUBTYPE_DATA_QOS) {
    off += 2;
  }

  if ((dot11_hdr_ptr->fc & IEEE_DOT11_FC_DS_STATUS_MASK) == 0x3) {
    off += 6;
  }

  if (off + IEEE_SNAP_HEADER_LEN >= num_bytes) {
    return NULL;
  }

  snap_hdr_ptr = (struct ieee_dot2_snap_header *) (packet_buf + off);

  if (snap_hdr_ptr->ssap != 0xaa 
      || snap_hdr_ptr->dsap != 0xaa
      || snap_hdr_ptr->control != 0x03
      || snap_hdr_ptr->organization[0] != 0x00
      || snap_hdr_ptr->organization[1] != 0x00
      || snap_hdr_ptr->organization[2] != 0x00) {
    return NULL;
  }

  ether_type = ntohs(snap_hdr_ptr->ether_type);

  off += IEEE_SNAP_HEADER_LEN;

  if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6) {
    return NULL;
  }

  return (struct ip *) (packet_buf + off);
}


struct ip *find_ip_header_sll(uint8_t *packet_buf, 
			      size_t num_bytes)
{
  struct sll_header *sll_hdr_ptr = (struct sll_header *) packet_buf;
  uint16_t ether_type;

  if (num_bytes < SLL_HDR_LEN + IPV4_HEADER_SIZE)
    return NULL;

  ether_type = ntohs(sll_hdr_ptr->sll_protocol);

  switch (ether_type) {
  case ETHERTYPE_IP:
    /* fall through */
  case ETHERTYPE_IPV6:
    return (struct ip *) (packet_buf + SLL_HDR_LEN);
  case ETHERTYPE_P_MAP:
    return (struct ip *) (packet_buf + SLL_HDR_LEN + P_MAP_HDR_SIZE);
  }
  return NULL;
}


struct ip *find_ip_header_sll2(uint8_t *packet_buf, 
			      size_t num_bytes)
{
  struct sll2_header *sll2_hdr_ptr = (struct sll2_header *) packet_buf;
  uint16_t ether_type;

  if (num_bytes < SLL2_HDR_LEN + IPV4_HEADER_SIZE)
    return NULL;

  ether_type = ntohs(sll2_hdr_ptr->sll2_protocol);

  switch (ether_type) {
  case ETHERTYPE_IP:
    /* fall through */
  case ETHERTYPE_IPV6:
    return (struct ip *) (packet_buf + SLL2_HDR_LEN);
  }
  return NULL;
}


struct ip *find_ip_header_erf(uint8_t *packet_buf, 
			      size_t num_bytes)
{
  struct erf_header *erf_hdr_ptr = (struct erf_header *) packet_buf;

  if (erf_hdr_ptr->erf_type != 0x02) {
    fprintf(stderr, "Error parsing ERF header: got packet with erf_type=0x%x",
	    erf_hdr_ptr->erf_type);
    exit(1);
  }

  int skip_bytes = sizeof(struct erf_header) + 2;
  
  if (num_bytes < skip_bytes) {
    return NULL;
  }

  return find_ip_header_eth(packet_buf + skip_bytes, num_bytes - skip_bytes);
}
