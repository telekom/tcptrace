#ifndef IEEE_DOT_11_H
#define IEEE_DOT_11_H

struct ieee_dot11_header {  
  uint16_t fc;
  uint16_t duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t sequence_control;
};

struct ieee_dot2_snap_header {
  uint8_t ssap;
  uint8_t dsap;
  uint8_t control;
  uint8_t organization[3];
  uint16_t ether_type;
};

#define IEEE_DOT11_HEADER_LEN 24
#define IEEE_SNAP_HEADER_LEN 8
#define IEEE_DOT11_FC_TYPE_DATA 0x0800
#define IEEE_DOT11_FC_TYPE_MASK 0x0c00
#define IEEE_DOT11_FC_SUBTYPE_DATA_QOS 0x8000
#define IEEE_DOT11_FC_SUBTYPE_MASK 0xf000
#define IEEE_DOT11_FC_DS_STATUS_MASK 0x0003

#endif
