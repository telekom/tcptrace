#ifndef MS_NETMON_H
#define MS_NETMON_H

#include <stdint.h>
#include <stdio.h>

#define NETMON_MAX_PACKET_SIZE 65535
#define NETMON_MIN_INVALID_FRAME_LENGTH 100000

#define NETMON_HEADER_SIZE 32
#define NETMON_MAGIC 0x55424d47
#define NETMON_MIN_VER 0x0200
#define NETMON_VER_2_1 0x0201
#define NETMON_VER_2_3 0x0203

#define FRAME_OFF_BUFFER_SIZE 1024

#define NETMON_MAC_TYPE_ZERO 0
#define NETMON_MAC_TYPE_ETHERNET 1
#define NETMON_MAC_TYPE_DOT11 6 
#define NETMON_MAC_TYPE_WIRELESS_WAN 8

#define ETHER_HEADER_SIZE 14
#define IPV4_HEADER_SIZE 20
#define VLAN_HEADER_SIZE 2


struct netmon_file_header {
  
  uint8_t signature[4];
  uint8_t bcd_ver_minor;
  uint8_t bcd_ver_major;
  uint16_t mac_type;
  uint16_t ts_year;
  uint16_t ts_month;
  uint16_t ts_day_of_week;
  uint16_t ts_day ;
  uint16_t ts_hour;
  uint16_t ts_minute;
  uint16_t ts_second;
  uint16_t ts_millisecond;
  uint32_t frame_table_offset;
  uint32_t frame_table_length;
};


struct netmon_frame_header {

  /* 
  uint32_t ts_low;
  uint32_t ts_high;
  */
  uint64_t ts;
  uint32_t frame_length;
  uint32_t num_bytes_avail;
};


struct netmon_frame_trailer_2_1 {
  uint8_t network[2];
};


struct netmon_frame_trailer_2_3 {
  uint8_t network[2];
  uint8_t process_info_index[4];
  uint8_t utc_timestamp[8];
  uint8_t timezone_index;
};


struct netmon_file_context {

  uint8_t packet_buf[NETMON_MAX_PACKET_SIZE];
  FILE *fp;
  uint32_t frame_off_buf[FRAME_OFF_BUFFER_SIZE];
  uint32_t num_off_avail;
  uint32_t frame_off_buf_index;
  uint32_t frame_table_off;
  uint32_t num_frames;
  uint32_t current_frame;
  struct timespec tspec_first;
  uint16_t mac_type;
  uint16_t version;
};

#define convert_letoh64(p) ((uint64_t)*((const uint8_t *)(p) + 7) << 56 |	\
			    (uint64_t)*((const uint8_t *)(p) + 6) << 48 | \
			    (uint64_t)*((const uint8_t *)(p) + 5) << 40 | \
			    (uint64_t)*((const uint8_t *)(p) + 4) << 32 | \
			    (uint64_t)*((const uint8_t *)(p) + 3) << 24 | \
			    (uint64_t)*((const uint8_t *)(p) + 2) << 16 | \
			    (uint64_t)*((const uint8_t *)(p) + 1) << 8 | \
			    (uint64_t)*((const uint8_t *)(p) + 0))

#define convert_letoh32(p) ((uint32_t)*((const uint8_t *)(p) + 3) << 24 | \
			    (uint32_t)*((const uint8_t *)(p) + 2) << 16 | \
			    (uint32_t)*((const uint8_t *)(p) + 1) << 8 | \
			    (uint32_t)*((const uint8_t *)(p) + 0))

#define convert_letoh16(p) ((uint16_t)*((const uint8_t *)(p) + 1) << 8 | \
			    (uint16_t)*((const uint8_t *)(p) + 0))

#endif /* NS_NETMON_H */
