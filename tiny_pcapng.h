#ifdef GROK_TINYPCAPNG

#include "tcptrace.h"
#include "tiny_pcap.h"

#define PCAPNG_BLOCK_TYPE_SECTION_HEADER 0x0a0d0d0a
#define PCAPNG_BLOCK_TYPE_IDB 1
#define PCAPNG_BLOCK_TYPE_SPB 3
#define PCAPNG_BLOCK_TYPE_EPB 6
#define PCAPNG_OPTION_IDB_IF_TSRESOL 9
#define PCAPNG_OPTION_ENDOFOPT 0
#define PCAPNG_ORDER_MAGIC_SWAPPED  0x4d3c2b1a
#define PCAPNG_ORDER_MAGIC_NATIVE  0x1a2b3c4d

#define PCAPNG_MAX_BLOCK_SIZE 65535
#define PCAPNG_MAX_INTERFACES 32
#define PCAPNG_MAX_ERROR_LEN 256

struct pcapng_interface {
  uint16_t link_type;
  long double ts_resol;
};

struct pcapng_file {

  FILE *fp;
  uint16_t (*get_uint16)(uint16_t val);
  uint32_t (*get_uint32)(uint32_t val);
  int num_bytes;
  uint8_t buf[PCAPNG_MAX_BLOCK_SIZE];
  
  int num_interfaces;
  struct pcapng_interface interfaces[PCAPNG_MAX_INTERFACES];
  char error_string[PCAPNG_MAX_ERROR_LEN];
};

struct pcapng_section_header {
  uint32_t block_type;
  uint32_t block_total_length;
  uint32_t block_order_magic;
  uint16_t major_version;
  uint16_t minor_version;
};

struct pcapng_idb {
  uint32_t block_type;
  uint32_t block_total_length;
  uint16_t link_type;
  uint16_t reserved;
  uint32_t snap_length;
};

struct pcapng_epb {
  uint32_t block_type;
  uint32_t block_total_length;
  uint32_t interface_id;
  uint32_t ts_high;
  uint32_t ts_low;
  uint32_t captured_length;
  uint32_t packet_length;
};

struct pcapng_spb {
  uint32_t block_type;
  uint32_t block_total_length;
  uint32_t packet_length;
};

struct pcapng_block {
  uint32_t block_type;
  uint32_t block_total_length;
};

struct pcapng_option {
  uint16_t option_code;
  uint16_t option_length;
};


#endif
