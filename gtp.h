#ifndef GTP_HEADER
#define GTP_HEADER

#include <stdint.h>

struct gtphdr {

  u_int8_t flags;
  u_int8_t message_type;
  u_int16_t total_length;
  u_int32_t teid;
};

#endif 
