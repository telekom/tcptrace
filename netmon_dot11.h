#ifndef NETMON_DOT11_H
#define NETMON_DOT11_H

struct netmon_802_11_capture_header {
  
  uint8_t header_revision;
  uint8_t header_len_lo;
  uint8_t header_len_hi;
  uint8_t dummy;

};

#endif
