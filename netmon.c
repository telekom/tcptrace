#include "tcptrace.h"
#include "netmon.h"
#include "file_helpers.h"


static struct netmon_file_context nfc;

#define WINDOWS_TICKS_PER_SECOND 10000000
#define WINDOWS_TO_UNIX_EPOCH 11644473600LL

static int convert_filetime_to_timespec(uint64_t ts_filetime, struct timespec *ts) {
  ts->tv_nsec = (ts_filetime % WINDOWS_TICKS_PER_SECOND) * 100;
  ts->tv_sec = (ts_filetime / WINDOWS_TICKS_PER_SECOND) - WINDOWS_TO_UNIX_EPOCH;  
  return 0;
}


static void init_netmon_file_context(struct netmon_file_context *nfc)
{
  nfc->fp = NULL;
  nfc->num_off_avail = 0;
  nfc->frame_off_buf_index = 0;
  nfc->frame_table_off = 0;
  nfc->num_frames = 0;
  nfc->current_frame = 0;
  nfc->tspec_first.tv_sec = 0;
  nfc->tspec_first.tv_nsec = 0;
  nfc->mac_type = NETMON_MAC_TYPE_ETHERNET;
  nfc->version = 0;
}


static uint32_t get_next_frame_off(struct netmon_file_context *nfc)
{
  int ret;
  uint32_t offset;

  if (nfc->current_frame >= nfc->num_frames)
    return 0;

  if (nfc->num_off_avail == 0) {

    if (fseek(nfc->fp, nfc->frame_table_off, SEEK_SET) != 0) {
      fprintf(stderr, "netmon.c: get_next_frame_off(): fseek failed (off=%d)\n", 
	      nfc->frame_table_off);
      exit(1);
    }

    ret = fread(&nfc->frame_off_buf, sizeof(uint32_t), FRAME_OFF_BUFFER_SIZE,
		nfc->fp);
    nfc->num_off_avail = ret;
    nfc->frame_off_buf_index = 0;
    nfc->frame_table_off += sizeof(uint32_t) * ret;

    if (nfc->num_off_avail == 0)
      return 0;
  } 

  offset = nfc->frame_off_buf[nfc->frame_off_buf_index];

  nfc->num_off_avail -= 1;
  nfc->frame_off_buf_index += 1;
  nfc->current_frame += 1;

  return offset;
}


static int
pread_netmon_file(
    struct timespec	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
  struct netmon_frame_header frame_hdr;

  struct ip *iphdr;
  struct timespec rel_tspec_frame;
  uint64_t ts;
  int ret;
  uint32_t bytes_to_read;
  uint32_t trailer_offset;
  uint32_t offset;
  uint16_t mac_type;

  while (1) {

    offset = get_next_frame_off(&nfc);
    if (offset == 0)
      return 0;

    if (fseek(nfc.fp, offset, SEEK_SET) != 0) {
      fprintf(stderr, "netmon.c: pread_netmon_file(): fseek failed (off=%d)\n", 
	      offset);
      exit(1);
    }

    ret = fread(&frame_hdr, sizeof(struct netmon_frame_header), 1, nfc.fp);
    if (ret != 1) {
      if (!feof(nfc.fp))
	fprintf(stderr, "NetMon error: can't read frame header\n");
      return 0;
    }

    ts = convert_letoh64(&frame_hdr.ts);
    rel_tspec_frame.tv_sec = ts / 1000000;
    rel_tspec_frame.tv_nsec = (ts % 1000000) * 1000;

    ptime->tv_sec = nfc.tspec_first.tv_sec + rel_tspec_frame.tv_sec;
    ptime->tv_nsec = nfc.tspec_first.tv_nsec + rel_tspec_frame.tv_nsec;
    if (ptime->tv_nsec >= 1000000000) {
      ptime->tv_sec++;
      ptime->tv_nsec -= 1000000000;
    }

    bytes_to_read = convert_letoh32(&frame_hdr.num_bytes_avail);
    trailer_offset = bytes_to_read;

    mac_type = nfc.mac_type;

    if (nfc.version >= NETMON_VER_2_3) {
      bytes_to_read += sizeof(struct netmon_frame_trailer_2_3);
    } else if (nfc.version >= NETMON_VER_2_1) {
      bytes_to_read += sizeof(struct netmon_frame_trailer_2_1);
    }

    if (bytes_to_read > NETMON_MAX_PACKET_SIZE) {
      bytes_to_read = NETMON_MAX_PACKET_SIZE;
    }

    ret = fread(&nfc.packet_buf, bytes_to_read, 1, nfc.fp);
    if (ret != 1) {
      if (!feof(nfc.fp))
	fprintf(stderr, "NetMon error: can't read %d bytes of packet body\n", 
		bytes_to_read);
      return 0;
    }

    if (frame_hdr.frame_length >= NETMON_MIN_INVALID_FRAME_LENGTH) {
      if (debug > 2)
	fprintf(stderr, "pread_netmon: packet with invalid frame_length\n");
      continue;
    }

    if (nfc.version >= NETMON_VER_2_3) {

      struct netmon_frame_trailer_2_3 *pnft = (struct netmon_frame_trailer_2_3 *) &nfc.packet_buf[trailer_offset];
      struct timespec tspec;
      mac_type = convert_letoh16(&pnft->network);
      uint64_t ts = convert_letoh64(&pnft->utc_timestamp);
      convert_filetime_to_timespec(ts, &tspec);

      *ptime = tspec;

      if (debug > 2) {
	printf("pread_netmon: got mac_type=%d, ts_unix_reported=%ld.%09ld, rel_ts=%lld, ts=%llu\n", 
	       mac_type, ptime->tv_sec, ptime->tv_nsec, ts, frame_hdr.ts);
      }

    } else if (nfc.version >= NETMON_VER_2_1) {

      struct netmon_frame_trailer_2_1 *pnft = (struct netmon_frame_trailer_2_1 *) &nfc.packet_buf[trailer_offset];
      mac_type = convert_letoh16(&pnft->network);

      if (debug > 2) {
	fprintf(stderr,"pread_netmon: got mac_type=%d, ts_unix_reported=%ld.%09ld, rel_ts=%lld, ts=%llu\n", 
		mac_type, ptime->tv_sec, ptime->tv_nsec, ts, frame_hdr.ts);
      }
    }
    
    *pphystype = PHYS_NONE;

    if (mac_type == NETMON_MAC_TYPE_ZERO) {
      *pphystype = PHYS_ETHER;
      iphdr = find_ip_header_eth(nfc.packet_buf, frame_hdr.num_bytes_avail);
    } else if (mac_type == NETMON_MAC_TYPE_ETHERNET) {
      *pphystype = PHYS_ETHER;
      iphdr = find_ip_header_eth(nfc.packet_buf, frame_hdr.num_bytes_avail);
    } else if (mac_type == NETMON_MAC_TYPE_WIRELESS_WAN) {
      /* just a raw IP packet */
      iphdr = (struct ip *) &nfc.packet_buf;
    } else if (mac_type == NETMON_MAC_TYPE_DOT11) {
      *pphystype = PHYS_ETHER;
      iphdr = find_ip_header_netmon_dot11(nfc.packet_buf, frame_hdr.num_bytes_avail);	       
    } else {
      /* Whatever it is, we don't know it ... */
      iphdr = NULL;
    }

    if (!iphdr) {
      if (debug > 2)
	fprintf(stderr,"pread_netmon: not an IP packet\n");
      continue;
    }
    
    *pphys     = &nfc.packet_buf; /* everything assumed to be ethernet */
    
    *ppip      = iphdr;
    *pplast    = (void *) iphdr + frame_hdr.num_bytes_avail - 1; /* last byte in IP packet */
    *plen      = frame_hdr.frame_length;
    *ptlen     = frame_hdr.num_bytes_avail;

    return 1;
  }
}


pread_f *is_netmon_file(char *file_name)
{
  int ret;
  char *error_string = NULL;
  struct netmon_file_header nfh;
  struct tm tm_first;

  init_netmon_file_context(&nfc);

  nfc.fp = fopen(file_name, "rb");
  if (!nfc.fp) return NULL;

  ret = fread(&nfh, sizeof(struct netmon_file_header), 1, nfc.fp);
  if (ret != 1) {
    error_string = "error reading NetMon file header";
    goto exit_error_with_message;
  }

  if (nfh.signature[0] != 'G' 
      || nfh.signature[1] != 'M'
      || nfh.signature[2] != 'B'
      || nfh.signature[3] != 'U') {
    error_string = "Invalid NetMon signature";
    goto exit_error_with_message;
  }

  nfc.frame_table_off = convert_letoh32(&nfh.frame_table_offset);
  nfc.num_frames = convert_letoh32(&nfh.frame_table_length) / sizeof(uint32_t);
  nfc.mac_type = convert_letoh16(&nfh.mac_type);
  nfc.version = (nfh.bcd_ver_major << 8) + nfh.bcd_ver_minor;

  tm_first.tm_sec = convert_letoh16(&nfh.ts_second);
  tm_first.tm_min = convert_letoh16(&nfh.ts_minute);
  tm_first.tm_hour = convert_letoh16(&nfh.ts_hour);
  tm_first.tm_mday = convert_letoh16(&nfh.ts_day);
  tm_first.tm_mon = convert_letoh16(&nfh.ts_month) - 1;
  tm_first.tm_year = convert_letoh16(&nfh.ts_year) - 1900;
  tm_first.tm_isdst = -1;

  nfc.tspec_first.tv_sec = mktime(&tm_first);
  nfc.tspec_first.tv_nsec = convert_letoh16(&nfh.ts_millisecond) * 1000000;

  if (debug > 1) {

    printf("Reference timestamp: %02d:%02d:%02d.%03d, %04d-%02d-%02d, %d,%d,%d,tm=%d\n", 
	   tm_first.tm_hour,
	   tm_first.tm_min,
	   tm_first.tm_sec,
	   convert_letoh16(&nfh.ts_millisecond),
	   1900 + tm_first.tm_year,
	   tm_first.tm_mon,
	   tm_first.tm_mday,
	   tm_first.tm_wday,
	   tm_first.tm_yday,
	   tm_first.tm_isdst,
	   nfc.tspec_first.tv_sec);
    
    printf("Netmon signature: %c%c%c%c, version %d.%d\n",
	   nfh.signature[0],
	   nfh.signature[1],
	   nfh.signature[2],
	   nfh.signature[3],
	   nfh.bcd_ver_major,
	   nfh.bcd_ver_minor);

    printf("Mac-type: %d, frame_table_off: %d, frame_table_length: %d\n",
	   convert_letoh16(&nfh.mac_type),
	   convert_letoh32(&nfh.frame_table_offset),
	   convert_letoh32(&nfh.frame_table_length));
  }

  return pread_netmon_file;
  
 exit_error_with_message:
  if (debug > 2)
    fprintf(stderr,"NetMon said: '%s'\n", error_string);
  
 exit_error_close:
  fclose(nfc.fp);
  return NULL;
}


