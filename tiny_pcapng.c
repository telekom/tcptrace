#ifdef GROK_TINYPCAPNG

#include <math.h>
#include <pcap.h>
#include "tcptrace.h"
#include "tiny_pcap.h"
#include "tiny_pcapng.h"
#include "file_helpers.h"

static struct pcapng_file pf;

static struct ip *find_ip_header(uint8_t *packet_buf, 
				 size_t num_bytes,
				 uint16_t link_type,
				 int *pphystype)
{
  size_t offset;

  *pphystype = PHYS_NONE;

  switch (link_type) {

  case 100:
    /* for some reason, the windows version of tcpdump is using */
    /* this.  It looks just like ethernet to me */
  case PCAP_DLT_EN10MB:
    *pphystype = PHYS_ETHER;
    return find_ip_header_eth(packet_buf, num_bytes);
  case PCAP_DLT_NULL:
    offset = 4;
    break;
  case PCAP_DLT_ATM_RFC1483:
    offset = 8;
    break;
  case PCAP_DLT_RAW:
    offset = 0;
    break;
  case PCAP_DLT_RAW_NEW:
    offset = 0;
    break;
  case PCAP_DLT_LINUX_SLL:
    /* linux cooked socket */
    offset = 16;
    break;
  case PCAP_DLT_IEEE802_11:
    offset = 24 + 8; /* 802.11 header + LLC/SNAP header */
    break;
  case PCAP_DLT_IEEE802_11_RADIO:
    offset = 64 + 24; /* WLAN header + 802.11 header */
    break;
  case PCAP_DLT_C_HDLC:
    offset = 4;
    break;
  default:
    return NULL;
  }
  
  return (struct ip *) (packet_buf + offset);      
}


static uint16_t get_uint16(uint16_t val) {
  return val;
}

static uint32_t get_uint32(uint32_t val) {
  return val;
}

static uint16_t get_uint16_swapped(uint16_t val) {
  return ((val & 0xff00) >> 8) + ((val & 0xff) << 8);
}

static uint32_t get_uint32_swapped(uint32_t val) {
  return ((val & 0xff000000) >> 24)
    + ((val & 0xff0000) >> 8) 
    + ((val & 0xff00) << 8)
    + ((val & 0xff) << 24);
}


void init_pcapng_file(struct pcapng_file *pf)
{
  pf->fp = NULL;
  pf->get_uint16 = get_uint16;
  pf->get_uint32 = get_uint32;
  pf->num_interfaces = 0;
  pf->num_bytes = 0;
  pf->error_string[0] = 0;
}


static int
pcapng_parse_block_idb(struct pcapng_file *pf, 
		       void **pphys,
		       int *pphystype,
		       struct ip **ppip,
		       void **pplast,
		       struct timespec *ptime,
		       int *plen,
		       int *ptlen) {
  
  struct pcapng_idb *idb = (struct pcapng_idb *) pf->buf; 
  struct pcapng_option *poption = (struct pcapng_option *) ((void *) idb + sizeof(struct pcapng_idb));
  void *plast_option = (void *) idb + pf->get_uint32(idb->block_total_length) - 4;
  struct pcapng_interface *pinterface = &pf->interfaces[pf->num_interfaces];

  if (pf->num_interfaces >= PCAPNG_MAX_INTERFACES) {
    return 0;
  }

  pinterface->ts_resol = 0.000001;
  pinterface->link_type = pf->get_uint16(idb->link_type);
  pf->num_interfaces++;

  while ((void *) poption <= plast_option) {

    int code = pf->get_uint16(poption->option_code);
    int length = pf->get_uint16(poption->option_length);

    if ((void *) poption + length + 4 > plast_option) {
      break;
    }

    if (code == PCAPNG_OPTION_ENDOFOPT) {
      break;

    } else if (code == PCAPNG_OPTION_IDB_IF_TSRESOL && length == 1) {

      int8_t resol = *((int8_t *) poption + 4);
      
      if (resol >= 0) {
	pinterface->ts_resol = pow(10, -resol);
      } else {
	pinterface->ts_resol = pow(2, resol);
      }
    } 

    poption = (void *) poption + length + 4 + ((length & 0x3) == 0 ? 0 : 4 - length);

  }

  return 1;
}


static int pcapng_parse_block_epb(struct pcapng_file *pf, 
				  void **pphys,
				  int *pphystype,
				  struct ip **ppip,
				  void **pplast,
				  struct timespec *ptime,
				  int *plen,
				  int *ptlen) {

  struct pcapng_epb *epb = (struct pcapng_epb *) pf->buf; 
  unsigned int interface_id = pf->get_uint32(epb->interface_id);
  struct ip *iphdr;
  struct pcapng_interface *pinterface;
  uint8_t *packet_buf;

  if (interface_id >= pf->num_interfaces) {
    return 0;
  }
  pinterface = &pf->interfaces[interface_id];
  packet_buf = pf->buf + 28;

  int captured_length = pf->get_uint32(epb->captured_length);
  int packet_length = pf->get_uint32(epb->packet_length);
  if (captured_length > pf->num_bytes - 28 - 4) {
    return 0;
  }

  iphdr = find_ip_header(packet_buf, captured_length, pinterface->link_type, pphystype);
  if (!iphdr) {
    if (debug > 2)
      fprintf(stderr,"pread_pcapng: not an IP packet (link-layer type %d)\n", pinterface->link_type);
    return 0;
  }

  *pphys = (void *) packet_buf;

  /* last byte in IP packet */
  *pplast    = (void *) packet_buf + captured_length; 
  *ppip      = iphdr;

  long double ts = ((long double) pf->get_uint32(epb->ts_high) * 4294967296.0L 
		    + pf->get_uint32(epb->ts_low)) * pinterface->ts_resol;
  ptime->tv_sec = ts;
  ptime->tv_nsec = (ts - (long double) ptime->tv_sec) * 1000000000;

  *plen = packet_length;
  *ptlen = captured_length;

  if (debug > 2) {
    printf("  Enhanced packet block, interface_id=%d, ts=0x%x.%x (tv_sec=%d, tv_nsec=%d) %Lf, len=%d, cap_len=%d\n", 
	   interface_id, 
	   pf->get_uint32(epb->ts_high),
	   pf->get_uint32(epb->ts_low),
	   ptime->tv_sec,
	   ptime->tv_nsec,
	   ts,
	   packet_length,
	   captured_length);
  }
    
  return 1;
}


static int
pcapng_parse_block_spb(struct pcapng_file *pf, 
		       void **pphys,
		       int *pphystype,
		       struct ip **ppip,
		       void **pplast,
		       struct timespec *ptime,
		       int *plen,
		       int *ptlen) {

  struct pcapng_spb *spb = (struct pcapng_spb *) pf->buf; 

  return 1;
}


static int read_block(struct pcapng_file *pf, int need_section_header) {

    struct pcapng_block *block_header = (struct pcapng_block *) pf->buf;
    int ret;

    pf->num_bytes = 0;

    ret = fread(pf->buf, sizeof(struct pcapng_block), 1, pf->fp);
    if (ret != 1) {
      if (!feof(pf->fp)) {
	sprintf(pf->error_string, "pcapng: can't read block header");
      }
      return 0;
    }

    pf->num_bytes = sizeof(struct pcapng_block);

    if (block_header->block_type == PCAPNG_BLOCK_TYPE_SECTION_HEADER) {
      
      struct pcapng_section_header *sh = (struct pcapng_section_header *) &pf->buf;

      ret = fread(pf->buf + 8, 8, 1, pf->fp);
      if (ret != 1) {
	sprintf(pf->error_string, "pcapng: can't read section header");
	return 0;
      }

      pf->num_bytes += 8;

      if (debug > 2) {
	printf("pcapng SECTION_HEADER magic=0x%x\n", sh->block_order_magic);
      }
      
      if (sh->block_order_magic == PCAPNG_ORDER_MAGIC_SWAPPED) {
	pf->get_uint16 = get_uint16_swapped;
	pf->get_uint32 = get_uint32_swapped;
      } else if (sh->block_order_magic == PCAPNG_ORDER_MAGIC_NATIVE){
	pf->get_uint16 = get_uint16;
	pf->get_uint32 = get_uint32;
      } else {
	sprintf(pf->error_string, "pcapng: invalid byte-order magic 0x%ld", 
		sh->block_order_magic);
	return 0;
      }
    } else {

      if (debug > 2) {
	printf("pcapng BLOCK HEADER type=0x%x, length=%d\n", block_header->block_type, 
	       block_header->block_total_length);
      }

      if (need_section_header) {
	sprintf(pf->error_string, "pcapng: no section header found");
	return 0;
      }
    }

    int32_t block_length = (int32_t) pf->get_uint32(block_header->block_total_length);

    int bytes_remaining = block_length - pf->num_bytes;

    if (bytes_remaining > PCAPNG_MAX_BLOCK_SIZE) {
      sprintf(pf->error_string, "pcapng: block too large");
      return 0;
    }

    if (bytes_remaining > 0) {
      ret = fread(pf->buf + pf->num_bytes, bytes_remaining, 1, pf->fp);
      if (ret != 1) {
	sprintf(pf->error_string, "pcapng: can't read block");
	return 0;
      }
    }

    pf->num_bytes += bytes_remaining;

    return 1;
}


static int
pread_pcapng_file(
    struct timespec	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
  struct pcapng_block *block_header = (struct pcapng_block *) pf.buf;
  int ret;
  unsigned int bytes_to_read;
  struct ip *iphdr;

  while (1) {

    ret = read_block(&pf, FALSE);
    if (!ret) {
      break;
    }

    uint32_t block_type = pf.get_uint32(block_header->block_type);

    if (block_type == PCAPNG_BLOCK_TYPE_SECTION_HEADER) {
      continue;
    } else if (block_type == PCAPNG_BLOCK_TYPE_IDB) {
      ret = pcapng_parse_block_idb(&pf, pphys, pphystype, ppip, 
				   pplast, ptime, plen, ptlen);
      continue;
    } else if (block_type == PCAPNG_BLOCK_TYPE_SPB) {
      ret = pcapng_parse_block_spb(&pf, pphys, pphystype, ppip, 
				   pplast, ptime, plen, ptlen);   
      if (!ret) {
	continue;
      }
    } else if (block_type == PCAPNG_BLOCK_TYPE_EPB) {
      ret = pcapng_parse_block_epb(&pf, pphys, pphystype, ppip, 
				   pplast, ptime, plen, ptlen);      
      if (!ret) {
	continue;
      }
    } 
    break;
  }

  if (!ret) {
    if (strlen(&pf.error_string[0]) > 0) {
      fprintf(stderr, "%s", pf.error_string); 
    }
  }

  return ret;
}


pread_f *is_pcapng_file(char *file_name)
{
  int ret;
  char *phystype = NULL;
  char *physname = NULL;
  struct pcapng_section_header section_header;

  init_pcapng_file(&pf);

  pf.fp = fopen(file_name, "rb");
  if (!pf.fp) return NULL;

  if (!read_block(&pf, TRUE)) {
    goto exit_error_with_message;
  }

  if (debug) {
    printf("Using pcapng\n");
    if (debug > 1) {
      
    }
  }

  return pread_pcapng_file;
  
 exit_error_with_message:
  if (debug > 1)
    fprintf(stderr,"tiny_pcapng.c said: '%s'\n", pf.error_string);
  
 exit_error_close:
  fclose(pf.fp);
  return NULL;
}


#endif 
