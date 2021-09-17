#ifdef GROK_TINYPCAP

#include "tcptrace.h"
#include "tiny_pcap.h"
#include "file_helpers.h"

static struct pcap_file pf;

void init_pcap_file(struct pcap_file *pf)
{
  pf->fp = NULL;
  pf->is_swapped = 0;
  pf->is_nano_second = 0;
}


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
  case PCAP_DLT_RAW_NEW:
    offset = 0;
    break;
  case PCAP_DLT_LINUX_SLL: /* linux cooked socket */
    return find_ip_header_sll(packet_buf, num_bytes);
  case PCAP_DLT_LINUX_SLL2: /* linux cooked socket */
    return find_ip_header_sll2(packet_buf, num_bytes);
  case PCAP_DLT_IEEE802_11:
    offset = 24 + 8; /* 802.11 header + LLC/SNAP header */
    break;
  case PCAP_DLT_IEEE802_11_RADIO:
    offset = 64 + 24; /* WLAN header + 802.11 header */
    break;
  case PCAP_DLT_C_HDLC:
    offset = 4;
    break;
  case PCAP_DLT_ERF:
    return find_ip_header_erf(packet_buf, num_bytes);    
    break;
  default:
    fprintf(stderr,"TINY_PCAP: I don't understand link-level format (%d)\n", link_type);
    exit(1);
  }
  
  return (struct ip *) (packet_buf + offset);      
}


static int
pread_pcap_file(
    struct timespec	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
  struct tiny_pcap_pkthdr pkthdr;
  uint32_t nano_seconds;
  int ret;
  unsigned int bytes_to_read;
  struct ip *iphdr;

  while (1) {

    ret = fread(&pkthdr, sizeof(pkthdr), 1, pf.fp);
    if (ret != 1) {
      if (!feof(pf.fp))
	fprintf(stderr, "TINY_PCAP error: can't read packet header");
      return 0;
    }
    
    if (pf.is_swapped) {
      pkthdr.tv_sec = SWAPLONG(pkthdr.tv_sec);
      pkthdr.tv_usec = SWAPLONG(pkthdr.tv_usec);
      pkthdr.caplen = SWAPLONG(pkthdr.caplen);
      pkthdr.len = SWAPLONG(pkthdr.len);
    }
    
    nano_seconds = pkthdr.tv_usec;
    if (!pf.is_nano_second)
      nano_seconds *= 1000;

    bytes_to_read = pkthdr.caplen;
    if (bytes_to_read > PCAP_MAX_PACKET_SIZE)
      bytes_to_read = PCAP_MAX_PACKET_SIZE;
    
    ret = fread(&pf.packet_buf, bytes_to_read, 1, pf.fp);
    if (ret != 1) {
      if (!feof(pf.fp))
	fprintf(stderr, "TINY_PCAP error: can't read packet body");
      return 0;
    }

    iphdr = find_ip_header(pf.packet_buf, bytes_to_read, pf.pcap_header.linktype, pphystype);
    if (!iphdr) {
      if (debug > 2)
	fprintf(stderr,"pread_tcpdump: not an IP packet\n");
      continue;
    }
    
    *pphys     = &pf.packet_buf; /* everything assumed to be ethernet */

    *ppip      = iphdr;
    *pplast    = (void *) iphdr + pkthdr.caplen - 1; /* last byte in IP packet */
    
    ptime->tv_nsec = nano_seconds;
    ptime->tv_sec = pkthdr.tv_sec;
    
    *plen      = pkthdr.len;
    *ptlen     = pkthdr.caplen;

    return 1;
  }
}


pread_f *is_pcap_file(char *file_name)
{
  int ret;
  char *error_string = NULL;
  char *phystype = NULL;
  char *physname = NULL;

  init_pcap_file(&pf);

  pf.fp = fopen(file_name, "rb");
  if (!pf.fp) return NULL;

  ret = fread(&pf.pcap_header, sizeof(pf.pcap_header), 1, pf.fp);
  if (ret != 1) {
    error_string = "error reading libpcap header";
    goto exit_error_with_message;
  }

  if (pf.pcap_header.magic == PCAP_MAGIC_NATIVE) {
    pf.is_swapped = 0;
    pf.is_nano_second = 0;
  } else if (pf.pcap_header.magic == PCAP_MAGIC_NATIVE_NANO) {
    pf.is_swapped = 0;
    pf.is_nano_second = 1;
  } else if (pf.pcap_header.magic == PCAP_MAGIC_SWAPPED) {
    pf.is_swapped = 1;
    pf.is_nano_second = 0;
  } else if (pf.pcap_header.magic == PCAP_MAGIC_SWAPPED_NANO) {
    pf.is_swapped = 1;
    pf.is_nano_second = 1;    
  } else {
    error_string = "invalid magic value in libpcap header";
    goto exit_error_with_message;
  }

  if (pf.is_swapped) {
    pf.pcap_header.version_major = SWAPSHORT(pf.pcap_header.version_major);
    pf.pcap_header.version_minor = SWAPSHORT(pf.pcap_header.version_minor);
    pf.pcap_header.snaplen = SWAPLONG(pf.pcap_header.snaplen);
    pf.pcap_header.linktype = SWAPLONG(pf.pcap_header.linktype);
  }

  if (debug) {
    printf("Using 'pcap' version of tcpdump\n");
    if (debug > 1) {
      printf("\tversion_major: %d\n", pf.pcap_header.version_major);
      printf("\tversion_minor: %d\n", pf.pcap_header.version_minor);
      printf("\tsnaplen: %d\n", pf.pcap_header.snaplen);
      printf("\tlinktype: %d\n", pf.pcap_header.linktype);
      printf("\tswapped: %d\n", pf.is_swapped);
      printf("\thas_nanosecond_format: %d\n", pf.is_nano_second);
    }
  }

  switch (pf.pcap_header.linktype) {
  case 100:
  case PCAP_DLT_EN10MB:
    /* OK, we understand this one */
    physname = "Ethernet";
    break;
  case PCAP_DLT_NULL:
    physname = "NULL";
    break;
  case PCAP_DLT_ATM_RFC1483:
    physname = "ATM, LLC/SNAP encapsulated";
    break;
  case PCAP_DLT_RAW:
  case PCAP_DLT_RAW_NEW:
    physname = "RAW_IP";
    break;
  case PCAP_DLT_LINUX_SLL:
    /* linux cooked-mode capture */
    physname = "Linux cooked-mode capture";
    break;
  case PCAP_DLT_LINUX_SLL2:
    physname = "Linux cooked capture v2";
    break;
  case PCAP_DLT_IEEE802_11:
    physname = "IEEE802_11";
    break;
  case PCAP_DLT_IEEE802_11_RADIO:
    physname = "IEEE802_11_RADIO";
    break;
  case PCAP_DLT_C_HDLC:
    physname = "Cisco HDLC";
    break;
  case PCAP_DLT_ERF:
    physname = "ERF";
    break;
  default:
    fprintf(stderr,"TINY_PCAP did not understand link format (%d)!\n",
	    pf.pcap_header.linktype);
    return NULL;
  }

  if (debug)
    fprintf(stderr,"Tcpdump format, physical type is %d (%s)\n",
	    pf.pcap_header.linktype, physname);

  return pread_pcap_file;
  
 exit_error_with_message:
  if (debug > 2)
    fprintf(stderr,"TinyPcap said: '%s'\n", error_string);
  
 exit_error_close:
  fclose(pf.fp);
  return NULL;
}

#endif 
