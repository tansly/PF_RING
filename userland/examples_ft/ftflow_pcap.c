/*
 * (C) 2018-19 - ntop.org
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <arpa/inet.h>
#include <getopt.h>

#include "pfring_ft.h"

#include "ftutils.c"

#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256

pcap_t *pd = NULL;
pfring_ft_table *ft = NULL;
u_int8_t quiet = 0, verbose = 0, do_shutdown = 0, enable_l7 = 0, enable_p4 = 0;
const char *p4rt = NULL, *bmv2_json = NULL;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth1"

int pcap_set_application_name(pcap_t *handle, char *name);
char *pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);
int pfring_print_pkt(char *buff, u_int buff_len, const u_char *p, u_int len, u_int caplen);

/* *************************************** */

void print_stats() {
  struct pcap_stat pcapStat;
  pfring_ft_stats *fstat; 
  struct timeval endTime;
  float deltaSec;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;
  char buf1[64], buf2[64];

  if (startTime.tv_sec == 0) {
    lastTime.tv_sec = 0;
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaSec = (double)delta_time(&endTime, &startTime)/1000000;

  if (pcap_stats(pd, &pcapStat) >= 0 && (fstat = pfring_ft_get_stats(ft))) {
    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped][%ju flows][%ju errors]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    pcapStat.ps_recv, pcapStat.ps_drop, 
            fstat->flows,
            fstat->err_no_room + fstat->err_no_mem,
            pcapStat.ps_recv-pcapStat.ps_drop,
	    pcapStat.ps_recv == 0 ? 0 : (double)(pcapStat.ps_drop*100)/(double)pcapStat.ps_recv);
    fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	    numPkts, (double)numPkts/deltaSec,
	    numBytes, (double)8*numBytes/(double)(deltaSec*1000000));

    if (lastTime.tv_sec > 0) {
      deltaSec = (double)delta_time(&endTime, &lastTime)/1000000;
      diff = numPkts-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %ju flows %s pkts [%.1f ms][%s pkt/sec]\n",
              fstat->active_flows,
	      pfring_format_numbers(diff, buf1, sizeof(buf1), 0), deltaSec*1000,
	      pfring_format_numbers(((double)diff/(double)(deltaSec)), buf2, sizeof(buf2), 1));
      lastPkts = numPkts;
    }

    fprintf(stderr, "=========================\n");
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;

  pcap_breakloop(pd);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

void processFlow(pfring_ft_flow *flow, void *user){
  pfring_ft_flow_key *k;
  pfring_ft_flow_value *v;
  char buf1[32], buf2[32], buf3[32];
  char *ip1, *ip2;

  k = pfring_ft_flow_get_key(flow);
  v = pfring_ft_flow_get_value(flow);

  if (k->ip_version == 4){
    ip1 = _intoa(k->saddr.v4, buf1, sizeof(buf1));
    ip2 = _intoa(k->daddr.v4, buf2, sizeof(buf2));
  } else {
    ip1 = (char *) inet_ntop(AF_INET6, &k->saddr.v6, buf1, sizeof(buf1));
    ip2 = (char *) inet_ntop(AF_INET6, &k->daddr.v6, buf2, sizeof(buf2));
  }

  printf("[Flow] ");

  if(enable_l7)
    printf("l7: %s, category: %u, ",
	   pfring_ft_l7_protocol_name(ft, &v->l7_protocol, buf3, sizeof(buf3)), v->l7_protocol.category);
  
  printf("srcIp: %s, dstIp: %s, srcPort: %u, dstPort: %u, protocol: %u, tcpFlags: 0x%02X, "
         "c2s: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
         "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }\n",
         ip1, ip2, k->sport, k->dport, k->protocol, v->direction[s2d_direction].tcp_flags | v->direction[d2s_direction].tcp_flags,         
         v->direction[s2d_direction].pkts, v->direction[s2d_direction].bytes, 
         (u_int) v->direction[s2d_direction].first.tv_sec, (u_int) v->direction[s2d_direction].first.tv_usec, 
         (u_int) v->direction[s2d_direction].last.tv_sec,  (u_int) v->direction[s2d_direction].last.tv_usec,
         v->direction[d2s_direction].pkts, v->direction[d2s_direction].bytes, 
         (u_int) v->direction[d2s_direction].first.tv_sec, (u_int) v->direction[d2s_direction].first.tv_usec, 
         (u_int) v->direction[d2s_direction].last.tv_sec,  (u_int) v->direction[d2s_direction].last.tv_usec);

  pfring_ft_flow_free(flow);
}

void proto_detected(const u_char *data, pfring_ft_packet_metadata *metadata,
        pfring_ft_flow *flow, void *user)
{
  char proto_name[32];
  pfring_ft_flow_key *flow_key = pfring_ft_flow_get_key(flow);
  pfring_ft_flow_value *flow_value = pfring_ft_flow_get_value(flow);

  printf("l7: %s, category: %u\n",
      pfring_ft_l7_protocol_name(ft, &flow_value->l7_protocol, proto_name,
        sizeof proto_name), flow_value->l7_protocol.category);

  /*
   * Instead of dealing with P4 runtime C, I will call our good old Python scripts here.
   * IMO this will be good enough for a PoC. We may later port it here if we think it would
   * provide any benefit.
   *
   * TODO: Actually check if the protocol is blocked.
   */
  pid_t pid = fork();
  if (pid == -1) {
    perror("proto_detected() fork() error");
    return;
  } else if (pid == 0) {
    char buf1[32], buf2[32];
    char *ip1, *ip2;
    if (flow_key->ip_version == 4) {
      ip1 = _intoa(flow_key->saddr.v4, buf1, sizeof(buf1));
      ip2 = _intoa(flow_key->daddr.v4, buf2, sizeof(buf2));
      execl("./blocklist_add.py", "./blocklist_add.py", bmv2_json, p4rt,
          ip1, ip2, NULL);
      /*
       * exec failed.
       */
      perror("proto_detected() exec() error");
      exit(EXIT_FAILURE);
    } else {
      /*
       * XXX: Will we support IPv6?
       */
      fputs("Got IPv6?", stderr);
      exit(EXIT_SUCCESS);
    }
  } else /* parent */ {
    /*
     * TODO: Wait for the child.
     * Or set SIGCHLD handler to ignore it.
     * If the child errors, there is nothing we can do anyway.
     */
  }
}

/* ****************************************************** */

void process_packet(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p) {
  pfring_ft_ext_pkthdr ext_hdr = { 0 };
  pfring_ft_action action;

  action = pfring_ft_process(ft, p, (pfring_ft_pcap_pkthdr *) h, &ext_hdr);

  if (verbose) {
    char buffer[256];
    buffer[0] = '\0';
    pfring_print_pkt(buffer, sizeof(buffer), p, h->len, h->caplen);
    printf("[Packet]%s %s", action == PFRING_FT_ACTION_DISCARD ? " [discard]" : "", buffer);
  }
}

/* *************************************** */

void print_help(void) {
  printf("ftflow_pcap - (C) 2018-19 ntop.org\n");
  printf("-h              Print help\n");
  printf("-i <device>     Device name or PCAP file\n");
  printf("-7              Enable L7 protocol detection (nDPI)\n");
  printf("-p <file>       Load nDPI custom protocols from file\n");
  printf("-c <file>       Load nDPI categories by host from file\n");
  printf("-f <filter>     BPF filter\n");
  printf("-q              Quiet mode\n");
  printf("-v              Verbose\n");

  printf("\nFor nDPI categories see for instance\n"
	 "https://github.com/ntop/nDPI/blob/dev/example/mining_hosts.txt\n");

}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, *bpfFilter = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *protocols_file = NULL;
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  u_int32_t ft_flags = 0;
  char *categories_file = NULL;
  int rc; 
 
  startTime.tv_sec = 0;

  static struct option long_opts[] = {
    {"p4rt", required_argument, NULL, 'r'},
    {"bmv2-json", required_argument, NULL, 'j'},
    {"block", required_argument, NULL, 'b'}
  };
  int option_index = 0;
  int c;

  while ((c = getopt_long(argc, argv, "c:hi:vf:p:q7r:j:b:",
          long_opts, &option_index)) != '?' && c != -1) {

    switch(c) {
    case 'j':
      // BMv2 JSON file
      enable_p4 = 1;
      bmv2_json = optarg;
      break;
    case 'r':
      // P4 runtime file
      enable_p4 = 1;
      p4rt = optarg;
      break;
    case 'b':
      // nDPI protocol to be blocked in P4
      enable_p4 = 1;
      // TODO: Parse and store the protocol
    case 'c':
      categories_file = strdup(optarg);
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'p':
      enable_l7 = 1;
      protocols_file = strdup(optarg);
      break;
    case 'q':
      quiet = 1;
      break;
    case 'f':
      bpfFilter = strdup(optarg);
      break;
    case '7':
      enable_l7 = 1;
      break;
    }
  }

  if (device == NULL) {
    if ((device = pcap_lookupdev(errbuf)) == NULL) {
      printf("pcap_lookup: %s", errbuf);
      return -1;
    }
  }

  if (enable_l7)
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;

  ft = pfring_ft_create_table(ft_flags, 0, 0, 0);

  if (ft == NULL) {
    fprintf(stderr, "pfring_ft_create_table error\n");
    return -1;
  }

  pfring_ft_set_flow_export_callback(ft, processFlow, NULL);

  if (enable_p4) {
    if (!enable_l7) {
      fputs("P4 control should be enabled together with nDPI (-7)\n", stderr);
      return -1;
    }
    if (!p4rt || !bmv2_json) {
      fputs("--p4rt and --bmv2-json are mandatory for P4 usage\n", stderr);
      return -1;
    }

    pfring_ft_set_l7_detected_callback(ft, proto_detected, NULL);
    pid_t pid = fork();
    if (pid == -1) {
      /*
       * fork failed.
       */
      perror("main() fork() error");
      exit(EXIT_FAILURE);
    } else if (pid == 0) {
      execl("./set_pipeline_conf.py", "./set_pipeline_conf.py", bmv2_json, p4rt, NULL);
      /*
       * exec failed.
       */
      perror("main() exec() error");
      exit(EXIT_FAILURE);
    } else /* parent */ {
      int wstatus;
      pid_t w;
      do {
        w = waitpid(pid, &wstatus, 0);
        if (w == -1) {
          if (errno == EINTR) {
            continue;
          }
          perror("main() waitpid() error");
          exit(EXIT_FAILURE);
        }

        if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0) {
          fprintf(stderr, "main() error: Child exited with %d\n", WEXITSTATUS(wstatus));
          exit(EXIT_FAILURE);
        } else if (WIFSIGNALED(wstatus)) {
          fprintf(stderr, "main() error: Child killed by signal %d\n", WTERMSIG(wstatus));
          exit(EXIT_FAILURE);
        }
      } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));
    }
  }

  if (protocols_file) {
    rc = pfring_ft_load_ndpi_protocols(ft, protocols_file);

    if (rc < 0) {
      fprintf(stderr, "Failure loading custom protocols from %s\n", protocols_file);
      return -1;
    }
  }

  if (categories_file) {
    if (!enable_l7) {
      fprintf(stderr, "Categories detection require L7 detection "
	      "(please use -c in combination with -7)\n");
      return -1;
    }

    if(pfring_ft_load_ndpi_categories(ft, categories_file) < 0) {
      fprintf(stderr, "Failure loading categories from %s\n", categories_file);
      return -1;
    }
  }
    
  promisc = 1;

  if ((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
    if ((pd = pcap_open_offline(device, errbuf)) == NULL) {
      printf("pcap_open error: %s\n", errbuf);
      return -1;
    }
  }

  if (bpfFilter != NULL) {
    if (pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
    } else {
      if (pcap_setfilter(pd, &fcode) < 0) {
        printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
      }
    }
  }
  
  if (!quiet) {
    printf("Capturing from %s %s nDPI support\n", device, enable_l7 ? "with" : "without (see -7)");    
  }

  pcap_set_application_name(pd, "ftflow_pcap");

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if (!verbose && !quiet) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pcap_loop(pd, -1, process_packet, NULL);

  pcap_close(pd);

  pfring_ft_flush(ft);

  pfring_ft_destroy_table(ft);

  return 0;
}
