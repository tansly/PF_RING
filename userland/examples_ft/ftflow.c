/*
 * (C) 2018-19 - ntop
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
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>
#include <getopt.h>

#include "pfring.h"
#include "pfring_ft.h"

#include "bstree.h"

#include "ftutils.c"

#define ALARM_SLEEP 1
#define DEFAULT_DEVICE "eth0"

pfring *pd = NULL;
pfring_ft_table *ft = NULL;
int bind_core = -1;
int bind_time_pulse_core = -1;
u_int8_t quiet = 0, verbose = 0, time_pulse = 0, enable_l7 = 0, enable_p4 = 0, do_shutdown = 0;
u_int64_t num_pkts = 0;
u_int64_t num_bytes = 0;
const char *p4rt = NULL, *bmv2_json = NULL;
struct bstree *blocked_protocols = NULL;

volatile u_int64_t *pulse_timestamp;

/* ************************************ */

void *time_pulse_thread(void *data) {
  struct timespec tn;

  if (bind_time_pulse_core >= 0)
    bind2core(bind_time_pulse_core);

  while (likely(!do_shutdown)) {
    clock_gettime(CLOCK_REALTIME, &tn);
    *pulse_timestamp = ((u_int64_t) ((u_int64_t) tn.tv_sec << 32) | (tn.tv_nsec/1000));
    usleep(1);
  }

  return NULL;
}

/* ************************************ */

void print_stats() {
  pfring_stat stat;
  pfring_ft_stats *fstat;
  static struct timeval start_time = { 0 };
  static struct timeval last_time = { 0 };
  struct timeval end_time;
  unsigned long long n_bytes, n_pkts;
  static u_int64_t last_pkts = 0;
  static u_int64_t last_bytes = 0;
  double diff, bytes_diff;
  u_int64_t delta_start;
  double delta_last;
  char buf[256], buf1[64], buf2[64], timebuf[128];

  if (start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);
  gettimeofday(&end_time, NULL);

  n_bytes = num_bytes;
  n_pkts = num_pkts;

  if (pfring_stats(pd, &stat) >= 0 && (fstat = pfring_ft_get_stats(ft))) {
    if (last_time.tv_sec > 0) {
      delta_start = delta_time(&end_time, &start_time);
      delta_last = delta_time(&end_time, &last_time);
      diff = n_pkts - last_pkts;
      bytes_diff = n_bytes - last_bytes;
      bytes_diff /= (1000*1000*1000)/8;

      snprintf(buf, sizeof(buf),
             "Duration:   %s\n"
             "ActFlows:   %ju\n"
             "TotFlows:   %ju\n"
             "Errors:     %ju\n"
             "Packets:    %lu\n"
             "Dropped:    %lu\n"
             "Bytes:      %lu\n"
             "Throughput: %s pps (%s Gbps)",
             msec2dhmsm(delta_start, timebuf, sizeof(timebuf)),
             fstat->active_flows,
             fstat->flows,
             fstat->err_no_room + fstat->err_no_mem,
             (long unsigned int) n_pkts,
             (long unsigned int) stat.drop,
             (long unsigned int) n_bytes,
	     pfring_format_numbers(((double) diff/(double)(delta_last/1000)),  buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double) bytes_diff/(double)(delta_last/1000)),  buf2, sizeof(buf2), 1));

      pfring_set_application_stats(pd, buf);
    }
  }

  last_pkts = n_pkts;
  last_bytes = n_bytes;
  memcpy(&last_time, &end_time, sizeof(last_time));
}

/* ************************************ */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;

  pfring_breakloop(pd);
}

/* ************************************ */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

/* This callback is called after a packet has been processed
void processFlowPacket(const u_char *data, pfring_ft_packet_metadata *metadata,
		       pfring_ft_flow *flow, void *user) {
  //fprintf(stderr, "Processing packet [payloadLen: %u]\n", metadata->payload_len);

  // Marking the flow to discard all packets (this can be used to implement custom filtering policies)
  // pfring_ft_flow_set_action(flow, PFRING_FT_ACTION_DISCARD);
}
*/

/* ******************************** */

const char *action_to_string(pfring_ft_action action) {
  switch (action) {
    case PFRING_FT_ACTION_FORWARD: return "forward";
    case PFRING_FT_ACTION_DISCARD: return "discard";
    case PFRING_FT_ACTION_DEFAULT: return "default";
  }
  return "";
}

/* ******************************** */

/* This callback is called when a flow expires */
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
         "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, action: %s\n",
         ip1, ip2, k->sport, k->dport, k->protocol, v->direction[s2d_direction].tcp_flags | v->direction[d2s_direction].tcp_flags,
         v->direction[s2d_direction].pkts, v->direction[s2d_direction].bytes,
         (u_int) v->direction[s2d_direction].first.tv_sec, (u_int) v->direction[s2d_direction].first.tv_usec,
         (u_int) v->direction[s2d_direction].last.tv_sec,  (u_int) v->direction[s2d_direction].last.tv_usec,
         v->direction[d2s_direction].pkts, v->direction[d2s_direction].bytes,
         (u_int) v->direction[d2s_direction].first.tv_sec, (u_int) v->direction[d2s_direction].first.tv_usec,
         (u_int) v->direction[d2s_direction].last.tv_sec,  (u_int) v->direction[d2s_direction].last.tv_usec,
         action_to_string(pfring_ft_flow_get_action(flow)));

  pfring_ft_flow_free(flow);
}

int compare_proto_names(const void *lhs, const void *rhs)
{
  return strcasecmp(lhs, rhs);
}

void proto_detected(const u_char *data, pfring_ft_packet_metadata *metadata,
        pfring_ft_flow *flow, void *user)
{
  char proto_name[32];
  pfring_ft_flow_key *flow_key = pfring_ft_flow_get_key(flow);
  pfring_ft_flow_value *flow_value = pfring_ft_flow_get_value(flow);

  printf("Detected: %s\n",
      pfring_ft_l7_protocol_name(ft, &flow_value->l7_protocol, proto_name,
        sizeof proto_name));

  /*
   * proto_name given by nDPI may be of the form "master.app".
   * We will block a flow if the user has selected either the master or app.
   * The user may have also specified the full protocol as "master.app",
   * so we check for that as well.
   *
   * TODO: Refactor this into something reasonable.
   */
  char *separator = NULL;
  if (!(bstree_search(blocked_protocols, proto_name) ||
        ((separator = strchr(proto_name, '.')) && (*separator = '\0',
          bstree_search(blocked_protocols, proto_name) ||
          bstree_search(blocked_protocols, separator + 1))))) {
    // hmm
    return;
  }
  if (separator) {
    *separator = '.';
  }

  /*
   * Instead of dealing with P4 runtime C, I will call our good old Python scripts here.
   * IMO this will be good enough for a PoC. We may later port it here if we think it would
   * provide any benefit.
   */
  pid_t pid = fork();
  if (pid == -1) {
    perror("proto_detected() fork() error");
    return;
  } else if (pid == 0) {
    char saddr_buf[32], daddr_buf[32];
    char *saddr, *daddr;
    char sport_buf[6], dport_buf[6]; // 16-bit uint -> 5 chars + NUL
    if (flow_key->ip_version == 4) {
      saddr = _intoa(flow_key->saddr.v4, saddr_buf, sizeof(saddr_buf));
      daddr = _intoa(flow_key->daddr.v4, daddr_buf, sizeof(daddr_buf));

      if (flow_key->protocol == IPPROTO_TCP || flow_key->protocol == IPPROTO_UDP) {
        int slen = snprintf(sport_buf, sizeof sport_buf, "%u", flow_key->sport);
        int dlen = snprintf(dport_buf, sizeof dport_buf, "%u", flow_key->dport);

        /*
         * These checks are unnecessary because the buffer sizes are sufficient.
         * Still, I'm adding these just in case I screwed up with my calculations.
         */
        if (slen > sizeof sport_buf) {
#ifndef NDEBUG
          fprintf(stderr, "WARN_DEBUG: snprintf(sport) returned %d\n", slen);
#endif
        }
        if (dlen > sizeof dport_buf) {
#ifndef NDEBUG
          fprintf(stderr, "WARN_DEBUG: snprintf(dport) returned %d\n", dlen);
#endif
        }
      }

      /*
       * TODO: Add entries for both directions or find a way to make a
       * bidirectional check in P4 code.
       */
  printf("Blocking %s: srcIp: %s, dstIp: %s, srcPort: %u, dstPort: %u, protocol: %u, "
         "c2s: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
         "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }\n",
         proto_name, saddr, daddr, flow_key->sport, flow_key->dport, flow_key->protocol,
         flow_value->direction[s2d_direction].pkts, flow_value->direction[s2d_direction].bytes,
         (u_int) flow_value->direction[s2d_direction].first.tv_sec, (u_int) flow_value->direction[s2d_direction].first.tv_usec,
         (u_int) flow_value->direction[s2d_direction].last.tv_sec,  (u_int) flow_value->direction[s2d_direction].last.tv_usec,
         flow_value->direction[d2s_direction].pkts, flow_value->direction[d2s_direction].bytes,
         (u_int) flow_value->direction[d2s_direction].first.tv_sec, (u_int) flow_value->direction[d2s_direction].first.tv_usec,
         (u_int) flow_value->direction[d2s_direction].last.tv_sec,  (u_int) flow_value->direction[d2s_direction].last.tv_usec);
      if (flow_key->protocol == IPPROTO_TCP) {
        execl("./blocklist_add.py", "./blocklist_add.py", bmv2_json, p4rt, "TCP",
          saddr, sport_buf, daddr, dport_buf, NULL);
      } else if (flow_key->protocol == IPPROTO_UDP) {
        execl("./blocklist_add.py", "./blocklist_add.py", bmv2_json, p4rt, "UDP",
          saddr, sport_buf, daddr, dport_buf, NULL);
      } else if (flow_key->protocol == IPPROTO_ICMP) {
        execl("./blocklist_add.py", "./blocklist_add.py", bmv2_json, p4rt, "ICMP",
          saddr, daddr, NULL);
      } else {
        fprintf(stderr, "Unsupported protocol: %u\n", flow_key->protocol);
        exit(EXIT_FAILURE);
      }

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

/* ******************************** */

void process_packet(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) {
  pfring_ft_pcap_pkthdr *hdr = (pfring_ft_pcap_pkthdr *) h;
  pfring_ft_ext_pkthdr ext_hdr;
  u_int64_t ts;
  pfring_ft_action action;

  ext_hdr.hash = h->extended_hdr.pkt_hash;

  if (time_pulse) {
    ts = *pulse_timestamp;
    hdr->ts.tv_sec = ts >> 32;
    hdr->ts.tv_usec = (ts << 32) >> 32;
  }

  action = pfring_ft_process(ft, p, hdr, &ext_hdr);

  num_pkts++;
  num_bytes += h->len + 24;

  if (verbose) {
    char buffer[256];
    buffer[0] = '\0';
    pfring_print_pkt(buffer, sizeof(buffer), p, h->len, h->caplen);
    printf("[Packet][%s] %s", action_to_string(action), buffer);
  }
}

/* ******************************** */

void packet_consumer() {
  struct pfring_pkthdr hdr;
  u_char *buffer_p = NULL;

  memset(&hdr, 0, sizeof(hdr));

  while (!do_shutdown) {
    if (pfring_recv(pd, &buffer_p, 0, &hdr, 0) > 0) {
      process_packet(&hdr, buffer_p, NULL);
    } else {
      if (!pfring_ft_housekeeping(ft, time(NULL))) {
        usleep(1);
      }
    }
  }
}

/* *************************************** */

void print_version(void) {
  char version[32], system_id[32];
  time_t license_expiration, maintenance_expiration;
  int rc;
  
  pfring_ft_version(version);
 
  printf("PF_RING FT v.%s\n" 
         "Copyright 2018-19 ntop.org\n",
         version);
      
  rc = pfring_ft_license(system_id, &license_expiration, &maintenance_expiration);

  printf("SystemID:      %s\n", system_id);
              
  if (!rc) {
    printf("License:       Invalid license\n");
  } else {
    printf("License:       Valid license\n");  

    if (license_expiration) {
      printf("License Type:  Time-limited License \n");
      printf("Lic. Duration: Until %s [%u days left]\n", ctime_nonl(license_expiration), days_left(license_expiration));
    } else if (maintenance_expiration > 0) {
      printf("License Type:  Permanent License \n");
      if (days_left(maintenance_expiration) <= 0)
        printf("Maintenance:   Expired\n");
      else
        printf("Maintenance:   Until %s [%u days left]\n", ctime_nonl(maintenance_expiration), days_left(maintenance_expiration));
    }
  } 
}

/* *************************************** */

/*
 * TODO: Update the help text to include P4 related arguments.
 */
void print_help(void) {
  printf("ftflow - (C) 2018-19 ntop.org\n");
  printf("Flow processing based on PF_RING FT (Flow Table)\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name\n");
  printf("-7              Enable L7 protocol detection (nDPI)\n");
  printf("-F <file>       Load filtering/shunting rules from file\n");
  printf("-p <file>       Load nDPI custom protocols from file\n");
  printf("-c <file>       Load nDPI categories by host from file\n");
  printf("-g <core>       CPU core affinity\n");
  printf("-S <core>       Enable timer thread and set CPU core affinity\n");
  printf("-q              Quiet mode\n");
  printf("-d              Debug mode\n");
  printf("-v              Verbose (print also raw packets)\n");
  printf("-V              Print version");

  printf("\nFor nDPI categories see for instance\n"
	 "https://github.com/ntop/nDPI/blob/dev/example/mining_hosts.txt\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL;
  char *configuration_file = NULL;
  char *categories_file = NULL;
  char *protocols_file = NULL;
  int promisc, snaplen = 1518, rc;
  u_int32_t flags = 0, ft_flags = 0;
  packet_direction direction = rx_and_tx_direction;
  pthread_t time_thread;

  static struct option long_opts[] = {
    {"p4rt", required_argument, NULL, 'r'},
    {"bmv2-json", required_argument, NULL, 'j'},
    {"block", required_argument, NULL, 'b'}
  };
  int option_index = 0;
  int c;

  while ((c = getopt_long(argc, argv, "c:dg:hi:p:qvF:S:V7r:j:b:",
          long_opts, &option_index)) != '?' && c != -1) {

    switch(c) {
    case 'j':
      /* Specifies the BMv2 JSON file */
      enable_p4 = 1;
      bmv2_json = optarg;
      break;
    case 'r':
      /* Specifies the P4 runtime file */
      enable_p4 = 1;
      p4rt = optarg;
      break;
    case 'b':
      /* Specifies nDPI protocol to be blocked in P4 */
      enable_p4 = 1;
      if (!blocked_protocols) {
        blocked_protocols = bstree_new(compare_proto_names, NULL);
      }
      bstree_insert(blocked_protocols, optarg);
      break;
    case 'c':
      enable_l7 = 1;
      categories_file = strdup(optarg);
      break;
    case 'd':
      pfring_ft_debug();
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'p':
      enable_l7 = 1;
      protocols_file = strdup(optarg);
      break;
    case 'q':
      quiet = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case '7':
      enable_l7 = 1;
      break;
    case 'F':
      enable_l7 = 1;
      configuration_file = strdup(optarg);
      break;
    case 'S':
      time_pulse = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    case 'V':
      print_version();
      exit(0);
      break;
    }
  }

  if (device == NULL) device = DEFAULT_DEVICE;
  bind2node(bind_core);

  if (enable_l7)
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;

  ft = pfring_ft_create_table(ft_flags, 0, 0, 0);

  if (ft == NULL) {
    fprintf(stderr, "pfring_ft_create_table error\n");
    return -1;
  }

  if (configuration_file) {
    /* Loading L7 filtering/shunting from configuration file */
    rc = pfring_ft_load_configuration(ft, configuration_file);

    if (rc < 0) {
      fprintf(stderr, "Failure loading rules from %s\n", configuration_file);
      return -1;
    }
  }

  /* Example of L7 packet filtering rules
  pfring_ft_set_filter_protocol_by_name(ft, "MDNS", PFRING_FT_ACTION_DISCARD);
  pfring_ft_set_filter_protocol_by_name(ft, "UPnP", PFRING_FT_ACTION_DISCARD);
  */

  /* Example of 'drop all' L7 protocols except Skype
  pfring_ft_set_default_action(ft, PFRING_FT_ACTION_DISCARD);
  pfring_ft_set_filter_protocol_by_name(ft, "Skype", PFRING_FT_ACTION_FORWARD);
  */

  /* Example of callback for expired flows */
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

  /* Example of callback for packets that have been successfully processed
  pfring_ft_set_flow_packet_callback(ft, processFlowPacket, NULL);
  */

  if (protocols_file) {
    rc = pfring_ft_load_ndpi_protocols(ft, protocols_file);

    if (rc < 0) {
      fprintf(stderr, "Failure loading custom protocols from %s\n", protocols_file);
      return -1;
    }
  }

  if (categories_file) {
    rc = pfring_ft_load_ndpi_categories(ft, categories_file);

    if (rc < 0) {
      fprintf(stderr, "Failure loading categories from %s\n", categories_file);
      return -1;
    }
  }

  promisc = 1;

  if (promisc)      flags |= PF_RING_PROMISC;
  if (!time_pulse) flags |= PF_RING_TIMESTAMP; /* needed for flow processing */

  pd = pfring_open(device, snaplen, flags);

  if (pd == NULL) {
    fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
      strerror(errno), device);
    return -1;
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "ftflow");
    pfring_version(pd, &version);

    if (!quiet) {
      printf("Using PF_RING v.%d.%d.%d\n",
       (version & 0xFFFF0000) >> 16,
       (version & 0x0000FF00) >> 8,
       version & 0x000000FF);
    }
  }

  pfring_set_direction(pd, direction);

  if ((rc = pfring_set_socket_mode(pd, recv_only_mode)) != 0)
    fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  if (time_pulse) {
    pulse_timestamp = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
    pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
    while (!*pulse_timestamp && !do_shutdown); /* wait for ts */
  }

  if (!quiet) {
    if (enable_l7)
      printf("Capturing from %s with nDPI support enabled\n", device);
    else
      printf("Capturing from %s without nDPI support (see -7)\n", device);
  }

  if (pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return -1;
  }

  if (bind_core >= 0)
    bind2core(bind_core);

  packet_consumer();

  sleep(1);

  if (time_pulse) {
    pthread_join(time_thread, NULL);
  }

  pfring_close(pd);

  pfring_ft_flush(ft);

  pfring_ft_destroy_table(ft);

  return 0;
}
