#!/bin/env python3

import subprocess
import sys
import re
import argparse

class App:

    re_conn = re.compile(r"\s*(\d+):.*\s+(\d+)>\s+(\d+)<")

    description="""
A handy shortcut to 'tcptrace -n -S --xplot_all_files -oX' to show TCP time-sequence plots.
"""
    epilog = """
usage 1: ttraces.py [--min_packets MIN] [--plot] <PCAP_FILE> [<PCAP_FILE> ...] 
         run tcptrace over all .pcap files (don't create time-sequence plots)
usage 2: ttraces.py [--min_packets MIN] <PCAP_FILE> <conn_id>
         run tcptrace -S over .pcap file and TCP connection <conn_id>
usage 3: ttraces.py [--min_packets MIN] <PCAP_FILE> /<pattern>
         run tcptrace -S over .pcap file and TCP connections whose output line in 'tcptrace -l' matches <pattern>
usage 4: ttraces.py [--min_packets MIN] <PCAP_FILE> [<PCAP_FILE> ...] +max
         run tcptrace -S over .pcap file and the TCP connection having the most packets.
usage 5: ttraces.py [--min_packets MIN] <PCAP_FILE> +
         run tcptrace -S over .pcap file and all TCP connections starting ordered by number of packets.

Where 'PCAP_FILE' is a .pcap file or has the format '@FILE_NAME', in which case the file name is read from file 
FILE_NAME. The 'tcptrace' and 'xplot' executables must be in the executable path.
    """

    def parse_options(self):

        parser = argparse.ArgumentParser(description=App.description, formatter_class=argparse.RawDescriptionHelpFormatter, epilog=App.epilog)
        parser.add_argument("--min_packets", type=int, default=0, help="Only consider TCP connections with at least this amount of packets")
        parser.add_argument("--plot", action="store_true", help="")
        parser.add_argument("args", nargs="*", help="The .pcap file(s) to analyse")
        self.options = parser.parse_args()

        if len(self.options.args) < 1:
            sys.stderr.write("usage 1: ttraces.py [--min_packets MIN] [--plot] <PCAP_FILE> [<PCAP_FILE> ...] - run tcptrace over all .pcap files (don't create time-sequence plots)\n")
            sys.stderr.write("usage 2: ttraces.py [--min_packets MIN] <PCAP_FILE> <conn_id>     - run tcptrace -S over .pcap file and TCP connection <conn_id>\n")
            sys.stderr.write("usage 3: ttraces.py [--min_packets MIN] <PCAP_FILE> /<pattern>    - run tcptrace -S over .pcap file and TCP connections that matches <pattern>\n")
            sys.stderr.write("usage 4: ttraces.py [--min_packets MIN] <PCAP_FILE> [<PCAP_FILE> ...] +max - run tcptrace -S over .pcap file and the TCP connection having the most packets.\n")
            sys.stderr.write("usage 5: ttraces.py [--min_packets MIN] <PCAP_FILE> +             - run tcptrace -S over .pcap file and all TCP connections starting ordered by number of packets.\n")
            sys.stderr.write("Where 'PCAP_FILE' is a .pcap file or has the format '@FILE_NAME', in which case the file name is read from file FILE_NAME\n")
            sys.exit(1)

        self.file_names = self.options.args

    def run_conn_id(self, file_name, conn_id):
        popen = subprocess.Popen(["tcptrace", "-n", "-S", "-o" + conn_id, "--xplot_all_files", file_name])
        return popen.wait()
    
    def expand_file_name(self, file_name):
        if file_name.startswith("@"):
            with open(file_name[1:]) as fh:
                return fh.readline().strip()
        else:
            return file_name

    def run_list_conns(self, file_name):

        popen = subprocess.Popen(["tcptrace", "-n", file_name], stdout = subprocess.PIPE)

        for line in popen.stdout:
            line = line.decode("latin1")
            sys.stdout.write(repr(line)+"\n")
            
        return popen.wait()

    def run_list_conns_long(self, file_name):

        re_conn_id = re.compile(r"TCP connection (\d+):")
        re_host = re.compile(r"host (\w+):\s*(\S.*)")
        re_ts_first = re.compile(r"first packet:\s*(\S.*)")
        re_total_packets = re.compile(r"total packets:\s+(\d+)\s+total packets:\s+(\d+)")
        
        popen = subprocess.Popen(["tcptrace", "-l", "-n", file_name], stdout = subprocess.PIPE)
        conn_id = None
        endpoint_a = None
        endpoint_b = None        

        out_prefixes = []
        out_suffixes = []
        max_prefix_len = 0
        
        for line in popen.stdout:

            line = line.decode("latin1")

            m = re_conn_id.search(line)
            if m:
                conn_id = m.group(1)
                endpoint_a = None
                host_a = None
                endpoint_b = None
                host_b = None
                ts_first = None
                is_complete = False
                continue
            
            m = re_host.search(line)
            if m:
                host = m.group(1)
                endpoint = m.group(2)
                if not endpoint_a:
                    host_a = host
                    endpoint_a = endpoint
                else:
                    host_b = host
                    endpoint_b = endpoint
                continue
            
            m = re_ts_first.search(line)
            if m:
                ts_first = m.group(1)
                continue

            if "complete conn: yes" in line:
                is_complete = True

            m = re_total_packets.search(line)
            if m:
                
                total_packets_a = int(m.group(1))
                total_packets_b = int(m.group(2))

                if self.options.min_packets > 0 and (total_packets_a + total_packets_b) < self.options.min_packets:
                    continue

                out_prefix = "%3s: %s %s - %s (%s2%s)" % \
                             (conn_id,
                              ts_first,
                              endpoint_a, endpoint_b, host_a, host_b)

                if len(out_prefix) > max_prefix_len:
                    max_prefix_len = len(out_prefix)

                out_prefixes.append(out_prefix)
                out_suffixes.append(" %4d> %4d< %s" % \
                                    (total_packets_a, total_packets_b, "(complete)" if is_complete else ""))

        for i in range(len(out_prefixes)):
            print(out_prefixes[i] + \
                  (max_prefix_len - len(out_prefixes[i])) * " " + \
                  out_suffixes[i])
            
        return popen.wait()

    def run_list_conns_multiple_files(self, file_names):
        for file_name in file_names:
            print("")
            print("--------", file_name, "--------")
            self.run_list_conns_long(self.expand_file_name(file_name))

    def run_sorted_connections(self, file_names, max_conns=-1):

        for file_name in map(self.expand_file_name, file_names):
            
            popen = subprocess.Popen(["tcptrace", "-n", file_name], stdout = subprocess.PIPE)
            conns = []
            
            for line in popen.stdout:
    
                line = line.decode("latin1")
    
                m = self.re_conn.match(line)
                if not m:
                    continue
    
                num_packets = int(m.group(2)) + int(m.group(3))
    
                if self.options.min_packets > 0:
                    if num_packets < self.options.min_packets:
                        continue
                
                conns.append((num_packets, m.group(1)))
            
            count = max_conns
    
            for conn in sorted(conns, key=lambda x: x[0], reverse=True):                         
                self.run_conn_id(file_name, conn[1])
                count -= 1
                if count == 0:
                    break
                
            ret = popen.wait()
            
        return ret

    def run_pattern(self, file_name, pattern):

        popen = subprocess.Popen(["tcptrace", "-n", file_name], stdout = subprocess.PIPE)
        
        for line in popen.stdout:

            line = line.decode("latin1")

            m = self.re_conn.match(line)
            if not m:
                continue

            if self.options.min_packets > 0:
                num_packets = int(m.group(2)) + int(m.group(3))
                if num_packets < self.options.min_packets:
                    continue

            if pattern in line:
                self.run_conn_id(file_name, m.group(1))

        return popen.wait()

    def run(self):

        self.parse_options()

        command = self.file_names[-1]
        file_names = self.file_names[:-1]
        
        if command == "+":
            ret = self.run_sorted_connections(file_names)

        elif command == "+max":
            ret = self.run_sorted_connections(file_names, 1)

        elif command[0] == "/":
            for file_name in map(self.expand_file_name, file_names):
                ret = self.run_pattern(file_name, command[1:])

        else:
            try:
                conn_id = int(command)
                for file_name in map(self.expand_file_name, file_names):
                    ret = self.run_conn_id(file_name, str(conn_id))
            except ValueError as e:
                ret = self.run_list_conns_multiple_files(self.file_names)
                        
        sys.exit(ret)
            
if __name__ == "__main__":
    App().run()
