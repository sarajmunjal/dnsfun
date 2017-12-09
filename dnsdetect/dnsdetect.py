from scapy.all import *
import sys, getopt
import netifaces
import time


def callback(map, local_ip):
    def process(pkt):
        if DNS in pkt and pkt[DNS].qr == 1 and pkt[IP].dst == local_ip:
            print repr(pkt[DNS])
            txn_id = pkt[DNS].id
            q_url = pkt[DNSQR].qname
            key = (txn_id, q_url)
            ip_addrs = set()
            ancnt = pkt[DNS].ancount
            ttls = set()
            for i in range(ancnt):
                ip_addrs.add(pkt[DNSRR][i].rdata)
                ttls.add(pkt[DNSRR][i].ttl)

            print 'q_url:{0}, txn_id : {1}, IPs: {2}, acnt: {3}, ttl:{4}'.format(q_url, txn_id, str(ip_addrs), ancnt,
                                                                                 ttls)
            if key in map:
                existing_val = map[key]
                # IP will be same
                if ip_addrs.issubset(existing_val[0]):
                    print 'False positive case with overlapping IPs'
                    return ''
                if ttls == existing_val[2]:
                    print 'False positive case with matching TTL values'
                    return ''
                print '{0} DNS poisoning attempt '.format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
                print 'TXID {0} Request {1}'.format(txn_id, q_url)
                print 'Original IPs:{0} , original TTLs:'.format(str(existing_val[0]), str(existing_val(2)))
                print 'New IPs {0}'.format(str(ip_addrs))
            else:
                map[key] = (ip_addrs, ancnt, ttls)
                return
        else:
            return

    return process


def get_local_ip(interface_name):
    return netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['addr'].encode("UTF-8")


def parse_args(argv):
    hosts_file = ''
    interface_name = ''
    try:
        opts, args = getopt.getopt(argv, "r:i:")
    except getopt.GetoptError:
        print 'Incorrect format of args. Expected: python dnsdetect.py [-i interface] [-r tracefile] expression'
        sys.exit(2)
    l = len(args)
    if l > 1:
        print 'Too many arguments.  Expected: python dnsdetect.py [-i interface] [-r tracefile] expression'
        sys.exit(2)
    if l < 1:
        print 'Too few arguments.  Expected: python dnsdetect.py [-i interface] [-r tracefile] expression'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-r':
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
    map = {}
    trace_file, interface_name, bpf_expr = parse_args(argv)
    # interface = get_default_interface() if interface_name is '' else interface_name
    interface = get_default_interface() if interface_name is '' else interface_name
    local_ip = get_local_ip(interface)
    bpf_filt = 'udp src port 53 && ip dst {0}'.format(local_ip) if (bpf_expr is '') else bpf_expr
    if trace_file is '':
        sniff(iface=interface, filter=bpf_filt, prn=callback(map, local_ip))
    else:
        sniff(offline=trace_file, iface=interface, filter=bpf_filt, prn=callback(map, local_ip))


if __name__ == "__main__":
    main(sys.argv[1:])
