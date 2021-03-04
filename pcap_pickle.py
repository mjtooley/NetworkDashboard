from scapy.utils import RawPcapReader
import enum
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
import pickle

class PktDirection(enum.Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

import time

def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts_subsec)

def pickle_pcap(pcap_file_in, pickle_file_out):
    print('Processing {}...'.format(pcap_file_in))

    servers = ['209.23.210.2','193.122.210.121', '198.251.141.87','198.251.139.84','52.15.45.106','99.84.110.7', '193.123.30.5', '193.123.30.5', '99.84.222.108', '52.109.12.70', '52.15.45.106',
            '162.255.38.125', '193.123.16.46', '209.23.210.2', '193.122.212.56']
    clients = ['10.0.0.133','10.0.0.239','10.0.0.51','10.0.0.60','10.0.0.7','10.0.0.107','10.0.0.40','10.0.0.13','10.0.0.82','10.0.0.241', '10.0.0.141', '10.0.0.85', '10.0.0.213']

    count = 0
    interesting_packet_count = 0

    server_sequence_offset = None
    client_sequence_offset = None

    # List of interesting packets, will finally be pickled.
    # Each element of the list is a dictionary that contains fields of interest
    # from the packet.
    packets_for_analysis = []

    client_recv_window_scale = 0
    server_recv_window_scale = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_file_in):
        count += 1

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]

        if ((ip_pkt.proto != 6) and (ip_pkt.proto != 17)):
            continue

        direction = PktDirection.not_defined

        if ip_pkt.src in  clients:
            if ip_pkt.dst not in  servers:
                continue
            direction = PktDirection.client_to_server
        elif ip_pkt.src in servers:
            if ip_pkt.dst not in  clients:
                continue
            direction = PktDirection.server_to_client
        else:
            continue

        interesting_packet_count += 1
        if interesting_packet_count == 1:
            first_pkt_timestamp = pkt_metadata[0] * 1000000 + pkt_metadata[1]
            first_pkt_timestamp_resolution = 1000000
            first_pkt_ordinal = count

        last_pkt_timestamp = (pkt_metadata[0] * 1000000) | pkt_metadata[1]
        last_pkt_timestamp_resolution = 10000000
        last_pkt_ordinal = count

        this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp

        # Determine the TCP payload length. IP fragmentation will mess up this
        # logic, so first check that this is an unfragmented packet
        #if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
        #    print('No support for fragmented IP packets')
        #    return False

        #tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)

        # Create a dictionary and populate it with data that we'll need in the
        # analysis phase.

        pkt_data = {}
        pkt_data['direction'] = direction
        pkt_data['ordinal'] = last_pkt_ordinal
        pkt_data['source'] = ip_pkt.src
        pkt_data['dst'] = ip_pkt.dst
        pkt_data['len'] = pkt_metadata[2]
        pkt_data['timestamp'] = last_pkt_timestamp
        pkt_data['time'] = last_pkt_timestamp/1000000 #ip_pkt.time
        pkt_data['relative_timestamp'] = this_pkt_relative_timestamp / \
                                         1000000
        if ip_pkt.proto == 6:
            tcp_pkt = ip_pkt[TCP]
            pkt_data['sport'] = tcp_pkt.sport
            pkt_data['dport'] = tcp_pkt.dport
            pkt_data['proto'] = 'TCP'
        if ip_pkt.proto == 17:
            udp_pkt = ip_pkt[UDP]
            pkt_data['sport'] = udp_pkt.sport
            pkt_data['dport'] = udp_pkt.dport
            pkt_data['proto'] = 'UDP'
        #pkt_data['tcp_payload_len'] = tcp_payload_len

        #if direction == PktDirection.client_to_server:
        #    pkt_data['window'] = tcp_pkt.window << client_recv_window_scale
        #else:
        #    pkt_data['window'] = tcp_pkt.window << server_recv_window_scale

        packets_for_analysis.append(pkt_data)
    # ---

    print('{} contains {} packets ({} interesting)'.
          format(pcap_file_in, count, interesting_packet_count))

    print('Writing pickle file {}...'.format(pickle_file_out), end='')
    with open(pickle_file_out, 'wb') as pickle_fd:
        #for client in clients:
        pickle.dump(clients, pickle_fd)
        #for server in servers:
        pickle.dump(servers, pickle_fd)
        pickle.dump(packets_for_analysis, pickle_fd)
    print('done.')


def analyze_pickle(pickle_file_in):
    packets_for_analysis = []

    with open(pickle_file_in, 'rb') as pickle_fd:
        clients = pickle.load(pickle_fd)
        servers = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Print a header
    print('##################################################################')
    print('TCP session between client {} and server {}'.
          format(clients, servers))
    print('##################################################################')

def findFlows(pickle_file_in):
    packets_for_analysis = []

    flows = [] # emptylist

    with open(pickle_file_in, 'rb') as pickle_fd:
        clients = pickle.load(pickle_fd)
        servers = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Print a header
    print('##################################################################')
    print('TCP session between client {} and server {}'.
          format(clients, servers))
    print('##################################################################')
    for pkt_data in packets_for_analysis:
        flow = {}  # empty dict
        try:
            flow['src'] = pkt_data['source']
            flow['dst'] = pkt_data['dst']
            flow['sport'] = pkt_data['sport']
            flow['dport'] = pkt_data['dport']
            flow['direction'] = pkt_data['direction']
            flow['len'] = 0
            flow['start'] = 0
            flow['end'] = 0
            if flow not in flows:
                flows.append(flow)
        except:
            print(pkt_data)


    for pkt_data in packets_for_analysis:
        for flow in flows:
            try:
                if (flow['src'] == pkt_data['source'] and
                    flow['dst'] == pkt_data['dst'] and
                    flow['sport'] == pkt_data['sport'] and
                    flow['dport'] == pkt_data['dport'] and
                    flow['direction'] == pkt_data['direction']
                    ):
                        flow['len'] = flow['len'] + pkt_data['len']
                        if flow['start'] == 0:
                            flow['start'] = pkt_data['time']
                        if pkt_data['time'] > flow['end']:
                            flow['end'] = pkt_data['time']
                            flow['duration'] = (flow['end'] - flow['start'])
                            if flow['duration'] > 0:
                                flow['mean_bps'] = flow['len']*8 / flow['duration']
            except:
                print(pkt_data)

    for flow in flows:
        if flow['direction'] == PktDirection.client_to_server:
            print("U: {src}:{sp} --> {dst}:{dp} Durations (sec):{dur:.0f}   Mean(bps): {mean:,.0f}".format(
                src=flow['src'],sp=flow['sport'],dst=flow['dst'],dp=flow['dport'],dur=flow['duration'],mean=flow['mean_bps']))
    for flow in flows:
        if flow['direction'] == PktDirection.server_to_client:
            print("D: {src}:{sp} --> {dst}:{dp} Durations (sec):{dur:.0f}  Mean(bps): {mean:,.0f}".format(
                src=flow['src'],sp=flow['sport'],dst=flow['dst'],dp=flow['dport'],dur=flow['duration'],mean=flow['mean_bps']))







pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/8personzoom.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/8personzoom.pkl")
flows = findFlows("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/8personzoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/7personzoom.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/7personzoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/6personzoom.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/6personzoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/5personzoom.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/5personzoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/4personzoom.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/4personzoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/7personzoom.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/2zoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/3zoomsessions.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/3zoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/4plusandyzoom.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/4zoom.pkl")
pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/zoom_call_one_to_one.pcap","C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/1zoom.pkl")

