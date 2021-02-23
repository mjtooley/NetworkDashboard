from scapy.utils import RawPcapReader
import enum
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
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

    servers = ['10.0.0.13','10.0.0.82','99.84.110.7', '193.123.30.5', '193.123.30.5', '99.84.222.108', '52.109.12.70', '52.15.45.106',
            '162.255.38.125', '193.123.16.46', '209.23.210.2', '193.122.212.56']
    clients = ['10.0.0.13','10.0.0.82','10.0.0.241', '10.0.0.141', '10.0.0.85', '10.0.0.213']

    #client = '192.168.1.137:57080'
    #server = '152.19.134.43:80'

    #(client_ip, client_port) = client.split(':')
    #(server_ip, server_port) = server.split(':')

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

        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        tcp_pkt = ip_pkt[TCP]

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

        if direction == PktDirection.client_to_server:
            if client_sequence_offset is None:
                client_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - client_sequence_offset
        else:
            assert direction == PktDirection.server_to_client
            if server_sequence_offset is None:
                server_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - server_sequence_offset

        # Determine the TCP payload length. IP fragmentation will mess up this
        # logic, so first check that this is an unfragmented packet
        if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
            print('No support for fragmented IP packets')
            return False

        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)

        # Create a dictionary and populate it with data that we'll need in the
        # analysis phase.

        pkt_data = {}
        pkt_data['direction'] = direction
        pkt_data['ordinal'] = last_pkt_ordinal
        pkt_data['source'] = ip_pkt.src
        pkt_data['dst'] = ip_pkt.dst
        pkt_data['len'] = pkt_metadata[2]
        pkt_data['timestamp'] = last_pkt_timestamp
        pkt_data['time'] = ip_pkt.time
        pkt_data['relative_timestamp'] = this_pkt_relative_timestamp / \
                                         1000000
        pkt_data['tcp_payload_len'] = tcp_payload_len

        if direction == PktDirection.client_to_server:
            pkt_data['window'] = tcp_pkt.window << client_recv_window_scale
        else:
            pkt_data['window'] = tcp_pkt.window << server_recv_window_scale

        packets_for_analysis.append(pkt_data)
    # ---

    print('{} contains {} packets ({} interesting)'.
          format(pcap_file_in, count, interesting_packet_count))

    print('First packet in connection: Packet #{} {}'.
          format(first_pkt_ordinal,
                 printable_timestamp(first_pkt_timestamp,
                                     first_pkt_timestamp_resolution)))
    print(' Last packet in connection: Packet #{} {}'.
          format(last_pkt_ordinal,
                 printable_timestamp(last_pkt_timestamp,
                                     last_pkt_timestamp_resolution)))

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

    # Print format string
    fmt = ('[{ordnl:>5}]{ts:>10.6f}s {flag:<3s} seq={seq:<8d} '
           'ack={ack:<8d} len={len:<6d} win={win:<9d}')

    for pkt_data in packets_for_analysis:

        direction = pkt_data['direction']

        if direction == PktDirection.client_to_server:
            print("%4d %1.4f %4d %s --> %s" % (pkt_data['ordinal'],
                                              pkt_data['relative_timestamp'],
                                              pkt_data['len'],
                                              pkt_data['source'],
                                              pkt_data['dst'] ))
        else:
            print("%4d %1.4f %4d %s <-- %s" % (pkt_data['ordinal'],
                                              pkt_data['relative_timestamp'],
                                              pkt_data['len'],
                                              pkt_data['source'],
                                              pkt_data['dst']))


pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/5sessionzoom.pcap","tstpickleout")
#pickle_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/testfile.pcap","tstpickleout")

analyze_pickle('tstpickleout')
