
#!/usr/bin/env python3
from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import plotly
from datetime import datetime
import pandas as pd
from collections import Counter
import sys

zoom = ['10.0.0.13', '10.0.0.82','99.84.110.7','193.123.30.5','193.123.30.5','99.84.222.108','52.109.12.70','52.15.45.106', '162.255.38.125', '193.123.16.46', '209.23.210.2', '193.122.212.56']
clients = ['10.0.0.241', '10.0.0.141', '10.0.0.85', '10.0.0.213', '10.0.0.82','10.0.0.13']
#pcap_file = "C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/5sessionzoom.pcap"

def human(num):
    for x in ['', 'k', 'M', 'G', 'T']:
        if num < 1024.: return "%3.1f %sB" % (num, x)
        num /= 1024.
    return  "%3.1f PB" % (num)

def flowList(packets, h1, h2):
    p = {}
    flow = []
    match = False

    for pkt in packets:
        if IP in pkt:
            try:
                if (pkt[IP].src ==  h1) and (pkt[IP].dst == h2):
                    match = True
                if match:
                    p['bytes'] = pkt[IP].len
                    p['bits'] = pkt[IP].len * 8
                    p['ts'] = pkt.time
                    p['src'] = pkt[IP].src
                    p['dst'] = pkt[IP].dst
                    #print p
                    flow.append(copy.deepcopy(p))

            except:
                e = sys.exc_info()[0]
                print(e)
                pass
        match = False
    return flow

def flowLists(packets, h1, h2):
    p = {}
    dsflow = []
    usflow = []
    match = False

    for pkt in packets:
        if IP in pkt:
            try:
                if (pkt[IP].src == h1) and (pkt[IP].dst == h2):
                        p['bytes'] = pkt[IP].len
                        p['bits'] = pkt[IP].len * 8
                        p['ts'] = pkt.time
                        p['src'] = pkt[IP].src
                        p['dst'] = pkt[IP].dst
                        #print p
                        usflow.append(copy.deepcopy(p))

                if (pkt[IP].dst == h1) and (pkt[IP].src == h2):
                        p['bytes'] = pkt[IP].len
                        p['bits'] = pkt[IP].len * 8
                        p['ts'] = pkt.time
                        p['src'] = pkt[IP].src
                        p['dst'] = pkt[IP].dst
                        #print p
                        dsflow.append(copy.deepcopy(p))
            except:
                e = sys.exc_info()[0]
                print (e)
                pass

    return dsflow,usflow

def processFlow(flow):
    pBytes = []
    pBits = []
    pTimes = []
    pTS = [] # Timestamps for more accuracy
    pStart = 0

    for p in flow:
        try:
            #print ('Source:',pkt[IP].src)
            #print ('Destination:', pkt[IP].dst)
            pBytes.append(p['bytes'])
            pBits.append(p['bits'])
            #First we need to covert Epoch time to a datetime
            timestamp = p['ts']
            pktTime=datetime.fromtimestamp(timestamp)
            #Then convert to a format we like
            pTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
            pTS.append(timestamp)
        except:
            e = sys.exc_info()[0]
            print (e)
            pass

    #This converts list to series
    bytes = pd.Series(pBytes).astype(int)
    bits = pd.Series(pBits).astype(int)

    #Convert the timestamp list to a pd date_time
    times = pd.to_datetime(pd.Series(pTimes).astype(str),  errors='coerce')
    timestamps = pd.Series(pTS).astype('datetime64[ns]')
    #Create the dataframe
    df  = pd.DataFrame({"Bytes": bytes, "Times":times})
    df_bits = pd.DataFrame({"Bits": bits, "Times": times})
    dfts = pd.DataFrame({"Bytes": bytes, "Timestamp": times})
    #set the date from a range to an timestamp
    df = df.set_index('Times')
    df_bits = df_bits.set_index('Times')
    dfts = dfts.set_index('Timestamp')

    #Create a new dataframe of 2 second sums to pass to plotly
    #df2=df.resample('1S').sum()  # 1S  L is milliseconds
    df2_bits = df_bits.resample('1S').sum()
    df_bytes = dfts.resample('100ms').sum()

    return df2_bits, df_bytes

def plotFlow(df):
    plotly.offline.plot({
        "data":[plotly.graph_objs.Scatter(x=df.index, y=df['Bits'])],
            "layout":plotly.graph_objs.Layout(title="Bits over Time ",
            xaxis=dict(title="Time"),
            yaxis=dict(title="Bits"))})

def create_DF(dfs, flow_names, field):
    usdf = pd.DataFrame()
    #usdf['TS'] = dfs[0].df['Times']
    print("create_DF:", field)

    try:
        i = 0
        for df in dfs:
            fn = flow_names[i]
            print("create_DF:", fn)
            usdf[fn] = df[field]
            i = i +1

    except:
        print(usdf[usdf.index.duplicated()])
        e = sys.exc_info()[0]
        print(e)

    return usdf

def create_DF2(dfs, flow_names):
    df = pd.DataFrame()
    print("create_DF2:")
    try:
        i = 0
        for df in dfs:
            fn = flow_names[i]
            print("create_DF2:", fn)
            df[fn] = df['Bytes']
            i = i +1

    except:
        print(df[df.index.duplicated()])
        e = sys.exc_info()[0]
        print(e)

    return df

def plotflows(dfs, flow_names,title):
    import plotly.graph_objects as go
    fig = go.Figure()
    for df in dfs:
        flow_name = flow_names.pop(0)
        fig.add_trace(go.Scatter(x=df.index, y=df['Bits'], name=flow_name, stackgroup='one'))

    fig.update_layout(
        title=title,
        xaxis_title = "Time",
        yaxis_title = "Rate, bits per second",
        legend_title = 'Flow'
    )
    fig.show()

def chartFlowsBits(dfs, flow_names, title):
    import plotly.graph_objects as go
    fig = go.Figure()
    i = 0
    for df in dfs:
        flow_name = flow_names[i]
        i = i+1
        fig.add_trace(go.Bar(x=df.index, y=df['Bits'], name=flow_name))

    fig.update_layout(
        template="simple_white",
        title=title,
        xaxis_title = "Time",
        yaxis_title = "Rate, Bits per transmission",
        legend_title = 'Flow',
        barmode = "stack",
    )
    fig.show()

def chartFlowsBytes(dfs, flow_names, title):
    import plotly.graph_objects as go
    fig = go.Figure()
    i = 0
    for df in dfs:
        flow_name = flow_names[i]
        i = i+1
        fig.add_trace(go.Bar(x=df.index, y=df['Bytes'], name=flow_name))

    fig.update_layout(
        template="simple_white",
        title=title,
        xaxis_title = "Time",
        yaxis_title = "Rate, Bytes per transmission",
        legend_title = 'Flow',
        barmode="stack",
    )
    fig.show()

# The data fram has a column for each flow
def plot_stacked_flows(df):
    import plotly.graph_objects as go
    fig = go.Figure()
    col_names = list(df.columns)

    for i in range(0, len(col_names)):
        name = col_names[i]
        # df1 = df[[name]].copy()
        fig.add_trace(go.Scatter(x=df.index,y=df[name],name=name, stackgroup='one'))

    fig.show()


hosts = {}
def getFlowName(h1, h2):
    if h1 not in hosts:
        try:
            rhost = socket.gethostbyaddr(h1)
            hosts[h1] = rhost[0]
        except:
            hosts[h1] = None
    if h2 not in hosts:
        try:
            rhost = socket.gethostbyaddr(h2)
            hosts[h2] = rhost[0]
        except:
            hosts[h2] = None
    h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
    h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
    flowname = h1 + "<->" + h2
    return flowname

def process_pcap(pcap_file):
    #Lists to hold packet info
    pktBytes=[]
    pktBits=[]
    pktTimes=[]
    traffic = Counter()
    ustraffic = Counter()
    uspktBits=[]
    uspktTimes=[]
    dstraffic = Counter()
    dspktBits=[]
    dspktTimes=[]


    print("Processing:", pcap_file)
    packets = rdpcap(pcap_file)
    print("start processing packets from file")

    #Read each packet and append to the lists.
    for pkt in packets:
        if IP in pkt:
            try:
                if ((pkt[IP].src in clients) and (pkt[IP].dst in zoom) ) :
                    pktBytes.append(pkt[IP].len)
                    pktBits.append(pkt[IP].len * 8)
                    uspktBits.append(pkt[IP].len * 8)
                    pktTime=datetime.fromtimestamp(pkt.time)
                    pktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
                    uspktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
                    traffic.update({tuple(sorted(map(atol, (pkt[IP].src, pkt[IP].dst)))): pkt[IP].len})
                    ustraffic.update({tuple(sorted(map(atol, (pkt[IP].src, pkt[IP].dst)))): pkt[IP].len})
                    h1 = (pkt[IP].src)
                    h2 = (pkt[IP].dst)
                    #print ("Up: %s -> %s" % (h1, h2))

                if ((pkt[IP].dst in clients) and (pkt[IP].src in zoom)):
                    pktBytes.append(pkt[IP].len)
                    pktBits.append(pkt[IP].len * 8)
                    dspktBits.append(pkt[IP].len * 8)
                    pktTime = datetime.fromtimestamp(pkt.time)
                    pktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
                    dspktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
                    traffic.update({tuple(sorted(map(atol, (pkt[IP].src, pkt[IP].dst)))): pkt[IP].len})
                    dstraffic.update({tuple(sorted(map(atol, (pkt[IP].src, pkt[IP].dst)))): pkt[IP].len})
                    h1 = (pkt[IP].src)
                    h2 = (pkt[IP].dst)
                    #print ("Down: %s -> %s" % (h1, h2))
            except:
                e = sys.exc_info()[0]
                print (e)
                pass

    dsflows = []
    dsflow_names = []
    usflows = []
    usflow_names = []
    print ("Traffic Top 10")
    for (h1, h2), total in traffic.most_common(10):
        h1, h2 = map(ltoa, (h1, h2))
        # print ("Top 10 Flow: %s - %s" % (h1, h2))
        for host in (h1, h2):
            if host not in hosts:
                try:
                    rhost = socket.gethostbyaddr(host)
                    hosts[host] = rhost[0]
                except:
                    hosts[host] = None
        h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
        h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
        print ("%s: %s - %s" % (human(float(total)), h1, h2))
        dsflow, usflow = flowLists(packets, h1,h2)
        dsflows.append(dsflow)
        usflows.append(usflow)
        flow_name = getFlowName(h1, h2)
        dsflow_names.append(flow_name)
        flow_name = getFlowName(h2,h1)
        usflow_names.append(flow_name)

    print("Top US flows")
    for (h1, h2), total in ustraffic.most_common(20):
        h1, h2 = map(ltoa, (h1, h2))

        # print ("Top 10 Flow: %s - %s" % (h1, h2))
        for host in (h1, h2):
            if host not in hosts:
                try:
                    rhost = socket.gethostbyaddr(host)
                    hosts[host] = rhost[0]
                except:
                    hosts[host] = None
        h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
        h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
        print("%s: %s - %s" % (human(float(total)), h1, h2))

    print("Top DS flows")
    for (h1, h2), total in dstraffic.most_common(20):
        h1, h2 = map(ltoa, (h1, h2))

        # print ("Top 10 Flow: %s - %s" % (h1, h2))
        for host in (h1, h2):
            if host not in hosts:
                try:
                    rhost = socket.gethostbyaddr(host)
                    hosts[host] = rhost[0]
                except:
                    hosts[host] = None
        h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
        h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
        print("%s: %s - %s" % (human(float(total)), h1, h2))

    usdfs = []
    usdfs2 = []
    for flow in usflows:
        df, df_bytes = processFlow(flow)
        usdfs.append(df)
        usdfs2.append(df_bytes)
    #usdfs.append(usdf2_bits)
    us_df = create_DF(usdfs, usflow_names, 'Bits')
    us_df2 = create_DF2(usdfs2, usflow_names)

    chartFlowsBits(usdfs, usflow_names, "Upstream")
    plotflows(usdfs, usflow_names, "Upstream")
    #plot_stacked_flows(us_df)


    dsdfs = []
    dsdfs2 = []
    for flow in dsflows:
        df, df_bytes = processFlow(flow)
        dsdfs.append(df)
        dsdfs2.append(df_bytes)
    #dsdfs.append(dsdf2_bits)
    ds_df = create_DF(dsdfs, dsflow_names,'Bits')
    ds_df2 = create_DF2(dsdfs2, dsflow_names)
    chartFlowsBits(dsdfs, dsflow_names,"Downtream")
    plotflows(dsdfs, dsflow_names, "Downstream")


    # Now save the Dataframes to CSV
    f_name, f_ext = os.path.splitext(pcap_file)
    us_df.to_csv(f_name+"_us"+".csv")
    ds_df.to_csv(f_name+"_ds"+".csv")
    us_df2.to_csv(f_name+"bytes_us"+".csv")
    ds_df2.to_csv(f_name+"bytes_ds"+".csv")

    print("Finished")

def pickledFlowLists(packets, h1, h2):
    p = {}
    dsflow = []
    usflow = []

    for pkt in packets:
        if (pkt['source'] == h1) and (pkt['dst'] == h2):
                p['bytes'] = pkt['len']
                p['bits'] = pkt['len'] * 8
                p['ts'] = pkt['time']
                p['src'] = pkt['source']
                p['dst'] = pkt['dst']
                #print p
                usflow.append(copy.deepcopy(p))

        if (pkt['dst'] == h1) and (pkt['source'] == h2):
                p['bytes'] = pkt['len']
                p['bits'] = pkt['len'] * 8
                p['ts'] = pkt['time']
                p['src'] = pkt['source']
                p['dst'] = pkt['dst']
                #print p
                dsflow.append(copy.deepcopy(p))

    return dsflow,usflow

import enum
class PktDirection(enum.Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

def process_pickled_pcap(pickle_file_in):
    from scapy.utils import RawPcapReader
    import enum
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP
    import pickle

    #Lists to hold packet info
    pktBytes=[]
    pktBits=[]
    pktTimes=[]
    traffic = Counter()
    ustraffic = Counter()
    uspktBits=[]
    uspktTimes=[]
    dstraffic = Counter()
    dspktBits=[]
    dspktTimes=[]

    packets_for_analysis = []

    with open(pickle_file_in, 'rb') as pickle_fd:
        clients = pickle.load(pickle_fd)
        servers = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Print a header
    print('##################################################################')
    print('Analyzing sessions between clients {} and servers {}'.
          format(clients, servers))
    print('##################################################################')


    for pkt_data in packets_for_analysis:

        direction = pkt_data['direction']

        if direction == PktDirection.client_to_server:
            print("%4d %1.4f %4d %s --> %s" % (pkt_data['ordinal'],
                                               pkt_data['relative_timestamp'],
                                               pkt_data['len'],
                                               pkt_data['source'],
                                               pkt_data['dst']))
        else:
            print("%4d %1.4f %4d %s <-- %s" % (pkt_data['ordinal'],
                                               pkt_data['relative_timestamp'],
                                               pkt_data['len'],
                                               pkt_data['source'],
                                               pkt_data['dst']))

        if ((pkt_data['source'] in clients) and (pkt_data['dst'] in zoom)):
            pktBytes.append(pkt_data['len'])
            pktBits.append(pkt_data['len'] * 8)
            uspktBits.append(pkt_data['len'] * 8)
            pktTime = datetime.fromtimestamp(pkt_data['time'])
            pktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
            uspktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
            traffic.update({tuple(sorted(map(atol, (pkt_data['source'], pkt_data['dst'])))): pkt_data['len']})
            ustraffic.update({tuple(sorted(map(atol, (pkt_data['source'], pkt_data['dst'])))): pkt_data['len']})
            h1 = (pkt_data['source'])
            h2 = (pkt_data['dst'])

        if ((pkt_data['dst'] in clients) and (pkt_data['source'] in zoom)):
            pktBytes.append(pkt_data['len'])
            pktBits.append(pkt_data['len'] * 8)
            uspktBits.append(pkt_data['len'] * 8)
            pktTime = datetime.fromtimestamp(pkt_data['time'])
            pktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
            uspktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
            traffic.update({tuple(sorted(map(atol, (pkt_data['source'], pkt_data['dst'])))): pkt_data['len']})
            ustraffic.update({tuple(sorted(map(atol, (pkt_data['source'], pkt_data['dst'])))): pkt_data['len']})
            h1 = (pkt_data['source'])
            h2 = (pkt_data['dst'])


    dsflows = []
    dsflow_names = []
    usflows = []
    usflow_names = []

    print ("Traffic Top 10")
    for (h1, h2), total in traffic.most_common(10):
        h1, h2 = map(ltoa, (h1, h2))
        # print ("Top 10 Flow: %s - %s" % (h1, h2))
        for host in (h1, h2):
            if host not in hosts:
                try:
                    rhost = socket.gethostbyaddr(host)
                    hosts[host] = rhost[0]
                except:
                    hosts[host] = None
        h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
        h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
        print ("%s: %s - %s" % (human(float(total)), h1, h2))
        dsflow, usflow = pickledFlowLists(packets_for_analysis, h1,h2)
        dsflows.append(dsflow)
        usflows.append(usflow)
        flow_name = getFlowName(h1, h2)
        dsflow_names.append(flow_name)
        flow_name = getFlowName(h2,h1)
        usflow_names.append(flow_name)

    print("Top US flows")
    for (h1, h2), total in ustraffic.most_common(20):
        h1, h2 = map(ltoa, (h1, h2))
        for host in (h1, h2):
            if host not in hosts:
                try:
                    rhost = socket.gethostbyaddr(host)
                    hosts[host] = rhost[0]
                except:
                    hosts[host] = None
        h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
        h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
        print("%s: %s - %s" % (human(float(total)), h1, h2))

    print("Top DS flows")
    for (h1, h2), total in dstraffic.most_common(20):
        h1, h2 = map(ltoa, (h1, h2))
        for host in (h1, h2):
            if host not in hosts:
                try:
                    rhost = socket.gethostbyaddr(host)
                    hosts[host] = rhost[0]
                except:
                    hosts[host] = None
        h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
        h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
        print("%s: %s - %s" % (human(float(total)), h1, h2))

    usdfs = []
    usdfs2 = []
    for flow in usflows:
        df, df_bytes = processFlow(flow)
        usdfs.append(df)
        usdfs2.append(df_bytes)
    #usdfs.append(usdf2_bits)
    us_df = create_DF(usdfs, usflow_names, 'Bits')
    us_df2 = create_DF2(usdfs2, usflow_names)

    chartFlowsBits(usdfs, usflow_names, "Upstream")
    chartFlowsBytes(usdfs2, usflow_names, "Upstream Bytes")
    plotflows(usdfs, usflow_names, "Upstream")
    #plot_stacked_flows(us_df)

    dsdfs = []
    dsdfs2 = []
    for flow in dsflows:
        df, df_bytes = processFlow(flow)
        dsdfs.append(df)
        dsdfs2.append(df_bytes)
    #dsdfs.append(dsdf2_bits)
    ds_df = create_DF(dsdfs, dsflow_names,'Bits')
    ds_df2 = create_DF2(dsdfs2, dsflow_names)
    chartFlowsBits(dsdfs, dsflow_names,"Downtream")
    chartFlowsBytes(dsdfs2, dsflow_names, "Downstream Bytes")
    plotflows(dsdfs, dsflow_names, "Downstream")

    # Now save the Dataframes to CSV
    f_name, f_ext = os.path.splitext(pickle_file_in)
    us_df.to_csv(f_name+"_us"+".csv")
    ds_df.to_csv(f_name+"_ds"+".csv")
    us_df2.to_csv(f_name+"bytes_us"+".csv")
    ds_df2.to_csv(f_name+"bytes_ds"+".csv")

    print("Finished")

#process_pcap("C:/Users/mtooley/Box/Internet Traffic Assymmetry/pcap_files/2person_zoom.pcap")
process_pickled_pcap('tstpickleout')
