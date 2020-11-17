
#!/usr/bin/env python3
from scapy.all import *
import plotly
from datetime import datetime
import pandas as pd
from collections import Counter
import sys

zoom = ['99.84.110.7','193.123.30.5','193.123.30.5','99.84.222.108','52.109.12.70','52.15.45.106', '162.255.38.125', '193.123.16.46', '209.23.210.2', '193.122.212.56']
clients = ['10.0.0.241', '10.0.0.141', '10.0.0.85', '10.0.0.213']
pcap_file = "5sessionzoom.pcap"

def human(num):
    for x in ['', 'k', 'M', 'G', 'T']:
        if num < 1024.: return "%3.1f %sB" % (num, x)
        num /= 1024.
    return  "%3.1f PB" % (num)


#print(df2)

#Create the graph
#plotly.offline.plot({
#    "data":[plotly.graph_objs.Scatter(x=df2.index, y=df2['Bytes'])],
#        "layout":plotly.graph_objs.Layout(title="Bytes over Time ",
#        xaxis=dict(title="Time"),
#        yaxis=dict(title="Bytes"))})


def flowList(h1, h2):
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
                print e
                pass
        match = False
    return flow

def flowLists(h1, h2):
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
                print e
                pass

    return dsflow,usflow

def processFlow(flow):
    pBytes = []
    pBits = []
    pTimes = []

    for p in flow:
        try:
            #print ('Source:',pkt[IP].src)
            #print ('Destination:', pkt[IP].dst)
            pBytes.append(p['bytes'])
            pBits.append(p['bits'])
            #First we need to covert Epoch time to a datetime
            pktTime=datetime.fromtimestamp(p['ts'])
            #Then convert to a format we like
            pTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
        except:
            e = sys.exc_info()[0]
            print e
            pass

    #This converts list to series
    bytes = pd.Series(pBytes).astype(int)
    bits = pd.Series(pBits).astype(int)

    #Convert the timestamp list to a pd date_time
    times = pd.to_datetime(pd.Series(pTimes).astype(str),  errors='coerce')
    #Create the dataframe
    df  = pd.DataFrame({"Bytes": bytes, "Times":times})
    df_bits = pd.DataFrame({"Bits": bits, "Times": times})
    #set the date from a range to an timestamp
    df = df.set_index('Times')
    df_bits = df_bits.set_index('Times')

    #Create a new dataframe of 2 second sums to pass to plotly
    df2=df.resample('1S').sum()  # 1S  L is milliseconds
    df2_bits = df_bits.resample('1S').sum()

    return df2_bits

def plotFlow(df):
    plotly.offline.plot({
        "data":[plotly.graph_objs.Scatter(x=df.index, y=df['Bits'])],
            "layout":plotly.graph_objs.Layout(title="Bits over Time ",
            xaxis=dict(title="Time"),
            yaxis=dict(title="Bits"))})

def plotflows(dfs, flow_names,title):
    import plotly.graph_objects as go
    fig = go.Figure()
    for df in dfs:
        flow_name = flow_names.pop(0)
        fig.add_trace(go.Scatter(x=df.index, y=df['Bits'], name=flow_name))

    fig.update_layout(
        title=title,
        xaxis_title = "Time",
        yaxis_title = "Rate, bits per second",
        legend_title = 'Flow'
    )
    fig.show()

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

#######################
# An alternative to rdpcap is to iterate with PcapReader
# for p in PcapReader("lan.pcap")
#    --- process p
#Read the packets from file
print ("Running...")
packets = rdpcap(pcap_file)

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
hosts = {}

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
                #print ("Up: %s - %s" % (h1, h2))

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
                #print ("Down: %s - %s" % (h1, h2))
        except:
            e = sys.exc_info()[0]
            print e
            pass

#This converts list to series
#bytes = pd.Series(pktBytes).astype(int)
bits = pd.Series(pktBits).astype(int)
usbits = pd.Series(uspktBits).astype(int)
dsbits = pd.Series(dspktBits).astype(int)

#Convert the timestamp list to a pd date_time
times = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors='coerce')
ustimes = pd.to_datetime(pd.Series(uspktTimes).astype(str),  errors='coerce')
dstimes = pd.to_datetime(pd.Series(dspktTimes).astype(str),  errors='coerce')

#Create the dataframe
#df  = pd.DataFrame({"Bytes": bytes, "Times":times})
df_bits = pd.DataFrame({"Bits": bits, "Times": times})
usdf_bits = pd.DataFrame({"Bits": bits, "Times": times})
dsdf_bits = pd.DataFrame({"Bits": bits, "Times": times})

#set the date from a range to an timestamp
#dsdf = dsdf.set_index('Times')
df_bits = df_bits.set_index('Times')
usdf_bits = usdf_bits.set_index('Times')
dsdf_bits = dsdf_bits.set_index('Times')

#Create a new dataframe of 2 second sums to pass to plotly
#df2=df.resample('1S').sum()
df2_bits = df_bits.resample('1S').sum()
usdf2_bits = df_bits.resample('1S').sum()
dsdf2_bits = df_bits.resample('1S').sum()

# plotly.offline.plot({
#    "data":[plotly.graph_objs.Scatter(x=df2_bits.index, y=df2_bits['Bits'])],
#        "layout":plotly.graph_objs.Layout(title="Downstream Bits over Time ",
#        xaxis=dict(title="Time"),
#        yaxis=dict(title="Bits"))})

sample_interval = 1
#tflows = traffic.elements()
print ("Traffic Top 10")
for (h1, h2), total in traffic.most_common(10):
    h1, h2 = map(ltoa, (h1, h2))
    print "Top 10 Flow: %s - %s" % (h1, h2)
    for host in (h1, h2):
        if host not in hosts:
            try:
                rhost = socket.gethostbyaddr(host)
                hosts[host] = rhost[0]
            except:
                hosts[host] = None
    h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
    h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
    print "%s/s: %s - %s" % (human(float(total)/sample_interval), h1, h2)

dsflows = []
dsflow_names = []
usflows = []
usflow_names = []

for (h1, h2), total in traffic.most_common():
    h1, h2 = map(ltoa, (h1, h2))
    #print "Flow: %s - %s" % (h1, h2)
    # Now check so see if it is a flow of interest
    dsflow, usflow = flowLists(h1,h2)
    dsflows.append(dsflow)
    usflows.append(usflow)
    flow_name = getFlowName(h1, h2)
    dsflow_names.append(flow_name)
    flow_name = getFlowName(h2,h1)
    usflow_names.append(flow_name)

usdfs = []
for flow in usflows:
    df = processFlow(flow)
    usdfs.append(df)
#usdfs.append(usdf2_bits)
plotflows(usdfs, usflow_names, "Upstream")

dsdfs = []
for flow in dsflows:
    df = processFlow(flow)
    dsdfs.append(df)
#dsdfs.append(dsdf2_bits)
plotflows(dsdfs, dsflow_names, "Downstream")
