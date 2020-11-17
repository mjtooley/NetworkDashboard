from __future__ import division
import calendar
import time
from datetime import datetime, timedelta
from ripe.atlas.cousteau import AtlasResultsRequest, ProbeRequest, Probe
import csv
import os.path
import numpy as np
import sys
import pandas as pd
import pygeoip
import re
import threading

asn = dict()
asn[7922] = 'Comcast'
asn[22773] = 'Cox'
asn[20115] = 'Charter'
asn[6128] = 'AlticeUSA'
asn[30036] = 'Mediacom'
asn[10796] = 'Charter'
asn[11351] = 'Charter'
asn[11426] = 'Charter'
asn[11427] = 'Charter'
asn[12271] = 'Charter'
asn[20001] = 'Charter'
asn[19108] = 'AlticeUSA'
asn[7018] = 'ATT Internet4'
asn[20057] = 'ATT Wireless'
asn[2685] = 'ATT Global Services'
asn[701] = 'Verizon'
asn[702] = 'Verizon'
asn[2828] = 'Verizon Wireless'
asn[209] = 'CenturyLink'
asn[22561] = 'CenturyLink'
asn[6939] = 'Hurricane Electric'
asn[174] = 'Cogent'
asn[3549] = 'Level 3'
asn[5650] = 'Frontier'
asn[11492] = 'CableOne'
asn[21928] = 'T-Mobile'
asn[19129] = 'Vistabeam-net'
asn[394883] = 'Vistabeam'
asn[5607] = 'sky-uk'
asn[2856] = 'BT'
asn[12576] = 'Orange-UK'
asn[13285] = 'TalkTalk'
asn[3352] = 'Telefonica-Spain'
asn[12479] = 'Orange-Spain'
asn[12430] = 'Vodafone-Spain'
asn[1136] = 'KPN'
asn[33915] = 'vodafone-nl'
asn[6830] = 'LibertyGlobal'
asn[2516] = ' KDDI-JP'
asn[17676] = 'Softbank'
asn[4713] =  'NTT'
asn[9605] = 'Docomoco'
asn[55836] = 'Reliant-IN'
asn[45609] = 'Bharti'
asn[38266] = 'Vodafone'
asn[45271] = ' Idea Cellular'

TESTASN = [7922, 6128]
NA_ASNs = [7922,6128, 20057, 7018, 209, 20115, 7922, 22773,  3549, 21928,701]
EU_ASNs = [5607, 2856, 12576, 13285, 3352, 12479, 12430, 1136, 33915, 6830]
ASIA_ASN = [2516, 17676,4713, 55836, 38266, 45271]

class Asn:
    def __index__(self):
        self.asn = dict()
        self.asn['7922'] = 'Comcast'
        self.asn['22773'] = 'Cox'
        self.asn['20115'] = 'Charter'
        self.asn['6128'] = 'AlticeUSA'
        self.asn['30036'] = 'Mediacom'
        self.asn['10796'] = 'Charter'
        self.asn['11351'] = 'Charter'
        self.asn['11426'] = 'Charter'
        self.asn['11427'] = 'Charter'
        self.asn['12271'] = 'Charter'
        self.asn['20001'] = 'Charter'
        self.asn['19108'] = 'AlticeUSA'
        self.asn['7018'] = 'ATT'
        self.asn['20057'] = 'ATT'
        self.asn['701'] = 'Verizon'
        self.asn['702'] = 'Verizon'
        self.asn['22394'] = 'Verizon Wireless'
        self.asn['209'] = 'CenturyLink'
        self.asn['22561'] = 'CenturyLink'
        self.asn['26868'] = 'NCTA'
        self.asn['6939'] = 'Hurricane Electric'
        self.asn['174'] = 'Cogent'
        self.asn['3549'] = 'Level 3'
        self.asn['5650'] = 'Frontier'
        self.asn['11492'] = 'CableOne'

def getAsn(ip):
    as_name = 'none'  # default
    gi_asn = pygeoip.GeoIP('GeoIPASNum.dat')
    asn_name = gi_asn.asn_by_addr(ip)
    asn = None
    if asn_name:
        names = str(asn_name).split()
        try:
            asn = int(re.sub('[^0-9]', '', names[0]))  # Parse out the leadign number
        except:
            asn = None
        del names[0]  #
        as_name = ' '.join(names)  # Re-assemble the ASN Name withouth the leading number
    return asn, as_name

def totimestamp(dt, epoch=datetime(1970,1,1)):
    td = dt - epoch
    # return td.total_seconds()
    return(td.microseconds + (td.seconds + td.days * 86400))

def getProbeList(asn, test_id):
    filters = {"id": test_id, "asn": asn}
    probe_list = []
    probes = []
    try:
        probes = ProbeRequest(**filters)
    except:
        print "error getting probes", probes

    try:
        if probes:
            for probe in probes:
                probe_list.append(probe["id"])  # add the probe ID to the list
    except:
        e = sys.exc_info()
        print ("Probe error", str(e))
        probe_list = []

    # For testing get the first 10 probes
    k= 50
    probe_list2 = probe_list[0:10]
    return probe_list2


def getResults(test_id,start_time,stop_time,probe_list):
    is_success = False
    kwargs = {
        "msm_id": test_id,
        "start": start_time,
        "stop": stop_time,
        "probe_ids": probe_list
    }
    is_success, results = AtlasResultsRequest(**kwargs).create()
    return(is_success, results)

def getTraceRtResults(asn, testid, start_time, stop_time, probe_list):
    lmr = []
    tr_rtt = []
    isp_hops = []
    tr_hops = []
    # Get the all the measurments of interest for these probes
    dict = {'Timestamp': [],
            'Lastmile_hops':[],
            'Lastmile': [],
            'Lastmile_median': [],
            'Lastmile_max': [],
            'Lastmile_min': [],
            'Lastmile_ste': [],
            'TraceRt_rtt': [],
            'TraceRt_rtt_median': [],
            'TraceRt_rtt_max': [],
            'Tracert_rtt_min': [],
            'Tracert_rtt_std': [],
            'Tracert_hops': []
            }
    df = pd.DataFrame(dict)
    if len(probe_list) > 0:
        kwargs = {
            "msm_id": 5004,
            "start": start_time,
            "stop": stop_time,
            "probe_ids": probe_list
        }
        try:
            is_success, results = AtlasResultsRequest(**kwargs).create()
        except:
            e = sys.exc_info()
            print('Error AtlasResultsRequest', str(e))
            return (0, 0, 0, 0, 0)
        if is_success:
            try:

                for result in results:
                    try:
                        timestamp, last_mile_rtt, traceRt_rtt, total_hops, isp_hops2 = find_first_hop_rtt(result)
                        lmr.append(last_mile_rtt)
                        tr_rtt.append(traceRt_rtt)
                        isp_hops.append(isp_hops2)
                        tr_hops.append((total_hops))
                    except:
                        e = sys.exc_info()
                        print ("Error getting first hop RTT", str(e))
                        pass
            except:
                e = sys.exc_info()
                print('Error processing tracert results', str(e))
    if len(lmr) > 0:
        lmr_a =np.array(lmr)
        tr_a = np.array(tr_rtt)
        isp_hops_a = np.array(isp_hops)
        tr_hops_a = np.array(tr_hops)

        df2 = {'Timestamp': start_time,
               'Lastmile_hops': np.mean(isp_hops_a),
               'Lastmile': np.mean(lmr_a),
               'Lastmile_median': np.median(lmr_a),
               'Lastmile_max': np.max(lmr_a),
               'Lastmile_min': np.min(lmr_a),
               'Lastmile_ste': np.std(lmr_a),
               'TraceRt_rtt': np.mean(tr_a),
               'TraceRt_rtt_median': np.median(tr_a),
               'TraceRt_rtt_max': np.max(tr_a),
               'Tracert_rtt_min': np.min(tr_a),
               'Tracert_rtt_std': np.std(tr_a),
               'Tracert_hops': np.mean(tr_hops_a)
               }
    else:
         df2 = {'Timestamp': start_time,
               'Lastmile_hops': 0,
               'Lastmile': 0,
               'Lastmile_median': 0,
               'Lastmile_max': 0,
               'Lastmile_min': 0,
               'Lastmile_ste': 0,
               'TraceRt_rtt': 0,
               'TraceRt_rtt_median': 0,
               'TraceRt_rtt_max': 0,
               'Tracert_rtt_min': 0,
               'Tracert_rtt_std': 0,
               'Tracert_hops': 0
               }
    df = df.append(df2, ignore_index=True)  # Append row to DF
    return (df)

def getPingResults(asn, testid, start_time, stop_time, probe_list):
    # Get the all the measurments of interest for these probes
    dict = {
            'Timestamp': [],
            'Ping_Average': [],
            'Ping_median': [],
            'Ping_max': [],
            'Ping_min': [],
            'Ping_Std':[]
            }
    df = pd.DataFrame(dict)
    if len(probe_list) > 0:
        kwargs = {
            "msm_id": testid,
            "start": start_time,
            "stop": stop_time,
            "probe_ids": probe_list
        }
        try:
            is_success, results = AtlasResultsRequest(**kwargs).create()
        except:
            e = sys.exc_info()
            print('Error AtlasResultsRequest', str(e))
            return (0, 0, 0, 0, 0)
        list = []
        if is_success:
                try:
                    for res in results:
                        for i in range(len(res['result'])):
                            try:
                                rtt = res['result'][i]['rtt']
                            except:
                                rtt = 0
                                pass
                            list.append(rtt)
                except:
                    e = sys.exc_info()
                    error_message = 'Error processing ping results, start: ' + str(start_time) + " stop: " + str(stop_time)
                    print(error_message, str(e))
                    print(res)

    if len(list) > 0:
        arr = np.array(list)
        #asn_times.append(start.strftime("%Y-%m-%d %H:%M:%S.%f"))
        #times = pd.to_datetime(pd.Series(asn_times).astype(str), errors='coerce')


        df2 = {
            'Timestamp': start_time,
            'Ping_Average': res['avg'],
            'Ping_median': np.median(arr),
            'Ping_max': np.max(arr),
            'Ping_min': np.min(arr),
            'Ping_Std': np.std(arr)
        }
    else:
        x_time = start_time.strftime("%Y-%m-%d %H:%M:%S.%f")
        df2 = {
            'Timestamp': x_time,
            'Ping_Average': res['avg'],
            'Ping_median': 0,
            'Ping_max': 0,
            'Ping_min': 0,
            'Ping_Std': 0
        }
    df = df.append(df2, ignore_index=True)  # Append row to DF
    return(df)

# Define a function getASNResults() to get built-in traceroute measurements for each ASN in list of source asns
# from RIPE servers
def getASNResults(asn, testid, start_time, days, probe_list):
    df_pings = pd.DataFrame()
    df_tracert = pd.DataFrame()
    # Get the all the measurments of interest for these probes
    stop = start_time + timedelta(hours=1)
    for hours in range(days):
        # Get Traceroute results
        if len(probe_list) > 0:
            df_tr = getTraceRtResults(asn, 5004, start_time, stop, probe_list)
            # Get Ping Results
            df_ping = getPingResults(asn, 1004, start_time, stop, probe_list)
            # append the dataframes
            if df_pings.empty:
                df_pings = df_ping.copy(deep=True)
            else:
                df_pings = df_pings.append(df_ping, ignore_index=True)
            if df_tracert.empty:
                df_tracert = df_tr.copy(deep=True)
            else:
                df_tracert = df_tracert.append(df_tr, ignore_index=True)

            #print("Traceroutes:", df_pings.head())
            #print("Pings:", df_tracert.head())

        start_time = stop
        stop = start_time + timedelta(hours=1)
    print("ready to merge DFs")
    # Merge DFs
    df_results = pd.merge(df_tracert, df_pings, on = "Timestamp", how="inner")
    # print(df_results.head())

    return(df_results)

def find_first_hop_rtt(res):
    RTT_med = 0
    last_mile_RTT = 0
    tr_rtt = 0
    hop_no = 0
    list = []
    new_count = 0
    counter = 0
    prev_asn_name = " "
    j=0
    Total_h = len(res['result']) # Get number of hops

    if res['result'][Total_h - 1]['hop'] != 255:
        for i in range(0, Total_h):
            try:
                hop_ip = res['result'][i]['result'][0]['from']
                new_count += 1
                now_asn, inter_network_name = getAsn(hop_ip)
                if j == 0:
                    prev_asn_name = inter_network_name
                    j = 1
                else:
                    if prev_asn_name != inter_network_name and counter < 1 and now_asn is not None:
                        hop_no = i
                        counter = 1
                        name = prev_asn_name
                        last_mile_RTT = RTT_med            # find the edge
                        description = inter_network_name  # ISP Name

                if prev_asn_name != inter_network_name and counter == 1 and now_asn is not None:
                    isp_hops = i
                    rtt1 = res['result'][isp_hops]['result'][0]['rtt']
                    rtt2 = res['result'][isp_hops]['result'][1]['rtt']
                    rtt3 = res['result'][isp_hops]['result'][2]['rtt']
                    tr_rtt = (rtt1 + rtt2 + rtt3)/3

                rtt = []
                pack_size = res['result'][i]['result'][0]['size']
                rtt.append(res['result'][i]['result'][0]['rtt'])
                rtt.append(res['result'][i]['result'][1]['rtt'])
                rtt.append(res['result'][i]['result'][2]['rtt'])   # find RTT for all three packets
                RTT_med = sorted(rtt)[len(rtt) // 2]               # find the RTT median
                dest_name=inter_network_name
                prev_asn = now_asn
                prev_asn_name = inter_network_name

            except KeyError: # the traceroute result is **** indicating unknown, so skip.
                    pass

    timestamp = res['timestamp']
    total_hops = Total_h
    isp_hops = hop_no
    return(timestamp,last_mile_RTT,tr_rtt, total_hops, isp_hops)



def plotDf(df,title ):
    import plotly.graph_objs as go
    df.set_index("Timestamp")
    fig = go.Figure()
#    fig.add_trace(go.Scatter(x=df["Timestamp"], y=df["Ping_Average"], name= "Ping Avg."))
    fig.add_trace(go.Scatter(x=df["Timestamp"], y=df["Ping_median"], name="Ping Median"))
#    fig.add_trace(go.Scatter(x=df["Timestamp"], y=df["Lastmile"], name="Lastmile Avg."))
    fig.add_trace(go.Scatter(x=df["Timestamp"], y=df["Lastmile_median"], name="Lastmile median"))
#    fig.add_trace(go.Scatter(x=df["Timestamp"], y=df["TraceRt_rtt"], name="Traceroute Avg."))
    fig.add_trace(go.Scatter(x=df["Timestamp"], y=df["TraceRt_rtt_median"], name="Traceroute median"))

    fig.update_layout(
        title= title,
        xaxis_title = "Time",
        yaxis_title = "RTT, mSec"
    )

    fig.update_layout(
        title={
            'text': title
        },
        xaxis_title = "Time",
        yaxis_title = "Avg. RTT, mSec",
        legend_title = 'Measurement',
        xaxis_tickformat = '%Y-%m-%dT%H:%M'
    )
    fig.update_xaxes(tickangle=45)

    fig.show()


asn = 6128
id = 5004 # Traceroutes 50xx
def doASN(n):
    print("Doing ASN " + str(n))
    start = datetime(2020,3,10,0)
    stop = start + timedelta(hours=1)
    n_days = 14
    stop = n_days*24  # number of days x 24 hours

    probe_list = getProbeList(n, id)
    df = getASNResults(n, id, start, stop, probe_list)
    print(df['Lastmile'].describe())
    print(df['TraceRt_rtt'].describe())
    print(df.head(5))
    filename = str(n)+'_ping_traceroute.csv'
    df.to_csv(filename)

    # plot the dataframe
    #title = str(n) + " Round Trip Times"
    #plotDf(df,title=title)


def main(argv):
    print('Starting Up...')
    testasns = [6128,7922]
    #doASN(testasns)
    p = []
    threadId = 0
    for i in testasns:
        p.append(threading.Thread(target=doASN, args=(i,)))
        p[threadId].start()
        threadId = threadId + 1

    for i in range(threadId-1):
        p[i].join()

    print("All Finished")

if __name__ == '__main__':
    main(sys.argv[1:])
