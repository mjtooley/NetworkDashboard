from __future__ import division
import calendar
import time
from datetime import datetime, timedelta
from ripe.atlas.cousteau import AtlasResultsRequest, ProbeRequest, Probe
import csv
import os.path
import numpy

import pandas as pd
from scapy.all import *


asn = dict()
asn[7922] = 'Comcast'
asn[22773] = 'Cox'
asn[6128] = 'AlticeUSA'
asn[30036] = 'Mediacom'
asn[20115] = 'Charter'
asn[10796] = 'Charter'
asn[11351] = 'Charter'
asn[11426] = 'Charter'
asn[11427] = 'Charter'
asn[12271] = 'Charter'
asn[20001] = 'Charter'
asn[19108] = 'AlticeUSA'
asn[7018] = 'ATT Internet4'
asn[20057] = 'ATT W/L'
asn[701] = 'Verizon'
asn[702] = 'Verizon'
asn[2828] = 'Verizon'
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

def getNetworkName(net_number):
    name = asn[net_number]
    return name

def totimestamp(dt, epoch=datetime(1970,1,1)):
    td = dt - epoch
    # return td.total_seconds()
    return(td.microseconds + (td.seconds + td.days * 86400))

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

def getProbeCount(asn):
    filters = {"id": 1009, "asn": asn}
    probes = []
    probe_list = []
    try:
        probes = ProbeRequest(**filters)
        try:
            if probes:
                for probe in probes:
                    probe_list.append(probe["id"])  # add the probe ID to the list
        except:
            e = sys.exc_info()
            print ("Probe error", str(e))

        print ('ASN:' + str(asn) + " " + 'count:' + str(len(probe_list)))
    except:
        print "error getting probes", probes

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


# Define a function getASNResults() to get built-in traceroute measurements for each ASN in list of source asns
# from RIPE servers
def getASNResults(asn, testid, start_time, stop_time, probe_list):
    # Get the all the measurments of interest for these probes
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
        if is_success:
            try:
                rtt_avg_list = []
                rtt_list = []
                for res in results:
                    rtt_avg_list.append(res['avg']) # append the average to the list of averages
                    result_rtt_list = res['result']
                    for rtt in result_rtt_list:
                        rtt_list.append(rtt)
                # Convert to numpy array
                arr = numpy.array(rtt_avg_list)
                rtt_average = numpy.average(arr)
                rtt_mean = numpy.mean(arr)
                rtt_median = numpy.median(arr)
                rtt_std  = numpy.std(arr)
                rtt_var = numpy.var(arr)
            except:
                rtt_average = 0
                rtt_mean = 0
                rtt_median = 0
                rtt_std = 0
                rtt_var = 0
                e = sys.exc_info()
                print('Error AtlasRequestResults2', str(e))
        else:
            print('AtlasRequestResultsNotSuccessful')
            rtt_average = 0
            rtt_mean = 0
            rtt_median = 0
            rtt_std = 0
            rtt_var = 0
            rtt_list = []
    return(rtt_average, rtt_mean, rtt_median, rtt_std, rtt_var, rtt_list)

csv_file = 'atlasdata.csv'
csv_columns = ['ASN', 'MSM_ID','Date','Timestamp', 'RTT', 'Mean', 'Median', 'Std', 'Var']

def plotRtts(df):
    import plotly.graph_objs as go
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df.index, y=df['Rtt'], name='Asn'))

    fig.update_layout(
        title="Avg RTT",
        xaxis_title = "Time",
        yaxis_title = "RTT, mSec",
    )
    fig.show()

def plotDfs(dfs):
    import plotly.graph_objs as go
    fig = go.Figure()
    for asn in ASNs:
        df = dfs[asn]
        fig.add_trace(go.Scatter(x=df.index, y=df['Rtt'], name=getNetworkName(asn)))

    fig.update_layout(
        title="Average Round Trip Time from Atlas Probes to F-Root-Server",
        xaxis_title = "Time",
        yaxis_title = "Avg. RTT, mSec",
        legend_title = 'ASN'
    )
    fig.show()


def doDay(asn, id, start, stop, r_file):
    rtt_average, rtt_mean, rtt_median, rtt_std, rtt_var, rtt_list = getASNResults(asn, id, start, stop)
    with open(r_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        try:
            #rtt_average, rtt_mean, rtt_median, rtt_std, rtt_var, rtt_list = getASNResults(asn, id, start, stop)
            # Prep row for CSV File
            row_dict = {}
            row_dict['ASN'] = asn
            row_dict['MSM_ID'] = id
            # row_dict['Date'] = start.strftime('%m/%d/%Y,%H:%M:%S')
            row_dict['Timestamp'] = totimestamp(start)
            row_dict['RTT'] = rtt_average
            row_dict['Mean'] = rtt_mean
            row_dict['Median'] = rtt_median
            row_dict['Std'] = rtt_std
            row_dict['Var'] = rtt_var
            writer.writerow(row_dict)
            print row_dict
        except:
            e = sys.exc_info()
            print ("Error", str(e))
    # now write out all the RTTs to a sescond CSV file
    r_file2 = r_file.split('.')
    r_file2 = r_file2[0]
    r_file2 = r_file2 +"_all" + ".csv"
    with open(r_file2,'w') as csvfile:
        writer = csv.DictWriter(csvfile,fieldnames = ['RTT'] )
        try:
            row_dict = {}
            for rtt in rtt_list:
                row_dict['RTT'] = rtt
                writer.writerow(row_dict)
        except:
            e = sys.exc_info()
            print("error", str(e))

def doAsn(asn):
    asn_rtts = []
    asn_times = []
    print("Starting doAsn process for " + str(asn))
    results_file = 'atlasdata_nov_' + str(asn) +'.csv'
    if os.path.isfile(results_file):
        os.remove(results_file)

    start = datetime(2020,2,1,0)
    csvfile = open(results_file, 'w')
    writer = csv.DictWriter(csvfile, fieldnames=['ASN', 'MSM_ID','Date','Timestamp', 'RTT', 'Mean', 'Median', 'Std', 'Var'])
    writer.writeheader()

    r_file2 = 'atlasdata_nov_raw' + str(asn) + '.csv'
    csvfile2 =  open(r_file2, 'w')
    writer2 = csv.DictWriter(csvfile2, fieldnames=['Timestamp', 'RTT'])
    writer2.writeheader()

    id = 1004 # 1001 = K (anycast), 1004 = F (ISC anycast), 1013 = E-root server, 1012488 = Google
    probe_list = getProbeList(asn, id)
    for count in range(0,24*120): # number of hours
        stop = start + timedelta(hours=1)
        print("ASN:" + str(asn) + " " + start.strftime('%m/%d/%Y,%H:%M:%S'))
        try:
            rtt_average, rtt_mean, rtt_median, rtt_std, rtt_var, rtt_list = getASNResults(asn, id, start, stop,probe_list)
            # Prep row for CSV File
            row_dict = {}
            row_dict['ASN'] = asn
            row_dict['MSM_ID'] = id
            row_dict['Date'] = start.strftime('%m/%d/%Y,%H:%M:%S')
            row_dict['Timestamp'] = totimestamp(start)
            row_dict['RTT'] = rtt_average
            row_dict['Mean'] = rtt_mean
            row_dict['Median'] = rtt_median
            row_dict['Std'] = rtt_std
            row_dict['Var'] = rtt_var
            writer.writerow(row_dict)
            asn_rtts.append(rtt_average)
            asn_times.append(start.strftime("%Y-%m-%d %H:%M:%S.%f"))
            # print row_dict
        except:
            e = sys.exc_info()
            print ("Error", str(e))

            # now write out all the RTTs to a sescond CSV file
        try:
            row_dict2 = {}
            for rtt in rtt_list:
                row_dict2['RTT'] = rtt['rtt']
                row_dict2['Timestamp'] = totimestamp(start)
                writer2.writerow(row_dict2)
                #print row_dict2
        except:
            e = sys.exc_info()
            print("error", str(e))

        start = stop # bump the start by an hour


    # Convert lists to series
    rtts = pd.Series(asn_rtts).astype(int)
    times = pd.to_datetime(pd.Series(asn_times).astype(str), errors='coerce')
    # Create dataframe
    df = pd.DataFrame({"Rtt": rtts,"Times": times})
    # set the date from a range to a timestamp
    df = df.set_index('Times')
    # Create a new data frame of 1 hour sums to pass to plotly
    df2 = df.resample('1H').sum()
    # Plot the graph
    # plotRtts(df2)
    fn2 = results_file = 'df_' + str(asn) +'.csv'
    df.to_csv(fn2,index=True)
    return(df2) # return the data frame
    print('Finished:', asn)

#ASNs = [7922, 22773, 20115, 6128, 7018, 20057, 22394, 3549, 209, 21928]
#ASNs = [7922,22773,20115, 6128, 7018, 20057, 3549, 209, 21928,701,22561]
ASNs = [5607, 2856, 12576, 13285, 3352, 12479, 12430, 1136, 33915, 6830, 2516, 17676,
        4713, 9605, 55836, 45609, 38266, 45271]

#ASNs = [7922, 22773]
def main(argv):
    print('Network Dashboard Starting Up...')
    for asn in ASNs:
        getProbeCount(asn)
        #doAsn(asn)

    df = doAsn(7922)

#    rtt_dfs = {} # empty dict
#    for asn in ASNs:
#        df = doAsn(asn)
#        rtt_dfs[asn] = df
#    plotDfs(rtt_dfs)

    p = []
    threadId = 0
    for i in ASNs:
        p.append(threading.Thread(target=doAsn, args=(i,)))
        p[threadId].start()
        threadId = threadId + 1

    for i in range(threadId-1):
        p[i].join()

    print("All Finished")

if __name__ == '__main__':
    main(sys.argv[1:])
