from __future__ import division
import calendar
import time
import datetime
import ConfigParser
import getopt,sys
import threading
import logging
import logging.config
from logging.handlers import RotatingFileHandler
from pymongo import MongoClient
from ripe.atlas.cousteau import AtlasResultsRequest, ProbeRequest, Probe
from socket import socket
from datetime import datetime, timedelta
import csv
import os.path
import numpy
import multiprocessing
import threading

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


# Define a function getASNResults() to get built-in traceroute measurements for each ASN in list of source asns
# from RIPE servers
def getASNResults(asn, testid, start_time, stop_time):

    #msm_ids = 1009,1010,1011,1012,5009,5010,5011,5012
    msm_ids = 1013, 1012480
    rtt_average = 0
    rtt_mean = 0
    rtt_median = 0
    rtt_std = 0
    rtt_var = 0
    test_id = testid
    filters = {"id": test_id, "asn": asn}
    probe_list = []
    probes = []
    try:
        print('ProbeRequest')
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
    k= 10
    probe_list2 = probe_list[0:10]

    #p = multiprocessing.Process(target=getResults, args=(test_id, start_time, stop_time, probe_list2,))
    #p.start()
    #p.join(30)

    # Get the all the measurments of interest for these probes
    if len(probe_list2) > 0:
        kwargs = {
            "msm_id": test_id,
            "start": start_time,
            "stop": stop_time,
            "probe_ids": probe_list2
        }
        try:
            print('atlasRequest')
            is_success, results = AtlasResultsRequest(**kwargs).create()
        except:
            e = sys.exc_info()
            print('Error AtlasResultsRequest', str(e))
            return (0, 0, 0, 0, 0)
        if is_success:
            print('atlas success')
            try:
                rtt_list = []
                for res in results:
                    rtt_list.append(res['avg'])
                    # Convert to numpy array
                arr = numpy.array(rtt_list)
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
    return(rtt_average, rtt_mean, rtt_median, rtt_std, rtt_var)

csv_file = 'atlasdata.csv'
csv_columns = ['ASN', 'MSM_ID', 'Date', 'Timestamp', 'RTT', 'Mean', 'Median', 'Std', 'Var']

def doDay(asn, id, start, stop, r_file):
    with open(r_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        try:
            rtt_average, rtt_mean, rtt_median, rtt_std, rtt_var = getASNResults(asn, id, start, stop)
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
            print row_dict
        except:
            e = sys.exc_info()
            print ("Error", str(e))

def doAsn(asn):
    # print("Starting doAsn process for ",asn)
    results_file = 'atlasdata_6_' + str(asn) +'.csv'
    if os.path.isfile(results_file):
        os.remove(results_file)
    # 1013 = E-root server, 1012488 = Google
    msm_ids = 1013, 1009
    with open(results_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for id in msm_ids:
            for month in range(2,4):
                for day in range(1,30):
                    #print("ASN:"+str(asn)+" "+str(month) + "/" + str(day))
                    try:
                        start = datetime(2020, month, day, 0)
                        stop = datetime(2020, month, day+1, 0)
                        print("ASN:" + str(asn) + " " + str(month) + "/" + str(day) )
                        p = multiprocessing.Process(target=doDay, args=(asn, id, start, stop, results_file,))
                        p.start()
                        p.join(30)
                    except:
                        e = sys.exc_info()
                        print ("Error", str(e))
    print('Finished:', asn)

def main(argv):
    print('Network Dashboard Starting Up...')
    doAsn(3269)
    doAsn(7922)


    p = []

    #threadId = 0
    #ASNs = [7922, 22773, 20115, 6128, 30036, 10796, 11351, 11426, 11427, 12271, 20001, 19108, 11492, 30722,  1267, 12874]
    #ASNs = [7922, 3269] #30036, 10796, 11351, 11426, 11427, 12271, 20001, 19108, 11492, 30722, 1267, 12874]
    #for i in ASNs:
     #   p.append(threading.Thread(target=doAsn, args=(i,)))
     #   p[threadId].start()
      #  threadId = threadId + 1
    #threadId = 0
    #for i in ASNs:
    #    p[threadId].join()
    #    threadId = threadId + 1
    print("All Finished")
    # p = multiprocessing.Process(target=doAsn, args=(7922,))
    #p.start()

    print("All Finished")

if __name__ == '__main__':
    main(sys.argv[1:])
