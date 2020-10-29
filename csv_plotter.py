import pandas as pd
from datetime import datetime
import os
import sys
#import matplotlib.pyplot as plt


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
NA_ASNs = [6128, 20057, 7018, 209, 20115, 7922, 22773,  3549, 21928,701]
EU_ASNs = [5607, 2856, 12576, 13285, 3352, 12479, 12430, 1136, 33915, 6830]
ASIA_ASN = [2516, 17676,4713, 55836, 38266, 45271]

def getNetworkName(net_number):
    name = asn[net_number]
    return name

def plotRtts(df,network):
    import plotly.graph_objs as go
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df.index, y=df['Rtt'], name= str(network)))

    fig.update_layout(
        title= str(network),
        xaxis_title = "Time",
        yaxis_title = "RTT, mSec",
    )
    fig.show()

def plotDfs(dfs, ASNs, col, plottitle, linetype):
    import plotly.graph_objs as go
    fig = go.Figure()
    for asn in ASNs:
        try:
            df = dfs[asn]
            fig.add_trace(go.Scatter(x=df.index,
                                     y=df[col],
                                     name=getNetworkName(asn),
                                     mode=linetype
                                     )
                          )
        except:
            pass  # do nothing since no DF for that ASN was created

    fig.update_layout(
        title={
            'text': plottitle
        },
        xaxis_title = "Time",
        yaxis_title = "Avg. RTT, mSec",
        legend_title = 'Network',
        legend=dict(
            yanchor='top',
            y=0.99,
            xanchor='left',
            x=0.01
        ),
        xaxis_tickformat = '%d %B (%a)'
    )
    fig.update_xaxes(tickangle=45)
    fig.show()


def plotDF(df):
    df.plot()
    plt.show()

import csv
def main(argv):
    directory = "/Users/mtooley/PycharmProjects/untitled"
    dfs = {} # empty dict
    df1 = pd.DataFrame()
    for filename in os.listdir(directory):
        if filename.startswith("df") and filename.endswith(".csv"):
            print filename
            fn_list1 = filename.split(".")
            fn1 = fn_list1[0]
            fn2 = fn1.split("_")
            network = int(fn2[1])
            data = pd.read_csv(filename)
            df = pd.DataFrame(data, columns=['Times','Rtt'])
            # set the date from a range to a timestamp
            df['MA'] = df.Rtt.rolling(24*7).mean()
            df = df.set_index('Times')
            #df['MA_72'] = df.rolling(window=72, min_periods=1).mean()
            # Create a new data frame of 1 hour sums to pass to plotly
            #df2 = df.resample('1H').sum()
            dfs[network] = df
            # Plot the RTTs
            #plotRtts(df, network)


    plotDfs(dfs, NA_ASNs, "Rtt","North America RTT", "lines+markers")
    plotDfs(dfs, NA_ASNs, "MA", "North America 7-Day Moving Average", "lines")
    plotDfs(dfs, EU_ASNs, "MA", "Europe 7-Day Moving Average", "lines")
    plotDfs(dfs, ASIA_ASN, "MA", "ASIA 7-Day Moving Average", "lines")

if __name__ == '__main__':
    main(sys.argv[1:])
