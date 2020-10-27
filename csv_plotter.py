import pandas as pd
from datetime import datetime
import os

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
asn[7018] = 'ATT'
asn[20057] = 'ATT'
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

ASNs = [7922, 22773, 20115, 6128, 7018, 20057, 3549, 209, 21928,701]

def getNetworkName(net_number):
    name = asn[net_number]
    return name

def plotRtts(df):
    import plotly.graph_objs as go
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df.index, y=df['RTT'], name='Asn'))

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
        try:
            df = dfs[asn]
            fig.add_trace(go.Scatter(x=df.index, y=df['Rtt'], name=getNetworkName(asn)))
        except:
            pass  # do nothing since no DF for that ASN was created

    fig.update_layout(
        title="Avg RTT",
        xaxis_title = "Time",
        yaxis_title = "RTT, mSec",
        legend_title = 'ASN'
    )
    fig.show()

import csv
def main(argv):
    directory = "/Users/mtooley/PycharmProjects/untitled"
    dfs = {} # empty dict
    for filename in os.listdir(directory):
        if filename.startswith("df") and filename.endswith(".csv"):
            with open(filename) as f:
                csv_reader = csv.reader(f)
                row1 = next(csv_reader) # read the first row
                row2 = next(csv_reader) # read row 2
                #network = int(row2[0])
                fn_list1 = filename.split(".")
                fn1 = fn_list1[0]
                fn2 = fn1.split("_")
                network = int(fn2[1])
            data = pd.read_csv(filename)
            df = pd.DataFrame(data, columns=['Times','Rtt'])
            # set the date from a range to a timestamp
            df = df.set_index('Times')
            # Create a new data frame of 1 hour sums to pass to plotly
            #df2 = df.resample('1H').sum()
            dfs[network] = df
    
    # Plot the RTTs
    plotDfs(dfs)

if __name__ == '__main__':
    main(sys.argv[1:])
