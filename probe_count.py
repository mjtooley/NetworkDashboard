from __future__ import division

from ripe.atlas.cousteau import AtlasResultsRequest, ProbeRequest, Probe
import pandas as pd

import plotly.express as px

ASNs = [7922, 22773, 20115, 6128, 30036, 10796, 11351, 11426, 11427, 12271, 20001, 7018, 20057, 3549, 209, 22561, 3356, 3549,21928, 30036, 10796, 11351, 11426,11427, 12271, 20001,
        19108, 22561, 11492,5607, 2856, 12576, 13285, 3352, 12479, 12430, 1136, 33915, 6830, 2516, 17676,4713, 9605, 55836, 45609, 38266, 45271]

def getNetworkName(net_number):
    asn ={}
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
    asn[20057] = 'ATT W/L'
    asn[701] = 'Verizon'
    asn[702] = 'Verizon'
    asn[2828] = 'Verizon'
    asn[209] = 'CenturyLink'
    asn[22561] = 'CenturyLink'
    asn[3356] = 'Lumen/L3'
    asn[3549] = 'Lumen/L3'
    asn[6939] = 'Hurricane Electric'
    asn[174] = 'Cogent'
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
    asn[4713] = 'NTT'
    asn[9605] = 'Docomoco'
    asn[55836] = 'Reliant-IN'
    asn[45609] = 'Bharti'
    asn[38266] = 'Vodafone'
    asn[45271] = ' Idea Cellular'

    name = asn[net_number]
    return name

def getProbeCount(network):
    filters = {"id": 1004, "asn": network}
    probes = []
    probe_list = []
    try:
        probes = ProbeRequest(**filters)
        if probes:
            probe = probes.next()
            #for probe in probes:
            #    probe_list.append(probe["id"])  # add the probe ID to the list
            count = probes.total_count
            name = getNetworkName(network)
            print ('ASN:' + str(network) + " " + name + ' count:' + str(count))
    except:
        #print "error getting probes", probes
        count = 0
    return str(network), count


pc = {}
for asn in ASNs:
    network, count = getProbeCount(asn)
    pc[getNetworkName(int(network))] = count

df = pd.DataFrame(list(pc.items()), index=range(len(pc)))
df.columns = ['Network', 'Probe Count']
print(df)

fig = px.bar(df,x='Network', y='Probe Count')
fig.update_xaxes(type='category')
fig.show()
