import pandas as pd
import csv



mac_to_host_df = pd.read_csv('TESTBED/3rd_time/import_data/mac_to_host.csv')
dpid_to_switch_df = pd.read_csv('TESTBED/3rd_time/import_data/dpid_to_switch.csv')

host_to_mac = dict(zip(mac_to_host_df['MAC_address'], mac_to_host_df['Name']))
datapathid_to_name = dict(zip(dpid_to_switch_df['Datapath'], dpid_to_switch_df['Switch_Number']))

for switch, num in datapathid_to_name.iteritems():
    datapathid_to_name[switch] = str(num)



'''sudo arp -d 10.10.5.103'''