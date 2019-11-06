import pandas as pd


# To create a CSV file (it can be opened in excel) from a dictionary

datapathid_to_name = {
						'Datapath': [123917682136897, 123917682136938, 123917682136941, 123917682136957, 123917682136955, 123917682136935],
						'Switch_Number': ['1', '2', '3', '4', '5', '6']
					}


mac_to_host = {
				'MAC_address': ['b8:27:eb:c2:10:5d', 'b8:27:eb:83:1b:e2'],
				'Name': ['h1', 'h2']
			}



datapath_df = pd.DataFrame(datapathid_to_name)
host_df = pd.DataFrame(mac_to_host)

datapath_df.to_csv("TESTBED/3rd_time/import_data/dpid_to_switch.csv")
host_df.to_csv("TESTBED/3rd_time/import_data/mac_to_host.csv")
