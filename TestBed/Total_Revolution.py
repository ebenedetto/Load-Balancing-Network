# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp, udp
from ryu.lib.packet.packet import Packet
from ryu.topology.api import get_switch, get_link, get_host
from ryu.topology import event, switches
import networkx as nx
from ryu.app.ofctl.api import get_datapath
from ryu.lib import hub
from collections import defaultdict
import time
import json
import matplotlib.pyplot as plt
import logging
import threading
import realtimeplt as rtp
from edgestats import EdgeStats
import numpy as np
import pandas as pd
import csv
import datetime


plt.ion()		# Plot in interactive mode


DEFAULT_WEIGHT = 1
NUMBER_OF_SWITCH_PORTS = 3		# To be set according to the topology
SLEEP = 8
WAIT_FOR_STATISTICS = 1
SLEEP_TH = WAIT_FOR_STATISTICS + SLEEP * 2		# How often the threshold on each link is monitored. If you want to modify it, only the numerical number can be changed
MAGNITUDE_MEGA_BYTES = 10**6
MAGNITUDE_KILO_BYTES = 10**3
LINK_THRESHOLD = 2 * MAGNITUDE_MEGA_BYTES
MAG_STR = "MByte"
MAX_RTT_ADMITTED = 2
PKT_IN_STOP_TIMER = 20
MIN_FLOW_BW = 0.3*MAGNITUDE_MEGA_BYTES		# We don't plot connections with bandwidth lower than this bandwidth


class LoadBalancingSwitch(app_manager.RyuApp):
	"""Load balancing SDN controller.
	
	Attributes
	----------
	app_manager.RyuApp : class
		Base class for Ryu applications

	Methods
	-------
	_monitor()
		Thread that periodically sends statistics requests to switches
	_monitor_threshold()
		Thread that periodically checks if the threshold has been exceeded in any of the links
	reallocate_flow(link_above_th)
		Finds the lowest effort flow and reallocates it
	switch_features_handler(ev)
		Installs the table-miss in a switch
	_packet_in_handler(ev)
		Handles a packet according to its type

	"""
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}


	def __init__(self, *args, **kwargs):
		"""
		Parameters
		----------
		net : networkx DiGraph
			Empty directed graph
		pos : networkx graph layout
			x and y coordinates of the nodes in the network
		topo_init : bool
			True if the topology was started
		reallocated : bool
			Used to make sure that just one flow on one link is reallocated for each loop of the thread `monitor_thread`
		datapaths : dict
			Maps a switch's datapath ID to its full datapath
		mac_to_port : dict
			{datapath ID: {MAC address : port}}
		mac_to_dpid : dict
			Maps a host's MAC address to the datapath ID of the switch it's connected to
		port_to_mac : dict
			{datapath ID: {port : MAC address}}
		ip_to_mac : dict
			{IP address: MAC address}
		edge_stats : dict
			Maps a link to its class
		match_path_and_prio : dict
			Maps a flow's match to the path it's routed on and its priority
		switch_to_hosts_mac : dict
			Maps each switch to the list of their connected hosts' MACs
		hosts_dict : dict
			Maps each switch to its list of hosts, of type dict
		port_occupied : defaultdict
			{switch: {switch port : 0/1}}
		pkt_in_just_served : defaultdict
			Maps each flow to a boolean value
		net_percentages : defaultdict
			{idle : [], below : [], over : []}
		table_rows_labels : list
			Contains the labels of all the active matches in the network
		table_columns_labels : list
			Contains all the links (tuples) as labels for the table 
		table_data : list of lists
			Matrix with the data used to populate the table
		monitor_thread : hub.spawn(_monitor)
			Thread that monitors statistics
		threshold_thread : hub.spawn(_monitor_threshold)
			Thread that monitors if the threshold has been exceeded
		first_pkt_in : bool
		
		datapathid_to_name : dict

		host_to_mac : dict

		"""
		super(LoadBalancingSwitch, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.pos = 0
		self.topo_init = False
		self.reallocated = False
		self.datapaths = {}
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.ip_to_mac = {}
		self.edge_stats = {}
		self.match_path_and_prio = {}
		self.switch_to_hosts_mac = {}
		self.hosts_dict = {}
		self.port_occupied = defaultdict(lambda: defaultdict(int))
		self.pkt_in_just_served = defaultdict(lambda: False)
		self.net_percentages = defaultdict(lambda: [])
		# Table information
		self.table_rows_labels = []
		self.table_columns_labels = []
		self.table_data = []
		# Declaration of the threads for the requests to switches
		self.monitor_thread = hub.spawn(self._monitor)
		self.threshold_thread = hub.spawn(self._monitor_threshold)
		self.first_pkt_in = True
		#self.get_static_data()
		self.datapathid_to_name = {
							123917682136897: '1',
							123917682136938: '2',
							123917682136941: '3',
							123917682136957: '4',
							123917682136955: '5',
							123917682136935: '6'}
		self.host_to_mac = {
							'b8:27:eb:c2:10:5d': 'h2',
							'b8:27:eb:83:1b:e2': 'h3'
							}


	def get_static_data(self):
		# TODO: riguardare perche' non funzionava
		# The CSV files MUST BE in the controller's folder
		mac_to_host_df = pd.read_csv('mac_to_host.csv')
		dpid_to_switch_df = pd.read_csv('dpid_to_switch.csv')

		self.host_to_mac = dict(zip(mac_to_host_df['MAC_address'], mac_to_host_df['Name']))
		self.datapathid_to_name = dict(zip(dpid_to_switch_df['Datapath'], dpid_to_switch_df['Switch_Number']))

		# Dict values from int to str
		for switch, num in datapathid_to_name.iteritems():
			self.datapathid_to_name[switch] = str(num)

	
	def restart_pkt_in(self, src_ip, dst_ip, sport, dport, proto, tos):
		"""Thread that pauses the packet_in handler.

		In the event that the controller handles a packet, and packets from the same connection arrive
		before the rules have been installed on the switches, the _packet_in_handler is stopped. This
		is done in order to stop the controller from being swamped by packet ins, which makes it unable
		to handle new connections. 

		Parameters
		----------
		src_ip, dst_ip, sport, dport, proto, tos : str, str, int, int, int, int, int
			Parameters that identify a connection

		"""
		#self.logger.info("Stopping packet in")
		hub.sleep(PKT_IN_STOP_TIMER)
		#self.logger.info("Packet in restarted")
		self.pkt_in_just_served[src_ip, dst_ip, sport, dport, proto, tos] = False


	def _monitor(self):
		"""Periodically sends statistics requests to switches and plots data.

		Methods
		-------
		_request_port_stats(dp)
			Request ports' statistics
		_request_flow_stats(dp)
			Request flows' statistics
		get_topology_data(0/3)
			Get topology information and update links' weights

		"""
		while True:
			# The following instruction has been put at the top of the loop because the switches start transfering bytes
			# right after they present themselves to the controller (tx_bytes = 70 Bytes circa). So if we immediately request
			# the statistics, the time interval will be very small and the throughput will skyrocket.
			hub.sleep(SLEEP - WAIT_FOR_STATISTICS)
			for dp in self.datapaths.values():
				self._request_port_stats(dp)
				self._request_flow_stats(dp)
			print "sono nella funzione monitor e il tempo e' di {}".format(datetime.datetime.now().time())
			self.logger.info("-" * 60)
			self.get_topology_data(0)
			for link in sorted(self.edge_stats.iterkeys()):
				dpid_src = self.edge_stats[link].link[0]
				dpid_dst = self.edge_stats[link].link[1]
				src_port = self.edge_stats[link].src_port
				dst_port = self.edge_stats[link].dst_port
				port_thr = self.edge_stats[link].src_port_stats['throughput']
				match_dict = self.edge_stats[link].match_to_stats
				'''	
				self.logger.info("switch_src: {}   switch_dst {} src_port: {}  dst_port: {},  {:f} Mbps".format(dpid_src, dpid_dst, src_port, dst_port, band/MAGNITUDE_MEGA_BYTES))
				for match in match_dict:
					match_thr = match_dict[match]['throughput']
					self.logger.info("The match {} is taking up {:f} Mbps".format(match, match_thr/MAGNITUDE_MEGA_BYTES))
				'''
				band_cnt = 0
				for match in match_dict:
					match_band_occupied = match_dict[match]['throughput'] # la banda specifica della regola
					band_cnt = band_cnt + match_band_occupied
					# print "Il match {} sta occupando {:f} MBps".format(match, match_band_occupied/MAGNITUDE_MEGA_BYTES)
				
				# Instead of PortStatsReply - it doesn't work on the testbed
				self.edge_stats[link].src_port_stats['throughput'] = band_cnt
				self.edge_stats[link].src_port_stats['throughputs_array'].append(band_cnt)
				self.edge_stats[link].src_port_stats['mean_throughput'] = np.mean(self.edge_stats[link].src_port_stats['throughputs_array'])

			if self.edge_stats and not self.topo_init:
				self.get_topology_data(3)
				self.topo_init = True
				self.logger.info("Topology started")
		
			if self.topo_init:
				hub.sleep(WAIT_FOR_STATISTICS)
				# If the topology has been created, plot
				self.update_table_data()
				rtp.thr_table_and_bar_chart_plotter(self, LINK_THRESHOLD, MAGNITUDE_KILO_BYTES)
				# Plot only if hosts presented themselves
				if len(self.switch_to_hosts) == len(self.host_to_mac):
					if not self.pos:
						# We don't want the layout of the topology to change each loop
						self.pos = nx.spring_layout(self.net)
					rtp.draw_topology(self)
				# TODO: rivedere le funzioni sottostanti perche' siamo passati a KB
				#rtp.thr_plotter(self, SLEEP, MAGNITUDE_MEGA_BYTES, MAG_STR, LINK_THRESHOLD)
				#rtp.avg_thr_bar_chart_plotter(self, MAGNITUDE_MEGA_BYTES, MAG_STR, LINK_THRESHOLD)
				#rtp.total_thr_pie_charts_plotter(self, LINK_THRESHOLD)


	def _monitor_threshold(self):
		"""Periodically checks if the threshold has been exceeded.

		Methods
		-------
		reallocate_flow(link)
			Reallocates flow with lower ToS or higher throughput

		"""
		while True:
			hub.sleep(SLEEP_TH)
			self.reallocated = False
			for link in sorted(self.edge_stats.iterkeys()):
				port_thr = self.edge_stats[link].src_port_stats['throughput']
				if port_thr > LINK_THRESHOLD:
					#self.logger.info("TX bytes: %d\nLink's threshold: %d", tx_byte, LINK_THRESHOLD)
					self.reallocate_flow(link)


	def _request_flow_stats(self, datapath):
		"""Requests flows' statistics"""
		parser = datapath.ofproto_parser
		# The controller uses this message to query information about flows statistics
		req = parser.OFPFlowStatsRequest(datapath, flags=0)
		datapath.send_msg(req)


	def _request_port_stats(self, datapath):
		"""Requests switch ports' statistics"""
		# Collect information on the incoming packet
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		# The controller uses this message to query information about ports statistics
		req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
		datapath.send_msg(req)


	def reallocate_flow(self, link_above_th):
		"""Reallocates a chosen flow on a new shortest path.

		Parameters
		----------
		link_above_th : tuple
			The link that first exceeded the threshold

		Methods
		-------
		choose_match(link_above_th) : tuple
			Returns the match that will be reallocated

		"""
		if self.reallocated:
			return

		self.logger.info("Link {}-{} is {:f} MBps over the threshold".format(self.edge_stats[link_above_th].link[0], self.edge_stats[link_above_th].link[1], (self.edge_stats[link_above_th].src_port_stats['throughput'] - LINK_THRESHOLD)/MAGNITUDE_MEGA_BYTES))
		parsed_match = self.choose_match(link_above_th)

		try:
			ip_src = parsed_match[1][1]
			ip_dst = parsed_match[2][1]
			ip_dscp = parsed_match[3][1]
		except IndexError:
			self.logger.debug("Table-miss: error extracting the IP-src, no reallocation of the flow {}".format(parsed_match))
			return

		found = False
		dpid_switch_link_above_th = self.edge_stats[link_above_th].link[0]
		port_switch_link_above_th = self.edge_stats[link_above_th].src_port
		priority = self.match_path_and_prio[parsed_match][1]
		# Duplicate the topology so that it can be modified if needed
		temp_net = self.net.copy()
		prev_path = self.match_path_and_prio[parsed_match][0]
		links_list = get_link(self.topology_api_app, None)
		
		for link in links_list:
			for i in range(len(prev_path)-1):
				if (link.src.dpid, link.dst.dpid) == (prev_path[i], prev_path[i+1]):
					prev_weight = self.edge_stats[(link.src.dpid, link.dst.dpid)].src_port_stats['throughput']
					weight_of_flow = self.edge_stats[(link.src.dpid, link.dst.dpid)].retrieve_value(parsed_match, 'throughput')
					weight_without_flow = prev_weight - weight_of_flow
					self.logger.info("The weight of link ({}, {}) without the value of the flow being reallocated is: {:f} MBps".format(link.src.dpid, link.dst.dpid, weight_without_flow/MAGNITUDE_MEGA_BYTES))
					if weight_without_flow > 0:
						temp_net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=weight_without_flow)
						temp_net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=weight_without_flow) 
					else:
						temp_net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=DEFAULT_WEIGHT)
						temp_net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=DEFAULT_WEIGHT)
		
		for link in links_list:
			if link.src.dpid == dpid_switch_link_above_th and link.src.port_no == port_switch_link_above_th:
				# Remove the edge from the duplicated topology
				temp_net.remove_edge(link.src.dpid, link.dst.dpid)
				self.logger.info("\nEliminated the link between the switches s%d e s%d, src port: %d", link.src.dpid, link.dst.dpid, port_switch_link_above_th)
				found = True
		if not found:
			# If found==0, it means that the link exists (because it generated the call for the forwarding of the rules),
			# but it's not present in links_list, which only contains connections between switches.
			self.logger.info("The congestion is on the link that connects the src switch to the src host. The path is not modified.")
			return
		
		src_mac = self.ip_to_mac[ip_src]
		dpid_src = self.mac_to_dpid[src_mac]
		dst_mac = self.ip_to_mac[ip_dst]
		dpid_dst = self.mac_to_dpid[dst_mac]

		# Shortest path computation based on link weights
		path = nx.shortest_path(temp_net, dpid_src, dpid_dst, weight='weight')
		
		if parsed_match[4][1] == 6:
			self.logger.info("TCP Connection with dscp {} and avg band usage of {:f} MBps is REALLOCATED between {} and {} on shortest path:{}\n".format(ip_dscp, self.edge_stats[link_above_th].retrieve_value(parsed_match, 'throughput')/MAGNITUDE_MEGA_BYTES, ip_src, ip_dst, path))
		elif parsed_match[4][1] == 17:
			self.logger.info("UDP Connection with dscp {} and avg band usage of {:f} MBps is REALLOCATED between {} and {} on shortest path:{}\n".format(ip_dscp, self.edge_stats[link_above_th].retrieve_value(parsed_match, 'throughput')/MAGNITUDE_MEGA_BYTES, ip_src, ip_dst, path))		

		'''
		prev_path=[1,2,3,4,5,6,7]
		path = [1,2,20,21,4,23,6,7]

		La funzione remove_match_from_edge, che cancella i match non piu' presenti sugli swithch, viene chiamata SOLO se lo switch mi manda la notifica
		di eliminazione della regola. Se uno switch e' in comune con il precedente percorso, ma cambia il suo output (prev_path 2-->3, path: 2-->20),
		non mi mandera' la notifica di eliminazione e io non cancellero' MAI le statistiche di quel match sul link precedentemente usato (2-->3)
		PROBLEMA:	avro' un collegamento non attivo (perche' lo swtich ha cambiato porta e i pkts viaggiano su un nuovo link) e una statistica che mi 
					rimane con un valore fisso (perche' non si aggiorna)
		SOLUZIONE:	Se sul nuovo percorso ci sono degli switch in comune con il precedente, che pero' cambiano la porta di uscita, devo elimare le statistiche.						
					Quindi devo cancellare le statistiche dei link 2-->3, 4-->5
		IMPLEMENTAZIONE: Voglio fare un ciclo che considera se nel nuvo percorso si sono degli switch in comune con il precedente
			DUBBIO: Facendo cosi' considero anche i link IN COMUNE tra il vecchio e il nuovo percorso  (nel nostro caso 1-->2, 6-->7)
			RISPOSTA:	le regole verranno REINVIATE anche a questi switch e qundi timer e byte_count verranno resettati. Quindi questo
						non mi causa problemi e posso usare questo approccio.

		RISULTATO ==========> Devo cancellare tutte le statistiche da tutti gli switch in comune con il precedente percorso

		Devo cancellare le statistiche 1-->2, 2-->3, 4-->5, 6-->7


		PROBLEMA CON TESTBED: quando viene modificata l'action di una regola, gli switch in uso sul testbed resettano i valori di timing ma non resettano i valori del byte_count 
		SOLUZIONE: 
			a)	se prima il percorso faceva 2-->3 e ora fa 2-->20, prendo il valore di prev_tx_bytes di 2-->3 e lo salvo come offset in 2-->20. Quando ricevero'
				per la prima volta le statistiche del link 2-->20, al byte_count che mi e' stato fornito, sottrarro' l'offset, in modo da avere la giusta
				quantita' di data effettivamente trasferiti da quando e' cambiata la regola. L'offset lo dovro' usare solo una volta perche', siccome
				il throughpout e' calcolato come differenza fra curr_tx_bytes e prev_tx_bytes, al successivo aggiornamento delle statistiche l'offset
				sara' gia' considerato in prev_tx_bytes.

				Il valore di byte_count del link 2-->3 che ho usato come offset e' l'ultimo DA QUANDO L'HO RICHIESTO, cioe' dall'ultima volta che 
				ho richiesto le statistiche:  Quindi il suo valore e' MINORE rispetto a quello che aveva prima che la regola fosse aggiornata. Come risultato 
				il link risulta avere una banda MAGGIORE rispetto a quella reale (solo dopo la prima volta che aggiorno le statistiche, perche' il throughput e' 
				calcolato come differenziale e quindi dalla seconda volta in poi non ho problemi).
				PROBLEMA: Risultando la banda maggiore de quella reale, il link potrebbe essere visto come over the threshold dalla funzione di riallocazione.
				SOLUZIONE:	1)	ritardare il controllo per la riallocazione in modo da aspettare il secondo aggiornamento delle statistiche.
							2)	vedi sotto il punto b)
			b)	assegno ai link 2-->20 il valore del throughput che aveva il link 2-->3. Questo lo faccio solo la prima volta che viene chiamata la funzione
				per aggiornare le statistiche. Dalla seconda volta in poi:
					- tutti i dati relativi alle statistiche precedenti sono stati salvati
						--> l'offset douvuto al byte_count relativo al precedente link, viene considerato nella variabile prev_tx_bytes
					- per calcolare il throughput guardo sempre la differenza fra curr_tx_bytes e prev_tx_bytes
				allora posso proseguire come faccio sempre.
				Per implementare questa soluzione uso uso l'array 'switches_in_common' e il dizionario 'prev_throughput'.
				
				
		DA VERIFICARE: siccome entrabe le soluzioni vengono applicate anche sui link IN COMUNE con il precedente percorso (perche' vengono applicate su tutti gli switch in comune 
		tra prev_path e path), verificare che si comportino come gli altri e quindi vengano resettati i valori di timing e NON quelli di byte_count. Questa verifica andrebbe 
		fatto un esperimento come il TUTORIAL 2. Siccome non e' stato possibile realizzare una topologia simile con gli switch a disposizione,  non siamo riusciti a fare una verifica di questo tipo.
		La verifica potrebbe essere fatta commentando la fuznione che elimina il link congestionato in modo che il flusso venga riallocato come prima.

		'''
		
		switches_in_common = []
		prev_throughput = {}
		for i in range(len(path)-1):
			for j in range(len(prev_path)-1):
					if path[i]==prev_path[j]:
						switches_in_common.append(prev_path[j])
						prev_throughput[prev_path[j]] = self.edge_stats[(prev_path[j], prev_path[j+1])].retrieve_value(parsed_match, 'throughput')
						self.logger.debug("Deleting statistics of link ({}, {})".format(prev_path[j], prev_path[j+1]))
						self.edge_stats[(prev_path[j], prev_path[j+1])].remove_match_from_edge(parsed_match)
						break
		
		first_switch = 0
		last_switch = 0

		if len(path) == 1:
			# The dst host is directly connected to the switch that has sent the packet_in
			self.logger.info("The concerned link is the one directly connected with the destination, \
								so it doesn't affect other flows. The flow entry isn't modified.")
			''' Different from `found == 0`: in that case, the congested link is the one between the src host and the
				switch the src host is connected to. Here, the congested link is the one between the dst host and the
				dst switch. This only happens if the src host and the dst host are connected to the same switch. '''
		elif len(path) >= 2:
			self.reallocated = True
			if len(path) > 2:
				# Send the rule to forward the pkt to all the switches on the path, except the first and the last one
				# 	path[i-1] <--link--> input_port : path[i] : output_port <--link--> path[i+1]
				for i in range(1, len(path)-1):
					self.logger.debug("REINSTALL the flow on switch s%s", path[i])
					output_port = temp_net[path[i]][path[i + 1]]['port']
					dp = get_datapath(self, path[i])
					actions = [dp.ofproto_parser.OFPActionOutput(output_port)]
					match = self.tuple_to_OFPMatch(parsed_match, dp)
					self.add_flow(dp, priority , match, actions, MAX_RTT_ADMITTED, path)
					# If the rule is already present in the switch, because the new path has that same switch among its switches,
					# then the rule will be overwritten, having the same match (eventually changing the output port).
					if path[i] in switches_in_common:
						self.edge_stats[(path[i], path[i + 1])].add_match_to_edge(match, prev_throughput[path[i]])
					else:
						self.edge_stats[(path[i], path[i + 1])].add_match_to_edge(match)
					self.logger.debug("I'm switch %d and the pkt will go out from port %d", dp.id, output_port)
			for dp in self.datapaths.values():   
				if dp.id == dpid_src:
					first_switch = dp
				elif dp.id == dpid_dst:
					last_switch = dp
			# First, forward the rule to the last switch...
			in_port_dst = self.mac_to_port[dpid_dst][dst_mac]
			self.logger.debug("in_port_dst  %s", in_port_dst)
			actions_1_dst = [last_switch.ofproto_parser.OFPActionOutput(in_port_dst)]
			match = self.tuple_to_OFPMatch(parsed_match, last_switch)
			self.add_flow(last_switch, priority , match, actions_1_dst, MAX_RTT_ADMITTED, path)
			self.logger.debug("I'm switch %d and the pkt will go out from port %d", last_switch.id, in_port_dst)
			self.logger.debug("REINSTALL the flow on the LAST switch (s%s) of the new path", path[len(path) - 1])
			# ...and then to the first switch
			out_port_src = temp_net[path[0]][path[1]]['port']	# Output port to the next hop
			self.logger.debug("out_port_src  %s", out_port_src)
			actions_1_src = [first_switch.ofproto_parser.OFPActionOutput(out_port_src)]
			match = self.tuple_to_OFPMatch(parsed_match, first_switch)
			self.add_flow(first_switch, priority , match, actions_1_src, MAX_RTT_ADMITTED, path)
			if path[0] in switches_in_common:
				self.edge_stats[(path[0], path[1])].add_match_to_edge(match, prev_throughput[path[0]])
			else:
				self.edge_stats[(path[0], path[1])].add_match_to_edge(match)
			self.logger.debug("I'm switch %d and the pkt will go out from port %d", first_switch.id, out_port_src)
			self.logger.debug("REINSTALL the flow on the FIRST switch (s%s) on the new path", path[0]) 
		return


	def choose_match(self, link_above_th):
		"""Returns the match that exceeded the threshold on the passed link.

		To choose the flow that has to be reallocated, we first look at the ToS:
		the lower the ToS, the higher the probability of being reallocated. If
		two flows have the same ToS, the flows' throughputs are considered: the
		flow with the highest throughput is chosen.

		Parameters
		----------
		link_above_th : tuple
			The link that first exceeded the threshold

		Methods
		-------
		retrieve_value() : float
			Returns the flow's throughput

		Returns
		-------
		tuple
			The match that identifies which flow to reallocate

		"""
		match_dict = self.edge_stats[link_above_th].match_to_stats
		link_usage = 0
		chosen_match = ()
		# Set the DSCP equal to a number which is higher than the values it can assume (0:255)
		lower_dscp = 256
		for match in match_dict:
			match_dscp = match[3][1]		# `ip_dscp`
			if match_dscp < lower_dscp:
				lower_dscp = match_dscp
				link_usage = self.edge_stats[link_above_th].retrieve_value(match, 'throughput')
				chosen_match = match
			elif lower_dscp == match_dscp and self.edge_stats[link_above_th].retrieve_value(match, 'throughput') > link_usage:
				link_usage = self.edge_stats[link_above_th].retrieve_value(match, 'throughput')
				chosen_match = match
		return chosen_match


	def get_match_values(self, match):
		"""Extracts the values of the match that will be used to identify the flow in the plotted table.

		Parameters
		----------
		match : tuple of tuples
			Previously parsed match
			Example:
			(('eth_type': 2048), ('ipv4_src': '10.0.0.1'), ('ipv4_dst': '10.0.0.2'), ('ip_dscp': 14), ('ip_proto': 6), ('tcp_src': 6000), ('tcp_dst': 34778))
		
		Returns
		-------
		string
			Returns `match` as a string, used as label in the table
			Example:
			'10.0.0.1:6000 --> 10.0.0.2, ToS: 14'
		
		"""
		match_values = []
		tos = 0
		for field in match:
			if field[0] == 'ipv4_src':
				match_values.append(field[1][-1])
			elif field[0]=='ipv4_dst':
				match_values.append(field[1][-1])
			elif field[0] == 'ip_dscp':
				if field[1] != 0:
					tos = field[1]*4
				match_values.append(tos)
			elif (field[0] == 'tcp_src') or (field[0] == 'udp_src'):
				match_values.append(field[1])
			match_string = '{0}:{3} --> {1}, ToS {2}'.format(match_values[0], match_values[1], match_values[2], match_values[3])
		return match_string


	def update_table_data(self):
		"""Reset and populate the plotted table."""
		idx = 0
		self.table_columns_labels = []
		for row in range(len(self.table_data)):
			for col in range(len(self.table_data[row])):
				# Set each cell's value to zero
				self.table_data[row][col] = 0
		# Populate the table
		for link in self.edge_stats.iterkeys():
			for match in self.edge_stats[link].match_to_stats.iterkeys():
				# Check if the link's throughput is higher than a set threshold: we only want to plot TCP/UDP connections, not ACKs or ARPs.
				if self.edge_stats[link].match_to_stats[match]['throughput'] > MIN_FLOW_BW:
					match_values = self.get_match_values(match)
					if match_values not in self.table_rows_labels:
						# Create entry
						self.table_rows_labels.append(match_values)
						tmp_thr_vect = [0] * len(self.edge_stats)
						tmp_thr_vect[idx] = float(self.edge_stats[link].match_to_stats[match]['throughput'])/MAGNITUDE_KILO_BYTES
						self.table_data.append(tmp_thr_vect)
					else:
						# Update data
						row = self.table_rows_labels.index(match_values)
						self.table_data[row][idx] = float(self.edge_stats[link].match_to_stats[match]['throughput'])/MAGNITUDE_KILO_BYTES
			idx = idx + 1  
			self.table_columns_labels.append((self.datapathid_to_name[link[0]], self.datapathid_to_name[link[1]]))
		# Remove the rules that are not valid anymore
		elem_deleted = True
		while elem_deleted:
			elem_deleted = False
			for row in range(len(self.table_data)):
				found = 0
				for col in range(len(self.table_data[row])):
					if self.table_data[row][col] != 0:
						found = 1
						break
				if not found:
					self.table_data.remove(self.table_data[row])
					self.table_rows_labels.remove(self.table_rows_labels[row])
					self.logger.debug("Flow removed from table.")
					elem_deleted = True
					break


	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		"""Installs the table-miss flow entry on the switches.
		
		It runs when the switches present themselves to the controller for the first time, because
		at the beginning they have no rules in their tables (configuration phase: CONFIG_DISPATCHER).

		"""
		# Save the datapath of the switch, contained in the packet the switch has sent to the controller
		datapath = ev.msg.datapath
		# Get the type of protocol used by the switch
		ofproto = datapath.ofproto
		# Get the message parsing library for the version of OpenFlow protocol used here; locally referenced as parser
		parser = datapath.ofproto_parser
		# Save the mapping ID-datapath in the dictionary
		self.datapaths[datapath.id] = datapath
		# Create a dictionary to map mac-port, with the dpid of the switch as key
		self.mac_to_port.setdefault(datapath.id, {})
		# We specify NO BUFFER to max_len of the output action due to OVS bug. At this moment, if we specify a lesser
		# number, e.g., 128, OVS will send Packet-In with invalid buffer_id and truncated packet data. In that case,
		# we cannot output packets correctly. The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions, 0, ())
		self.logger.debug("Installed table-miss on switch %s", datapath.id)


	def add_flow(self, datapath, priority, match, actions, idle_timeout, path, buffer_id=None):
		"""Function that adds the rules to the flow-mod table."""
		# Get the type of protocol used by the switch
		ofproto = datapath.ofproto
		# Get the message parsing library for the version of OpenFlow protocol used here; locally referenced as parser
		parser = datapath.ofproto_parser
		# Extract important information about the flow from the match
		match_tuple = self.OFPMatch_to_tuple(match)
		# Save flow's path and priority
		self.match_path_and_prio[match_tuple] = (path, priority)
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		# Bitmap between the flags that are needed to reset the byte count (OFPFF_RESET_COUNTS)
		# and inform when the flow has been removed or times out (OFPFF_SEND_FLOW_REM)
		flags = (ofproto.OFPFF_RESET_COUNTS | ofproto.OFPFF_SEND_FLOW_REM)
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout,
									buffer_id=buffer_id, priority=priority, flags = flags,
									match=match, instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout,
									priority=priority, flags = flags, match=match, instructions=inst)  
		datapath.send_msg(mod)
		'''
		Se un flusso viene riallocato, dobbiamo ricalcolare il percorso e reinstaurare le regole. Se pero' lungo il nuovo percorso e' presente
		uno switch che era presente anche nel percorso precedente, la regola viene sovrascritta. Nel processo di sovrascrittura non vengono pero' 
		azzerati i contatori di pkt_count e byte_count (e invece viene azzerato il campo duration_sec). Quindi quando andiamo a calcolare la variabile average_link_usage
		nella funzione che rialloca i cammini, abbiamo un byte_count cumulativo dall'inizio della connessione e lo dividiamo per un duration_sec 
		che invece corrisponde all'ultima volta che abbiamo modificato la regola: il risultato e' un average_link_usage molto piu' alto rispetto alla realta'.
		Con questa logica potrebbe succedere che una connessione attiva da moltissimo tempo (e quindi ha un byte_count molto alto) che sta usando poca banda, risulti piu' papabile ad essere
		cambiata rispetto ad una che c'e' da poco tempo ma sta usando poca banda.
		Per risolvere il problema basta azzerare i contatori quando si reinstrada la regola mettendo il flag ofproto.OFPFF_RESET_COUNTS
		'''


	def send_arp(self, datapath, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port):
		"""Generates either an ARP request or an ARP reply."""
		if opcode == 1:		# ARP request
			# The target MAC address is unknown, so I put it equal to 0
			target_mac = "00:00:00:00:00:00"
			# IP of the host of which I want to know the MAC
			target_ip = dst_ip
		elif opcode == 2:	# ARP reply
			# Insert the MAC and IP address of the IP that has received the ARP request
			target_mac = dst_mac
			target_ip = dst_ip

		e = ethernet.ethernet(dst_mac, src_mac, ether.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, opcode, src_mac, src_ip, target_mac, target_ip)
		p = Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()
	
		actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
				datapath=datapath,
				buffer_id=0xffffffff,
				in_port=datapath.ofproto.OFPP_CONTROLLER,
				actions=actions,
				data=p.data)
		datapath.send_msg(out)


	def OFPMatch_to_tuple(self, match):
		"""Returns `match` as a tuple of tuples.

		Example of what is returned:
		(
			('eth_type', 2048),
			('ipv4_src', '10.0.0.2'),
			('ipv4_dst', '10.0.0.1'),
			('ip_dscp', 14),
			('ip_proto', 6),
			('tcp_src', 48744), 
			('tcp_dst', 4000), 
		)

		"""
		parsed_match = [0,0,0,0,0,0,0]
		for field in match._fields2:
			if field[0] == 'eth_type': 
				parsed_match[0] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'ipv4_src': 
				parsed_match[1] = (field[0], field[1]) # field[1] type str
			elif field[0] == 'ipv4_dst': 
				parsed_match[2] = (field[0], field[1]) # field[1] type str
			elif field[0] == 'ip_dscp': 
				parsed_match[3] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'ip_proto': # se trovi nella tupla la striga dell' ip_proto
				parsed_match[4] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'udp_src' or field[0] == 'tcp_src': 
				parsed_match[5] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'udp_dst' or field[0] == 'tcp_dst': 
				parsed_match[6] = (field[0], field[1]) # field[1] type int
		return tuple(parsed_match)


	def tuple_to_OFPMatch(self, parsed_match, dp):
		parser = dp.ofproto_parser
		try:
			if parsed_match[6][0]	== 'tcp_dst':
				self.logger.debug('tuple_to_OFPMatch -- TCP')
				match = parser.OFPMatch(eth_type=parsed_match[0][1],
											ipv4_src=parsed_match[1][1],
											ipv4_dst=parsed_match[2][1],
											ip_dscp=parsed_match[3][1],
											ip_proto=parsed_match[4][1],
											tcp_src=parsed_match[5][1],
											tcp_dst=parsed_match[6][1])
				return match
			else:
				self.logger.debug('tuple_to_OFPMatch -- UDP')
				match = parser.OFPMatch(eth_type=parsed_match[0][1],
												ipv4_src=parsed_match[1][1],
												ipv4_dst=parsed_match[2][1],
												ip_dscp=parsed_match[3][1],
												ip_proto=parsed_match[4][1],
												udp_src=parsed_match[5][1],
												udp_dst=parsed_match[6][1])
				return match
		except Exception as e:
			# Tuple index out of range on match[6][0]: check if it is an IP forwarding instruction
			if hasattr(e, 'message'):
				print e.message
			else:
				print e
			try:
				#self.logger.info('IP forwarding')
				match = parser.OFPMatch(eth_type=parsed_match[0][1],
										ipv4_src=parsed_match[1][1],
										ipv4_dst=parsed_match[2][1])
				return match
			except Exception as e:
				# Tuple index out of range. Check if it is a rule to force the forwarding of TCP/UDP packets
				if hasattr(e, 'message'):
					print e.message
				else:
					print e
				match = parser.OFPMatch(eth_type=parsed_match[0][1],
										ip_proto=parsed_match[4][1])
				return match
		self.logger.info("\n\n\n Unknown match, review parsing algorithm. \n\n\n")


	def host_cache(self):
		"""Adds the hosts to the graph."""
		for switch in self.switch_to_hosts.iterkeys():
			for mac_value in self.switch_to_hosts[switch]:
				hnode_name = mac_value
				edge_name = (hnode_name, switch)
				#edge_name = (hnode_name, self.datapathid_to_name[switch])
				self.net.add_node(hnode_name)
				self.net.add_edge(*edge_name, weight=600)


	def _mac_learning(self, dpid_src, src, in_port):
		"""MAC learning, called in the `_packet_in_handler`."""
		self.mac_to_port.setdefault(dpid_src, {})
		self.port_to_mac.setdefault(dpid_src, {})
		self.mac_to_port[dpid_src][src] = in_port
		self.mac_to_dpid[src] = dpid_src
		self.port_to_mac[dpid_src][in_port] = src


	def _handle_arp_packets(self, switches, datapath, dpid_src, pkt, src, dst, in_port):
		"""Handling of an ARP packet."""
		arp_packet = pkt.get_protocol(arp.arp)

		arp_src_ip = arp_packet.src_ip
		arp_dst_ip = arp_packet.dst_ip
		self.host_cache()
		if arp_packet.opcode == 1:
			#self.logger.info("ARP request")
			if arp_dst_ip in self.ip_to_mac:
				#self.logger.info("The address is inside the IP TO MAC table")
				src_ip = arp_dst_ip
				dst_ip = arp_src_ip
				src_mac = self.ip_to_mac[arp_dst_ip]
				dst_mac = src
				out_port = in_port
				# Send an ARP reply
				opcode = 2
				self.send_arp(datapath, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)
				#self.logger.info("Packet in %s %s %s %s", src_mac, src_ip, dst_mac, dst_ip)
			else:
				#self.logger.info("The address is NOT inside the IP TO MAC table")
				src_ip = arp_src_ip
				dst_ip = arp_dst_ip
				src_mac = src
				dst_mac = dst
				# Learn the new IP address
				self.ip_to_mac.setdefault(src_ip, {})
				self.ip_to_mac[src_ip] = src_mac
				# self.logger.info("The IP address is now inside the IP TO MAC table")
				# Send an ARP request to all the switches
				opcode = 1
				for id_switch in switches:
					# Get the the datapath structure from its dpid
					datapath_dst = get_datapath(self, id_switch)
					for port in range(1, NUMBER_OF_SWITCH_PORTS+1):
						if self.port_occupied[id_switch][port] == 0:
						# If the switch is NOT connected to another switch, then it is connected to a host: send the request.
							out_port = port
							if id_switch == dpid_src:
							# The current switch is the one that has sent the packet_in
								if out_port != in_port:
									# The output port is different from the one that generated the packet_in
									self.send_arp(datapath_dst, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)
							else:
								# The destination switch is different from the one that generated the packet_in
								self.send_arp(datapath_dst, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)
		else:
			#self.logger.info("ARP reply")
			src_ip = arp_src_ip
			dst_ip = arp_dst_ip
			src_mac = src
			dst_mac = dst
			if arp_dst_ip in self.ip_to_mac:
				# Learn the new IP address
				self.ip_to_mac.setdefault(src_ip, {})
				self.ip_to_mac[src_ip] = src_mac
			# Send an ARP reply to the switch
			opcode = 2
			out_port = self.mac_to_port[self.mac_to_dpid[dst_mac]][dst_mac]
			datapath_dst = get_datapath(self, self.mac_to_dpid[dst_mac])
			self.send_arp(datapath_dst, opcode, src_mac, src_ip, dst_mac, dst_ip, out_port)


	def _handle_ipv4_packets(self, pkt, ip4_pkt, ofproto, parser, datapath, dpid_src, src, dst):
		"""Handling of an IPv4 packet."""
		src_ip = ip4_pkt.src
		dst_ip = ip4_pkt.dst
		src_mac = src
		dst_mac = dst
		# Extract the IP packet layer-4 protocol
		proto = ip4_pkt.proto
		sport = "0"
		dport = "0"
		tos = ip4_pkt.tos

		# Since the location of src/dst ports of TCP and UDP are in different position in the pkt, we want to distinguish the two cases
		if proto == 6:
			tcp_pkt = pkt.get_protocol(tcp.tcp)
			sport = tcp_pkt.src_port
			dport = tcp_pkt.dst_port

		if proto == 17:
			udp_pkt = pkt.get_protocol(udp.udp)
			sport = udp_pkt.src_port
			dport = udp_pkt.dst_port

		self.host_cache()
		if self.pkt_in_just_served[src_ip, dst_ip, sport, dport, proto, tos] == False:
			self.pkt_in_just_served[src_ip, dst_ip, sport, dport, proto, tos] = True

			restart_pkt_in_thread = threading.Thread(target=self.restart_pkt_in, args=(src_ip, dst_ip, sport, dport, proto, tos))
			restart_pkt_in_thread.start()
			self.logger.info("\n--- Packet_in switch: {}, source IP: {}, destination IP: {}, port_src {} and port_dst {}, with ToS {} and layer 4 protocol: {}".format( self.datapathid_to_name[dpid_src], src_ip, dst_ip, sport, dport, tos, proto))
			#self.logger.info("--- Packet_in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src_mac, dst_mac, in_port)
			
			datapath_dst = get_datapath(self, self.mac_to_dpid[dst_mac])        # Given the dst MAC, extract form the MAC-dictionary the corresponding datapath
			# From the datapath extract its ID
			dpid_dst = datapath_dst.id
			self.logger.info(" --- Destination present on switch: %s", self.datapathid_to_name[dpid_dst])

			# Shortest path computation based on link weights
			path = nx.shortest_path(self.net, dpid_src, dpid_dst, weight='weight') # I compute it looking for the one with minor weight
			for idx in range(len(path)):
				nice_path = self.datapathid_to_name[path[idx]]
			self.logger.info(" --- Shortest path: %s\n", nice_path)
			
			# Set the flows for different cases and for both link's directions.
			if len(path) == 1:
				# The destination host is directly connected to the switch that has sent the pkt in:
				# 	src_host <---> in_port_src : switch : in_port_dst <---> dst_host
				# Learning switch: I save the correspondence between my port and the source MAC attacched to that port
				in_port_src = self.mac_to_port[dpid_src][src_mac] 
				# I get the ID of the interface of the dst host to forward the pkt to the right interface      
				in_port_dst = self.mac_to_port[dpid_dst][dst_mac]
				# Add rule (from src to dst)
				actions_1 = [datapath.ofproto_parser.OFPActionOutput(in_port_dst)]
				match_1 = parser.OFPMatch(eth_dst=dst_mac)
				self.add_flow(datapath, 1, match_1, actions_1, MAX_RTT_ADMITTED, path)
				# Add rule (from dst to src)
				actions_2 = [datapath.ofproto_parser.OFPActionOutput(in_port_src)]
				match_2 = parser.OFPMatch(eth_dst=src_mac)
				self.add_flow(datapath, 1, match_2, actions_2, MAX_RTT_ADMITTED, path)

			elif len(path) >= 2:
				if len(path) > 2:
					# I send the rule to forward the pkt to all the other switches on the path, except the first and the last one
					# 	path[i-1] <--link--> input_port : path[i] : output_port <--link--> path[i+1]
					for i in range(1, len(path)-1):
						#self.logger.info("Install the flow on switch %s", path[i])
						output_port = self.net[path[i]][path[i + 1]]['port']
						dp = get_datapath(self, path[i])
						actions_1 = [dp.ofproto_parser.OFPActionOutput(output_port)]
						# TCP
						if proto == 6:
							match_1 = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip,
													ip_dscp=tos/4,
													tcp_dst=dport,
													tcp_src=sport,
													ip_proto=proto)
							self.add_flow(dp, 3, match_1, actions_1, MAX_RTT_ADMITTED, path)    # Add rule (from src to dst)
							self.edge_stats[(path[i], path[i + 1])].add_match_to_edge(match_1)
						# UDP
						elif proto == 17:
							match_1 = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip,
													ip_dscp=tos/4,
													udp_dst=dport,
													udp_src=sport,
													ip_proto=proto)
							self.add_flow(dp, 3, match_1, actions_1, MAX_RTT_ADMITTED, path)    # Add rule (from src to dst)
							self.edge_stats[(path[i], path[i + 1])].add_match_to_edge(match_1)
						# IP forwarding
						else:
							match_1 = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip)
							self.add_flow(dp, 1, match_1, actions_1, MAX_RTT_ADMITTED, path)    # Add rule (from src to dst)
							self.edge_stats[(path[i], path[i + 1])].add_match_to_edge(match_1)
				# Install rule just on src and dst switches
				# 	src_ host <---> in_port_src : path[0] : out_port_src <-- ... --> out_port_dst : path[len(path)-1] : in_port_dst <---> dst_host
				datapath_src = get_datapath(self, path[0])      # That's me
				datapath_dst = get_datapath(self, path[len(path) - 1])      # Last switch to be reached
				dpid_src = datapath_src.id
				#self.logger.info("dpid_src  %s", dpid_src)
				dpid_dst = datapath_dst.id
				#self.logger.info("dpid_dst  %s", dpid_dst)
				# From src to dst
				in_port_src = self.mac_to_port[dpid_src][src_mac]  # I look for the interface connecting the src switch and host
				#self.logger.info("in_port_src  %s", in_port_src)
				out_port_src = self.net[path[0]][path[1]]['port']  # Output port to the next hop
				#self.logger.info("out_port_src  %s", out_port_src)
				# From dst to src
				in_port_dst = self.mac_to_port[dpid_dst][dst_mac]  # I look for the interface connecting dst switch and host
				#self.logger.info("in_port_dst  %s", in_port_dst)
				# TCP
				if proto == 6:
					# Add rule (from src to dst) -- send the packet out to the dst host
					actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(in_port_dst)]
					match_1_dst = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip,
													ip_dscp=tos/4, # DSCP value is the first 6-bit of ToS field in IP header. N.B. I valori di ToS ammissibili sono solo 0, 32, 40, 56, 72, 88, 96, ..., 224. Pertanto se imponiamo --tos 0x23, iperf assegnera' 32, se --tos 0x24 assegna 36 e cosi' via
													tcp_dst=dport,
													tcp_src=sport,
													ip_proto=proto)
					self.add_flow(datapath_dst, 3, match_1_dst, actions_1_dst, MAX_RTT_ADMITTED, path)
					#self.logger.info("Install the flow on switch %s", path[len(path) - 1])
					# Add rule (from src to dst) -- send the packet out to the next switch in the path
					actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
					match_1_src = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip,
													ip_dscp=tos/4,
													tcp_src=sport,
													tcp_dst=dport,
													ip_proto=proto)
					self.add_flow(datapath_src, 3, match_1_src, actions_1_src, MAX_RTT_ADMITTED, path)
					self.edge_stats[(path[0], path[1])].add_match_to_edge(match_1_src)
					#self.logger.info("Install the flow on switch %s", path[0])
				# UDP
				elif proto == 17:
					# Add rule (from src to dst) -- send the packet out to the dst host
					actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(in_port_dst)]
					match_1_dst = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip,
													ip_dscp=tos/4,
													udp_src=sport,
													udp_dst=dport,
													ip_proto=proto)
					self.add_flow(datapath_dst, 3, match_1_dst, actions_1_dst, MAX_RTT_ADMITTED, path)

					#self.logger.info("Install the flow on switch %s", path[len(path) - 1])
					# Add rule (from src to dst) -- send the packet out to the next switch in the path
					actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
					match_1_src = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip,
													ip_dscp=tos/4,
													udp_src=sport,
													udp_dst=dport,
													ip_proto=proto)
					self.add_flow(datapath_src, 3, match_1_src, actions_1_src, MAX_RTT_ADMITTED, path)
					self.edge_stats[(path[0], path[1])].add_match_to_edge(match_1_src)
					#self.logger.info("Install the flow on switch %s", path[0])
				# IP forwarding
				else:
					# Add rule (from src to dst) -- send the packet out to the dst host
					actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(in_port_dst)]
					match_1_dst = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip)
					self.add_flow(datapath_dst, 1, match_1_dst, actions_1_dst, MAX_RTT_ADMITTED, path)
					#self.logger.info("Install the flow on switch %s", path[len(path) - 1])
					# Add rule (from src to dst) -- send the packet to the next switch in the path
					actions_1_src = [datapath.ofproto_parser.OFPActionOutput(out_port_src)]
					match_1_src = parser.OFPMatch(eth_type=0x0800,
													ipv4_src=src_ip,
													ipv4_dst=dst_ip)
					self.add_flow(datapath_src, 1, match_1_src, actions_1_src, MAX_RTT_ADMITTED, path)
					self.edge_stats[(path[0], path[1])].add_match_to_edge(match_1_src)
					#self.logger.info("Install the flow on switch %s", path[0])
					# Add rule -- if IP + TCP, send the packet to the controller, no buffer
					match = parser.OFPMatch(eth_type=0x0800,
											ip_proto=6)
					actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
											ofproto.OFPCML_NO_BUFFER)]
					self.add_flow(datapath_src, 2, match, actions, MAX_RTT_ADMITTED, path)
					self.edge_stats[(path[0], path[1])].add_match_to_edge(match)
					# Add rule -- if IP + UDP, send the packet to the controller, no buffer
					match = parser.OFPMatch(eth_type=0x0800,
											ip_proto=17)
					actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
											ofproto.OFPCML_NO_BUFFER)]
					self.add_flow(datapath_src, 2, match, actions, MAX_RTT_ADMITTED, path)
					self.edge_stats[(path[0], path[1])].add_match_to_edge(match)
						

		out_port = self.mac_to_port[dpid_src][src_mac]
		actions = [parser.OFPActionOutput(out_port)]
		out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
		datapath.send_msg(out)


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		"""Handler for the packet_in event.
		
		When a switch receives a packet and doesn't know how to handle it, it sends the controller
		a PacketIn message. The controller then calculates the shortest path to the destination,
		populates the routing tables and replies with a PacketOut message, which tells the switch
		how to handle the packet.

		"""
		# If you hit this you might want to increase the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("Packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
		# Save the message
		msg = ev.msg
		# Save the datapath of the switch, contained in the packet
		datapath = msg.datapath
		# Get the type of protocol used by the switch
		ofproto = datapath.ofproto
		# Get the message parsing library for the version of OpenFlow protocol used here; locally referenced as parser
		parser = datapath.ofproto_parser
		# Get the physical port number where the packet was received on the switch that sent the packet-in message
		in_port = msg.match['in_port']
		# `msg.data` contains the packet as a string of characters of 8 bytes each; by calling .Packet() we parse the
		# OpenFlow message data and save it into the variable `pkt`:
		pkt = packet.Packet(msg.data)
		# Get the protocol
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# Ignore lldp packets
			return
	
		# Get the MAC addresses
		src = eth.src
		dst = eth.dst
		# Get the switch identifier, needed to access the right table in the dictionary `mac_to_port`
		dpid_src = datapath.id
		
		# TOPOLOGY DISCOVERY----------------------------------------------------------------------
		switches = self.get_topology_data(1)

		# MAC LEARNING----------------------------------------------------------------------------
		self._mac_learning(dpid_src, src, in_port)

		# HANDLE ARP PACKETS----------------------------------------------------------------------
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			self._handle_arp_packets(switches, datapath, dpid_src, pkt, src, dst, in_port)

		# HANDLE IP PACKETS-----------------------------------------------------------------------
		ip4_pkt = pkt.get_protocol(ipv4.ipv4)
		if ip4_pkt:
			self._handle_ipv4_packets(pkt, ip4_pkt, ofproto, parser, datapath, dpid_src, src, dst)
	

	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		"""Gets and updates the topology data."""
		switch_list = get_switch(self.topology_api_app, None)
		switches = [switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)

		for link in links_list:
			# Add bidirecional link and create its corresponding class
			if self.edge_stats.get((link.src.dpid, link.dst.dpid)) == None:
				self.edge_stats[(link.src.dpid, link.dst.dpid)] = EdgeStats(link.src.dpid, link.dst.dpid)
				self.edge_stats[(link.src.dpid, link.dst.dpid)].src_port = link.src.port_no
				self.edge_stats[(link.src.dpid, link.dst.dpid)].dst_port = link.dst.port_no
			if self.edge_stats.get((link.dst.dpid, link.src.dpid)) == None:
				self.edge_stats[(link.dst.dpid, link.src.dpid)] = EdgeStats(link.dst.dpid, link.src.dpid)
				self.edge_stats[(link.dst.dpid, link.src.dpid)].src_port = link.dst.port_no
				self.edge_stats[(link.dst.dpid, link.src.dpid)].dst_port = link.src.port_no
			# Get link's weights
			weight_src = self.edge_stats[(link.src.dpid, link.dst.dpid)].src_port_stats['throughput']
			weight_dst = self.edge_stats[(link.dst.dpid, link.src.dpid)].src_port_stats['throughput']
			# If a link's weight is zero, set it to the default weight; otherwise update it
			if weight_src == 0:
				self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=DEFAULT_WEIGHT)
			else:
				self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=weight_src)
			if weight_dst == 0:
				self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=DEFAULT_WEIGHT)
			else:
				self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=weight_dst)
		
		if ev == 1:		# Completes the topology discovery in the `_packet_in_handler`
			links_ = [(link.dst.dpid, link.src.dpid, link.dst.port_no) for link in links_list]
			for l in links_:
				# Set the value to 1 if a switch is directly connected to another switch
				self.port_occupied[l[0]][l[2]] = 1
			#print json.dumps(self.port_occupied)
			#elif ev == 3:	# If called from the `_monitor` thread			
			for dpid in switches:
				# Get all the hosts connected to the switch
				hosts_list = get_host(self.topology_api_app, dpid)
				# Save the hosts as dictionaries
				self.hosts_dict[dpid] = [ host.to_dict() for host in hosts_list ]
				for host in self.hosts_dict[dpid]:
					if host != []:
						self.switch_to_hosts.setdefault(dpid, [])
						if (host['mac'] not in self.switch_to_hosts[dpid]) and (host['mac'] in self.host_to_mac.keys()): 
							self.switch_to_hosts[dpid].append(host['mac'])
				self.host_cache()
			return switches
		
			
	@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
	def flow_removed_handler(self, ev):
		"""Deletes the flow entry from the `match_to_stats` dictionary of each link."""
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto

		if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
			reason = 'IDLE TIMEOUT'
		elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
			reason = 'HARD TIMEOUT'
		elif msg.reason == ofp.OFPRR_DELETE:
			reason = 'DELETE'
		elif msg.reason == ofp.OFPRR_GROUP_DELETE:
			reason = 'GROUP DELETE'
		else:
			reason = 'unknown'

		#self.logger.info("\nThe flow of switch {} has been removed due to a {}. Some data: priority {}, duration {}, idle_timeout {}, byte_count {}, match.fields {}, avg link usage of {} Byte/s".format(dp.id, reason, msg.priority, msg.duration_sec, msg.idle_timeout, msg.byte_count, msg.match, msg.byte_count/msg.duration_sec)
		match_tuple = self.OFPMatch_to_tuple(msg.match)
		for elem in self.edge_stats:
			if self.edge_stats[elem].link[0] == dp.id:
				for match in self.edge_stats[elem].match_to_stats:
					if match == match_tuple:
						self.edge_stats[elem].remove_match_from_edge(match_tuple)
						return

	
	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def port_stats_reply_handler(self, ev):
		"""Handles what is returned to the request (to each switch) for port statistics."""
		'''
		body = ev.msg.body
		for stat in body:
			for elem in self.edge_stats:
				if (self.edge_stats[elem].link[0] == ev.msg.datapath.id) and (self.edge_stats[elem].src_port == stat.port_no):
					self.edge_stats[elem].update_weight_from_PortStatsReply(stat.tx_bytes, stat.duration_sec, stat.duration_nsec)
		'''
		pass


	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply_handler(self, ev):
		"""Handles what is returned to the request (to each switch) for flows statistics."""
		body = ev.msg.body
		for stat in body:
			for elem in self.edge_stats:
				match_temp = self.OFPMatch_to_tuple(stat.match)
				try:
					if (self.edge_stats[elem].link[0] == ev.msg.datapath.id) and \
						(self.edge_stats[elem].src_port == stat.instructions[0].actions[0].port) and \
						(match_temp[0][1] != 35020):	# eth_type!=35020: ignore lldp's default rules
						self.edge_stats[elem].update_weight_from_FlowStatsReply(stat.byte_count, stat.duration_sec, stat.duration_nsec, stat.match)
				except KeyError:
					self.logger.debug('Table-miss: the parsed_match doesn\'t contain tuples, it\'s an empty list. KeyError raised on match_temp[0][1].')
		print "sono nella funzione EventOFPFlowStatsReply e il tempo e' di {}".format(datetime.datetime.now().time())



app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')

''' 
sudo arp -d 10.10.5.103


cd
ryu/bin/ryu-manager --observe-links ryu/ryu/app/2nd_time/Total_Revolution.py

ssh pi@192.168.4.2
ssh pi@192.168.4.3

h2<---->s1
h3<---->s6


h2-->h3
h2:
iperf3 -c 10.10.5.103 -p 5000 -i 1 -t 2000 -b 5M
iperf3 -c 10.10.5.103 -p 5001 -i 1 -t 2000 -b 5M
iperf3 -c 10.10.5.103 -p 5002 -i 1 -t 2000 -b 12M --tos 0x28

h3:
iperf3 -s -p 5000 -i 1
iperf3 -s -p 5001 -i 1
iperf3 -s -p 5002 -i 1
'''