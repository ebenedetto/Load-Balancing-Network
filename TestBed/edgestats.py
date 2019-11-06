import numpy as np


class EdgeStats:
	"""Keeps track of the link's statistics.

	Attributes
	----------
	link : tuple
		The link identifier, which is of the type (src_dpid, dst_dpid)
	src_port : int
		Port of the src_dpid to which the link is connected
	dst_port : int
		Port of the dst_dpid to which the link is connected
	match_to_stats : dict
		Maps each flow on the link to its statistics
		Example:
		{
			match_1: {
						'throughput':  <float>
						'mean_throughput':  <float>
						'prev_tx_bytes':  <int>
						'curr_tx_bytes':  <int>
						'prev_alive_time':  <float>
						'curr_alive_time':  <float>
						'time_interval':  <float>
						'throughputs_array':  <list>
			}
			...
			match_N: { ... }
		}
	src_port_stats : dict
		Keeps track of the src_port statistics

	Methods
	-------
	initialize_port_dict()
		Initializes the `src_port_stats` dictionary
	add_match_to_edge(match)
		Adds an empty entry in the `match_to_stats` dictionary
	remove_match_from_edge(match)
		Deletes a match from the `match_to_stats` dictionary
	retrieve_value(match, value_string)
		Gets a value from `match_to_stats` dictionary
	update_weight_from_FlowStatsReply(byte_count, duration_sec, duration_nsec, match)
		Updates the values in the `match_to_stats` dictionary
	update_weight_from_PortStatsReply(tx_bytes, duration_sec, duration_nsec)
		Updates the values in the `src_port_stats` dictionary
	extract_fields(match)
		Returns `match` as a tuple of tuples

	"""
	def __init__(self, src_dpid, dst_dpid):
		self.link = (src_dpid, dst_dpid)
		self.src_port = 0
		self.dst_port = 0
		self.match_to_stats =  {}
		self.src_port_stats = {}
		self.initialize_port_dict()


	def initialize_port_dict(self):
		"""Sets the initial values of the src_port_stats dictionary."""
		self.src_port_stats['throughput'] =  0
		self.src_port_stats['mean_throughput'] =  0 
		self.src_port_stats['prev_tx_bytes'] =  0
		self.src_port_stats['curr_tx_bytes'] =  0 
		self.src_port_stats['prev_alive_time'] =  0 
		self.src_port_stats['curr_alive_time'] =  0 
		self.src_port_stats['time_interval'] =  0 
		self.src_port_stats['throughputs_array'] =  [] 


	def add_match_to_edge(self, match, prev_throughput=None):
		"""Adds an entry in the dictionary match_to_stats.

		The key is the match, which defines a flow.
		The values are statistical information about
		how the link is used by a specific flow.


        Parameters
        ----------
        match : class `ryu.ofproto.ofproto_v1_3_parser.OFPMatch`
            The match extracted from the packet
		
		Methods:
		--------
		extract_fields(match)
			Returns the match as a tuple of tuples

		"""
		match = self.extract_fields(match)
		#self.logger.info("Added rule {} on the link {}".format(match, self.link))
		self.match_to_stats[match] = {}
		self.match_to_stats[match]['throughput'] =  0
		self.match_to_stats[match]['mean_throughput'] =  0 
		self.match_to_stats[match]['prev_tx_bytes'] =  0
		self.match_to_stats[match]['curr_tx_bytes'] =  0 
		self.match_to_stats[match]['prev_alive_time'] =  0 
		self.match_to_stats[match]['curr_alive_time'] =  0 
		self.match_to_stats[match]['time_interval'] =  0 
		self.match_to_stats[match]['throughputs_array'] =  [] 
		if prev_throughput == None:
			self.match_to_stats[match]['prev_throughput'] = 0
		else:
			self.match_to_stats[match]['prev_throughput'] = prev_throughput
			print match
			print "assegnato il prev throughput di {}".format(self.match_to_stats[match]['prev_throughput'])


	def remove_match_from_edge(self, match):
		"""Deletes the entry associated to the passed match from the dictionary."""
		#self.logger.info("Removed rule {} from the link {}".format(match, self.link))
		del self.match_to_stats[match]
		#self.logger.info("Here's the dictionary now {}".format(self.match_to_stats))


	def retrieve_value(self, match, value_string):
		"""Returns a specific value in the match_to_stats dictionary.
		
		Parameters
		----------
		match : class 'ryu.ofproto.ofproto_v1_3_parser.OFPMatch'
			Match field in the message
		value_string: string 
			Addresses the specific required value

		"""
		return self.match_to_stats[match][value_string]


	def update_weight_from_FlowStatsReply(self, byte_count, duration_sec, duration_nsec, match):
		"""Updates flow statistics.

		It's called in the FlowStatsReply function of the LoadBalancingSwitch class.

		Parameters
		----------
		byte_count : int
			Number of bytes of a flow
		duration_sec : int
			Time flow has been alive in seconds
		duration_nsec : float
			Time flow has been alive in nanoseconds beyond duration_sec
		match : class 'ryu.ofproto.ofproto_v1_3_parser.OFPMatch'
			Match field in the message

		Methods
		-------
		extract_fields(match) : tuple
			Returns the match as a tuple of tuples

		"""
		match = self.extract_fields(match)
		'''
		Gli switch sul testbed mandano delle statistiche con duration_sec = 0 e byte_count > 0. Questo
		perche' gli switch forniscono il valore di duration_nsec sempre uguale a 0 e quindi non ho
		sensibilita' su tempi brevi.
		PROBLEMA: il calcolo del throughput non puo' essere fatto perche' dovrei dividere per 0.
		SOLUZIONE:	Ignorare i valori forniti e azzerare quelli salvati. Al prossiamo giro di richieste
					duration_sec sara' > 0 e potro' calcolare il throughput
		'''
		if (duration_sec + duration_nsec * 10**(-18)) == 0:
			self.match_to_stats[match] = {}
			self.match_to_stats[match]['throughput'] =  0
			self.match_to_stats[match]['mean_throughput'] =  0 
			self.match_to_stats[match]['prev_tx_bytes'] =  0
			self.match_to_stats[match]['curr_tx_bytes'] =  0 
			self.match_to_stats[match]['prev_alive_time'] =  0 
			self.match_to_stats[match]['curr_alive_time'] =  0 
			self.match_to_stats[match]['time_interval'] =  0 
			self.match_to_stats[match]['throughputs_array'] =  [] 
			return

		self.match_to_stats[match]['curr_alive_time'] = duration_sec + duration_nsec * 10**(-18)
		self.match_to_stats[match]['time_interval'] = (self.match_to_stats[match]['curr_alive_time'] - self.match_to_stats[match]['prev_alive_time'])
		if self.match_to_stats[match]['time_interval'] < 0:
			print "Achtung! Time < 0 for the rule of the link {} - {}, src_port {}, match {}, something is not right :<".format(self.link[0], self.link[1], self.src_port, match)
			print "Values: curr_tx_bytes {},  curr_alive_time {}, time_interval {}".format(self.match_to_stats[match]['curr_tx_bytes'],self.match_to_stats[match]['curr_alive_time'], self.match_to_stats[match]['time_interval'] )
		if self.match_to_stats[match]['prev_throughput'] != 0:
			self.match_to_stats[match]['throughput'] = self.match_to_stats[match]['prev_throughput']
			self.match_to_stats[match]['prev_throughput'] = 0
		else:
			try:
				self.match_to_stats[match]['throughput'] = (self.match_to_stats[match]['curr_tx_bytes'] - self.match_to_stats[match]['prev_tx_bytes'])/self.match_to_stats[match]['time_interval']
			except:
				print "\n Divisione per zero: Tempo attuale della statistica {}".format(self.match_to_stats[match]['curr_alive_time'])
				print "Tempo precedente della statistica {}".format(self.match_to_stats[match]['prev_alive_time'])
		if self.match_to_stats[match]['throughput'] > 2000000:
			print match
			print "\n Tempo attuale della statistica {} e valore {} e del prev_throughput e' di {}".format(self.match_to_stats[match]['curr_alive_time'], self.match_to_stats[match]['curr_tx_bytes'], self.match_to_stats[match]['prev_throughput'])
			print "Tempo precedente della statistica {} e valore {}".format(self.match_to_stats[match]['prev_alive_time'], self.match_to_stats[match]['prev_tx_bytes'])
		self.match_to_stats[match]['prev_alive_time'] = self.match_to_stats[match]['curr_alive_time']
		self.match_to_stats[match]['prev_tx_bytes'] = byte_count
		self.match_to_stats[match]['throughputs_array'].append(self.match_to_stats[match]['throughput'])
		self.match_to_stats[match]['mean_throughput'] = np.mean(self.match_to_stats[match]['throughputs_array'])
		'''
		if match[0][1] == 2048 and match [1][1] == '10.10.5.102' and match[6][1] == 5000:
			print "il valore di throughput e' di {}".format(self.match_to_stats[match]['throughput'])
			print "il valore di curr_tx_bytes e' di {}".format(self.match_to_stats[match]['curr_tx_bytes'])
			print "il valore di curr_alive_time e' di {}".format(self.match_to_stats[match]['curr_alive_time'])
			print "il valore di time_interval e' di {}".format(self.match_to_stats[match]['time_interval'])
			print "il valore di throughputs_array e' di {}".format(self.match_to_stats[match]['throughputs_array'])
			print "il valore di prev_throughput e' di {}".format(self.match_to_stats[match]['prev_throughput'])
		'''


	def update_weight_from_PortStatsReply(self, tx_bytes, duration_sec, duration_nsec):
		"""Updates port statistics.

		It's called in the PortStatsReply function of the LoadBalancingSwitch class.

		Parameters
		----------
		tx_bytes : int
			Number of transmitted bytes from the beginning
		duration_sec : int
			Time port has been alive in seconds
		duration_nsec : float
			Time port has been alive in nanoseconds beyond duration_sec

		"""
		self.src_port_stats['curr_tx_bytes'] = tx_bytes
		self.src_port_stats['curr_alive_time'] = duration_sec + duration_nsec * 10**(-18)
		self.src_port_stats['time_interval'] = self.src_port_stats['curr_alive_time'] - self.src_port_stats['prev_alive_time']
		if self.src_port_stats['time_interval'] < 0:
			print "Achtung! Time < 0 for the rule of the link {} - {}, something is not right :<".format(self.link[0], self.link[1])
			print "Values: curr_tx_bytes {},  curr_alive_time {}, time_interval {}".format(self.src_port_stats['curr_tx_bytes'],self.src_port_stats['curr_alive_time'], self.src_port_stats['time_interval'] )
		self.src_port_stats['prev_alive_time'] = self.src_port_stats['curr_alive_time']
		try:
			self.src_port_stats['throughput'] = (self.src_port_stats['curr_tx_bytes'] - self.src_port_stats['prev_tx_bytes']) / self.src_port_stats['time_interval']
		except ZeroDivisionError:
			pass
		self.src_port_stats['prev_tx_bytes'] = tx_bytes
		self.src_port_stats['throughputs_array'].append(self.src_port_stats['throughput'])
		self.src_port_stats['mean_throughput'] = np.mean(self.src_port_stats['throughputs_array'])


	def extract_fields(self, match):
		"""Extracts the fields that identify a flow and returns them as a tuple.

		Parameters
		----------
		match : class `ryu.ofproto.ofproto_v1_3_parser.OFPMatch`
			Match field in the message

		Returns
		-------
		tuple
			A tuple of tuples of the extracted fields
			Example:
			(
				('eth_type', 2048), 
				('ipv4_src', '10.0.0.2'), 
				('ipv4_dst', '10.0.0.1'), 
				('ip_dscp', 14) 
				('ip_proto', 6), 
				('tcp_src', 48744), 
				('tcp_dst', 4000) 
			)

		"""
		match_array = [0,0,0,0,0,0,0]
		for field in match._fields2:
			if field[0] == 'eth_type': 
				match_array[0] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'ipv4_src': 
				match_array[1] = (field[0], field[1]) # field[1] type str
			elif field[0] == 'ipv4_dst': 
				match_array[2] = (field[0], field[1]) # field[1] type str
			elif field[0] == 'ip_dscp': 
				match_array[3] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'ip_proto':
				match_array[4] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'udp_src' or field[0] == 'tcp_src': 
				match_array[5] = (field[0], field[1]) # field[1] type int
			elif field[0] == 'udp_dst' or field[0] == 'tcp_dst': 
				match_array[6] = (field[0], field[1]) # field[1] type int
		return tuple(match_array)

