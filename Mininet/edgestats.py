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


	def add_match_to_edge(self, match):
		"""Adds an entry in the dictionary match_to_stats.

		The key is the match, which defines a flow.
		The values are statistical information about how
		the link is used by a specific flow over time.


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



	def remove_match_from_edge(self, match):
		"""Deletes the entry associated to the passed match from the dictionary.

		Parameters
		----------
		match : class 'ryu.ofproto.ofproto_v1_3_parser.OFPMatch'
			Match field in the message

		"""
		#self.logger.info("Removed rule {} from the link {}".format(match, self.link))
		del self.match_to_stats[match]
		#self.logger.info("Here's the dictionary now {}".format(self.match_to_stats))


	def retrieve_value(self, match, value_string):
		"""Returns a specific value in the `match_to_stats` dictionary.
		
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
			Time the flow has been alive in seconds
		duration_nsec : float
			Time the flow has been alive in nanoseconds beyond duration_sec
		match : class 'ryu.ofproto.ofproto_v1_3_parser.OFPMatch'
			Match field in the message

		Methods
		-------
		extract_fields(match) : tuple
			Returns the match as a tuple of tuples

		"""
		match = self.extract_fields(match)
		self.match_to_stats[match]['curr_tx_bytes'] = byte_count
		self.match_to_stats[match]['curr_alive_time'] = duration_sec + duration_nsec * 10**(-18)
		self.match_to_stats[match]['time_interval'] = (self.match_to_stats[match]['curr_alive_time'] - self.match_to_stats[match]['prev_alive_time'])
		if self.match_to_stats[match]['time_interval'] < 0:
			self.logger.debug("Time < 0 for the rule of the link {} - {}, src_port {}, match {}, something's not right :<".format(self.link[0], self.link[1], self.src_port, match))
			self.logger.debug("Values: curr_tx_bytes {},  curr_alive_time {}, time_interval {}".format(self.match_to_stats[match]['curr_tx_bytes'],self.match_to_stats[match]['curr_alive_time'], self.match_to_stats[match]['time_interval']))
		self.match_to_stats[match]['prev_alive_time'] = self.match_to_stats[match]['curr_alive_time']
		self.match_to_stats[match]['throughput'] = (self.match_to_stats[match]['curr_tx_bytes'] - self.match_to_stats[match]['prev_tx_bytes'])/self.match_to_stats[match]['time_interval']
		self.match_to_stats[match]['prev_tx_bytes'] = byte_count
		self.match_to_stats[match]['throughputs_array'].append(self.match_to_stats[match]['throughput'])
		self.match_to_stats[match]['mean_throughput'] = np.mean(self.match_to_stats[match]['throughputs_array'])


	def update_weight_from_PortStatsReply(self, tx_bytes, duration_sec, duration_nsec):
		"""Updates port statistics.

		It's called in the PortStatsReply function of the LoadBalancingSwitch class.

		Parameters
		----------
		tx_bytes : int
			Number of transmitted bytes from the beginning
		duration_sec : int
			Time the port has been alive in seconds
		duration_nsec : float
			Time the port has been alive in nanoseconds beyond duration_sec

		"""
		self.src_port_stats['curr_tx_bytes'] = tx_bytes
		self.src_port_stats['curr_alive_time'] = duration_sec + duration_nsec * 10**(-18)
		self.src_port_stats['time_interval'] = self.src_port_stats['curr_alive_time'] - self.src_port_stats['prev_alive_time']
		if self.src_port_stats['time_interval'] < 0:
			self.logger.debug("Time < 0 for the rule of the link {} - {}, src_port {}, match {}, something's not right :<".format(self.link[0], self.link[1]))
			self.logger.debug("Values: curr_tx_bytes {},  curr_alive_time {}, time_interval {}".format(self.src_port_stats['curr_tx_bytes'],self.src_port_stats['curr_alive_time'], self.src_port_stats['time_interval']))
		self.src_port_stats['prev_alive_time'] = self.src_port_stats['curr_alive_time']
		self.src_port_stats['throughput'] = (self.src_port_stats['curr_tx_bytes'] - self.src_port_stats['prev_tx_bytes']) / self.src_port_stats['time_interval']
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