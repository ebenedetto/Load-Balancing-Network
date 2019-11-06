<!-- markdownlint-disable MD014 --->
<!-- markdownlint-disable MD007 --->
<!-- markdownlint-disable MD010 --->
<!-- markdownlint-disable MD001 --->

# Tutorial 1

This tutorial is aimed at showing that the controller:

- allocates flows based on the shortest path, avoiding overloaded links;
- if a link is above a certain threshold (_LINK_THRESHOLD_), scans the active flows in that link and reallocates the one with the lowest DSCP;
	- among flows with the same DSCP, it chooses the one with highest bandwidth.

## Controller settings

~~~python
DEFAULT_WEIGHT = 1
NUMBER_OF_SWITCH_PORTS = 6
SLEEP = 8
SLEEP_TH = SLEEP * 2
SLEEP_PLOT = SLEEP_TH * 2
MAGNITUDE_MEGA_BYTES = 10**6
LINK_THRESHOLD = 103 * MAGNITUDE_MEGA_BYTES
MAG_STR = "MByte"
MAX_RTT_ADMITTED = 2
PKT_IN_STOP_TIMER = 20
MIN_FLOW_BW = 0.3
~~~

## Commands for `ryu` and `mininet`

Open 2 terminal windows.

### Controller

To start the controller, from one of the terminals, run:

~~~bash
PHYTHONPATH=. /home/ryu/ryu/bin/ryu-manager --observe-links /path/to/the/controllers/file/load_balancer.py
~~~

### Topology

![tutorial1_1](../docs/images/tutorial_1/1_0.png)

AFTER the controller has started, from the other terminal, run:

~~~bash
$ cd /path/to/the/file/of/the/topology
$ sudo mn --custom tutorial1_topo.py --topo mytopo --controller=remote
~~~

When the topology has been created, from the **mininet CLI**:

~~~bash
mininet> xterm h1 h1 h1 h1 h1
mininet> xterm h4 h5 h6 h7 h7
~~~

### Commands for `XTerm`

###### Constraints

The following constraints apply:

- Connections MUST start:
	- In the given order
	- Immediately after the statistics' update (so after the "-"*60 print)
		- This has to be done because, for each connection, `iPerf3` starts 3 connections (with different TCP ports and ToS 0) before starting the definitive one with the correct ToS: that requires some time
		- If a connection starts and, in the meantime, statistics' update, the definitive flow won't follow the predicted path: it sees that the first path was used (by those 3 starting connections) and so it searches for a better one
- After the first connection has been set up, before starting another connection, wait AT LEAST 2 statistics' updates
	- In order to let the previously installed connection stabilize at the rate specified in the `iPerf3` command (TCP slowstart mechanism)
- The bandwidth must be specified in bit/s and not in Byte/s

*To paste commands in the XTerm windows, use "middle click" or "shift-insert".*

#### Servers (h1)

In each _h1_ XTerm window, using `iPerf3`, start a server (_-s_). Each server is listening for TCP connections on the port specified by the flag _-p_ and will print the transmitted bytes and the bandwidth every second (flag _-i_).

N.B. The port numbers can be changed, but each server must have its own unique number of port. The time interval specified with the flag _-i_ can be changed, or omitted.

~~~bash
iperf3 -s -p 4000 -i 1
~~~

~~~bash
iperf3 -s -p 5000 -i 1
~~~

~~~bash
iperf3 -s -p 6000 -i 1
~~~

~~~bash
iperf3 -s -p 7000 -i 1
~~~

~~~bash
iperf3 -s -p 7500 -i 1
~~~

#### Hosts (h4, h5, h6, h7 h7)

Respecting the [constraints](#Constraints), start the TCP connections.
The flags are:

- _-c_ : tells the client to connect to an `iPerf3` server running on a specified host, in our example it's always _h1_ (IP address 10.0.0.1)
- _-p_ : specifies the port the server is listening on, and to which the client connects to
- _-t_ : how long the connection lasts, in seconds
- _-i_ : the time interval in seconds between periodic bandwidth, jitter, and loss reports
	- can be omitted
- _-b_ : target bandwidth of _N_ bits/sec
- _-S_ : type-of-service for outgoing packets
	- if omitted, it defaults to zero
	- ToS = 0x38<sub>hex</sub> = 56<sub>dec</sub> ==> DSCP = 14<sub>dec</sub>

~~~bash
iperf3 -c 10.0.0.1 -p 4000 -t 500 -i 1 -b 560M -S 0x38
~~~

![2_0](../docs/images/tutorial_1/1_1.png)

~~~bash
iperf3 -c 10.0.0.1 -p 5000 -t 500 -i 1 -b 200M -S 0x38
~~~

![1_2](../docs/images/tutorial_1/1_2.png)

~~~bash
iperf3 -c 10.0.0.1 -p 6000 -t 500 -i 1 -b 400M -S 0x38
~~~

![1_3](../docs/images/tutorial_1/1_3.png)

~~~bash
iperf3 -c 10.0.0.1 -p 7000 -t 500 -i 1 -b 80M
~~~

![1_4](../docs/images/tutorial_1/1_4.png)

~~~bash
iperf3 -c 10.0.0.1 -p 7500 -t 500 -i 1 -b 560M -S 0x38
~~~

![1_5](../docs/images/tutorial_1/1_5.png)

The flow with the lowest ToS (the 4th one, between h1 and h7) is reallocated.

![1_final](../docs/images/tutorial_1/1_final.png)

## Results

[Link to Youtube video](https://youtu.be/1yEEJhPy4O8)
