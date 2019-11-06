<!-- markdownlint-disable MD014 --->
<!-- markdownlint-disable MD007 --->
<!-- markdownlint-disable MD010 --->
<!-- markdownlint-disable MD001 --->

# Tutorial 2

This tutorial aims at showing that, when a flow reallocation occurs, the controller does not consider the weight of the flow that is going to be reallocated (on the links of the path where this flow is, just before the reallocation) when looking for a new path.

## Controller settings

~~~python
DEFAULT_WEIGHT = 1
NUMBER_OF_SWITCH_PORTS = 4
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

![2_0](../docs/images/tutorial_2/2_01.png)

AFTER the controller has started, from the other terminal, run:

~~~bash
$ cd /path/to/the/file/of/the/topology
$ sudo mn --custom tutorial2_topo.py --topo mytopo --controller=remote
~~~

When the topology has been created, from the **mininet CLI**:

~~~bash
mininet> xterm h1 h4 h6
mininet> xterm h1 h3 h5
~~~

### Commands for `XTerm`

###### Constraints

All 3 connections must start

- simultaneously (one after the other, without waiting), this way the shortest path algorithm will allocate them relying on the same statistics (so h1-->h2 will not be affected by the flow on h5-->h6)
- immediately after the statistics' update (so after the "-"*60 print)
	- this has to be done because, for each connection, `iPerf3` starts 3 connections (with different TCP ports and ToS 0) before starting the definitive one with the correct ToS, and that requires some time
	- if a connection starts and, in the meantime, statistics' update, the definitive flow won't follow the predicted path: it sees that the first path was used (by those 3 starting connections) and so it searches for a better one

This way, the shortest path will not be different from the predicted one, because the controller will base its calculations on the same links' weights for all 3 connections.

It can happen that the weight of a link without the value of the flow being reallocated is different from 0, even if there is just 1 flow.
This occurs because we assign weights to arcs looking at the throughput of the source port of the link, and this value is usually different from the sum of all the flows' thoughputs on that link (because the requested flows' and ports' statistics do not arrive simultaneously to the controller).

*To paste commands in the xterm windows, use "middle click" or "shift-insert".*

##### `iPerf3` flags

- _-c_ : tells the client to connect to an `iPerf3` server running on a host, identified by its IP address
- _-p_ : specifies the port the server is listening on, and to which the client connects to
- _-t_ : how long the connection lasts, in seconds
- _-i_ : the time interval in seconds between periodic bandwidth, jitter, and loss reports
	- can be omitted
- _-b_ : target bandwidth of _N_ bits/sec
- _-S_ : type-of-service for outgoing packets
	- if omitted, it defaults to zero
	- ToS = 0x24<sub>hex</sub> = 36<sub>dec</sub> ==> DSCP = 9<sub>dec</sub>

#### First connection

##### Server (h2)

~~~bash
iperf3 -s -p 5000 -i 1
~~~

##### Host (h1)

~~~bash
iperf3 -c 10.0.0.2 -p 5000 -t 500 -i 1 -b 400M
~~~

#### Second connection

##### Server (h4)

~~~bash
iperf3 -s -p 4000 -i 1
~~~

##### Host (h3)

~~~bash
iperf3 -c 10.0.0.4 -p 4000 -t 500 -i 1 -b 160M -S 0x24
~~~

#### Third connection

##### Server (h6)

~~~bash
iperf3 -s -p 6000 -i 1
~~~

##### Host (h5)

~~~bash
iperf3 -c 10.0.0.6 -p 6000 -t 500 -i 1 -b 640M -S 0x24
~~~

## Results

After the 3 connections are started, the situation of the network is the following:

![2_1](../docs/images/tutorial_2/2_11.png)

The link that connects s8 and s9 has exceeded the set threshold: one of the flows on that link will be reallocated.

![2_2](../docs/images/tutorial_2/2_21.png)

Since the blue connection has a ToS value which is lower than the one of the green connection, it is reallocated. The new path still contains the (1, 8) link, thus the shortest path is computed without considering the throughput of the reallocated flow.

![2_3](../docs/images/tutorial_2/2_31.png)

---

[Link to Youtube video](https://youtu.be/W95KeX04cLM)
