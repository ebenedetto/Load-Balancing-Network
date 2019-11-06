# Tutorial <a name="tutorial"></a>

## Tutorial 0 <a name="tutorial0"></a>

This tutorial describes how to setup the environment in which this project is defined.

### Mininet 

**Mininet** is a *network emulator* which creates a realistic virtual network with virtual hosts, switches, controllers, and links (on a single machine (VM, cloud or native). Mininet hosts run standard Linux network software, and its switches support OpenFlow for highly flexible custom routing and Software-Defined Networking.

In order to download and install *Mininet* the following steps must be performed:

1. Download the [Mininet VM image](https://github.com/mininet/mininet/wiki/Mininet-VM-Images).
2. Download and install a virtualization system: [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (free, GPL) it is free and works on OS X, Windows, and Linux.
3. Run through the [VM Setup Notes](http://mininet.org/vm-setup-notes/)  to log in to the VM and customize it as desired.
4. Follow the [Walkthrough](http://mininet.org/walkthrough) to get familiar with Mininet commands and typical usage.

### Ryu

**Ryu** is a component-based software defined networking framework. Ryu provides software components with well defined API that make it easy for developers to create new network management and control applications. Ryu supports various southbound protocols for managing network devices, such as [OpenFlow](https://www.opennetworking.org/), Netconf, OF-config, etc.

The easiest way to download and install *ryu* is to use the *pip* command

```
% pip install ryu
```

Once the installation process is done a simple tutorial can be found [here](https://ryu.readthedocs.io/en/latest/getting_started.html)

<div style="page-break-after: always;"></div>
