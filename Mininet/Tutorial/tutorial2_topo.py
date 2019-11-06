from mininet.topo import Topo

class MyTopo(Topo):

   def __init__(self):
       "Create custom topo."

       # Initialize topology
       Topo.__init__( self )

       # Add hosts, mac="00:00:00:00:00:0*"
       h1 = self.addHost('h1', mac="00:00:00:00:00:01")
       h2 = self.addHost('h2', mac="00:00:00:00:00:02")
       h3 = self.addHost('h3', mac="00:00:00:00:00:03")
       h4 = self.addHost('h4', mac="00:00:00:00:00:04")
       h5 = self.addHost('h5', mac="00:00:00:00:00:05")
       h6 = self.addHost('h6', mac="00:00:00:00:00:06")

       # Add switches
       s1 = self.addSwitch('s1')
       s2 = self.addSwitch('s2')
       s3 = self.addSwitch('s3')
       s4 = self.addSwitch('s4')
       s5 = self.addSwitch('s5')
       s6 = self.addSwitch('s6')
       s7 = self.addSwitch('s7')
       s8 = self.addSwitch('s8')
       s9 = self.addSwitch('s9')

       # Add links 
       self.addLink(h1, s1)
       self.addLink(h2, s7)
       self.addLink(h3, s2)
       self.addLink(h4, s3)
       self.addLink(h5, s8)
       self.addLink(h6, s9)
       self.addLink(s1, s2)
       self.addLink(s2, s3)
       self.addLink(s3, s4)
       self.addLink(s4, s5)
       self.addLink(s5, s6)
       self.addLink(s6, s7)
       self.addLink(s7, s9)
       self.addLink(s9, s8)
       self.addLink(s8, s1)
       self.addLink(s8, s5)


topos = {'mytopo': ( lambda: MyTopo() )}

