from mininet.topo import Topo

class TopoProject:
    def __init__(self):
    
        Topo.__init__(self)

        h0 = self.addHost('h0')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        sw0 = self.addSwitch('sw0')
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        sw4 = self.addSwitch('sw4')
        sw5 = self.addSwitch('sw5')
        sw6 = self.addSwitch('sw6')

        self.addLink(sw0,h0)
        self.addLink(sw0,h1)

        self.addLink(sw6,h2)
        self.addLink(sw6,h3)
        self.addLink(sw6,h4)


        self.addLink(sw6,sw5)

        self.addLink(sw5,sw4)
        self.addLink(sw5,sw3)
        
        self.addLink(sw4,sw2)
        self.addLink(sw3,sw2)
        self.addLink(sw3,sw1)
 
        self.addLink(sw2,sw0)
        self.addLink(sw1,sw0)

topos = { 'topoproj': ( lambda: TopoProject() ) }