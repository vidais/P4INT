"""Custom topology example

Eight switches where two are sink nodes plus creating three routes with different speeds:


Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
# from mininet.link import TCLink

class TopoProject( Topo ):
    "Topology used for the project."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost2 = self.addHost( 'h2' )
        rightHost3 = self.addHost( 'h3' )
        rightHost4 = self.addHost( 'h4' )
        rightHost5 = self.addHost( 'h5' )
        rightHost6 = self.addHost( 'h6' )
   

        leftSwitch = self.addSwitch( 's1' )

        topLeftSwitch = self.addSwitch('s2')
        topRightSwitch = self.addSwitch('s3')

        middleLeftSwitch = self.addSwitch('s7')
        middleRightSwitch = self.addSwitch('s8')
        
        bottomLeftSwitch = self.addSwitch('s4')
        bottomRightSwitch = self.addSwitch('s5')

        rightSwitch = self.addSwitch( 's6' )

        # Add links
        self.addLink( leftHost, leftSwitch)

        # TOP Link
        self.addLink( leftSwitch, topLeftSwitch )
        self.addLink( topLeftSwitch, topRightSwitch )
        self.addLink( topRightSwitch, rightSwitch )

        # Middle Link
        self.addLink( leftSwitch, middleLeftSwitch )
        self.addLink( middleLeftSwitch, middleRightSwitch )
        self.addLink( middleRightSwitch, rightSwitch )
         
        #Bottom Link
        self.addLink( leftSwitch, bottomLeftSwitch )
        self.addLink( bottomLeftSwitch, bottomRightSwitch )
        self.addLink( bottomRightSwitch, rightSwitch )

        self.addLink( rightSwitch, rightHost2 )
        self.addLink( rightSwitch, rightHost3 )
        self.addLink( rightSwitch, rightHost4 )
        self.addLink( rightSwitch, rightHost5 )
        self.addLink( rightSwitch, rightHost6 )


topos = { 'topoproj': ( lambda: TopoProject() ) }
