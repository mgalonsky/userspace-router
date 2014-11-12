from scapy.all import *

#Your per-packet router code goes here
def pkt_callback(pkt):
    print "Received an Ethernet packet. MAC src:", pkt.src, "MAC dst:",pkt.dst
    print pkt.summary()

    #Determine if it is an IP packet. If not then return

    #Determine if the destination IP is local to this computer. If yes, then return

    #Is the destination *network* in your routing table, if not, send ICMP "Destination host unreachable", then return

    #Decrement the TTL. If TTL=0, send ICMP for TTL expired and return.

    #Find the next hop (gateway) for the destination *network* and look up the MAC address of that router

    #Determine the outgoing interface and MAC address needed to reach the next-hop router
    OUT_IFACE="eth4"

    #Modify the SRC and DST MAC addresses to match the outgoing interface and the DST MAC found above

    #Update the IP header checksum

    #Send the packet out the proper interface as required to reach the next hop router. Use:

    sendp(pkt, iface=OUT_IFACE)

#Main code here...
if __name__ == "__main__":
    #First setup your routing table either as global variables or as objects passed to pkt_callback
    #And any other init code

    #Start the packet sniffer
    sniff(prn=pkt_callback, store=0)
