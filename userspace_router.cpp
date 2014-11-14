/*
 * Melissa Galonsky and Helen Woodward
 * A simple userspace router meant for HMC CS125 lab 5
 */


#include <iostream>
#include <string>
#include <crafter.h>
//will want to add pthread too

using namespace std;
using namespace Crafter;


//Your per-packet router code goes here
void packetHandler(Packet* packet, void* user){

	Ethernet* ethHeader = packet->GetLayer<Ethernet>();
	IP* ipHeader = packet->GetLayer<IP>();

	if (ethHeader == nullptr) {
		cout << "ethHeader was null" << endl;
	}
	else {
		ethHeader->Print();
	}
	if (ipHeader == nullptr) {
		cout << "ipHeader was null" << endl;
	}
	else {
		ipHeader->Print();
	}

	cout<<"--------------------------------------"<<endl;

    //Determine if it is an IP packet. If not then return

    //Determine if the destination IP is local to this computer. If yes, then return

    //Is the destination *network* in your routing table, if not, send ICMP "Destination host unreachable", then return

    //Decrement the TTL. If TTL=0, send ICMP for TTL expired and return.

    //Find the next hop (gateway) for the destination *network* and look up the MAC address of that router

    //Determine the outgoing interface and MAC address needed to reach the next-hop router
//    OUT_IFACE="eth4"

    //Modify the SRC and DST MAC addresses to match the outgoing interface and the DST MAC found above

    //Update the IP header checksum

    //Send the packet out the proper interface as required to reach the next hop router. Use:

	//I think this call becomes pkt.send(iface)
//    sendp(pkt, iface=OUT_IFACE)
}

//Main code here...
int main(int argc, char* argv[]){

	string iface = argv[1];
	Sniffer sniff("", iface, packetHandler);
	sniff.Capture(5);
    //First setup your routing table either as global variables or as objects passed to pkt_callback
    //And any other init code

	//set up a sniffer for all interfaces
	//if possible get 1 that uses all interfaces and call caputre on it with -1
	//otherwise will have to create a seperate sniffer for each interface and spawn each one before blocking to avoid finishing

}
