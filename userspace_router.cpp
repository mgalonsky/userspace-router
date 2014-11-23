/*
 * Melissa Galonsky and Helen Woodward
 * A simple userspace router meant for HMC CS125 lab 5
 */


#include <iostream>
#include <string>
#include <crafter.h>
#include <fstream>
#include <unistd.h>

using namespace std;
using namespace Crafter;



struct HeaderFields
{
	string iface;
	string sourceMAC;
	string destMAC;
};

// Parses the file routing.config and sets up the routing tables accordingly
void parseConfig();

// ARP to complete setting up the tables
void arp();

// Convert an ip to its /24 subnet
string IPtoSubnet(string &IP);

map<string, string> destToNextHop;
map<string, HeaderFields> nextHopToHeaderFields;
set<string> localIPs;
set<string> ifaces;

//Your per-packet router code goes here
void packetHandler(Packet* packet, void* user){

	string myIface = *(string*) user;

	Ethernet* ethHeader = packet->GetLayer<Ethernet>();
	IP* ipHeader = packet->GetLayer<IP>();

	if (ethHeader == nullptr) {
		cerr << "ethHeader was null" << endl;
		return;
	}

	if(ethHeader->GetSourceMAC() == GetMyMAC(myIface)) {
		cerr<< "sourceMAC was ourselves" << endl;
		return;
	}

	if (ipHeader == nullptr) {
		cerr << "ipHeader was null" << endl;
		return;
	}
	
	string DestIP = ipHeader->GetDestinationIP();
	string DestNet = IPtoSubnet(DestIP);
	//check if local to this machine (if it is, return)
	if (localIPs.find(DestNet) != localIPs.end()) {
		cerr<<"packet was in local subnet"<<endl;
		return;
	}

	auto destIter = destToNextHop.find(DestNet);
	//see if DestIP is in our routing tables
	if (destIter == destToNextHop.end()) {
		cerr << "packet was unreachable" << endl;
		//send ICMP for destination unreachable here
		ICMP icmpHeader;
		icmpHeader.SetType(ICMP::DestinationUnreachable);
		icmpHeader.SetIdentifier(RNG16());
		byte* buffer = new byte[ipHeader->GetSize()];
		ipHeader->GetRawData(buffer);
		icmpHeader.AddPayload(buffer, ipHeader->GetHeaderSize() + 8);
		IP icmpIPHeader;
		icmpIPHeader.SetDestinationIP(ipHeader->GetSourceIP());
		icmpIPHeader.SetSourceIP(GetMyIP(myIface));
		Ethernet icmpEthHeader;
		icmpEthHeader.SetSourceMAC(GetMyMAC(myIface));
		icmpEthHeader.SetDestinationMAC(ethHeader->GetSourceMAC());
		Packet icmpPkt;
		icmpPkt.PushLayer(icmpEthHeader);
		icmpPkt.PushLayer(icmpIPHeader);
		icmpPkt.PushLayer(icmpHeader);
		icmpPkt.Send(myIface);
		delete[] buffer;
		return;
	}
	
	int ttl = ipHeader->GetTTL();
	cerr << "ttl was: " << ttl << endl;
	ttl--;
	if(ttl == 0) {
		//send ICMP for ttl=0 here
		ICMP icmpHeader;
		icmpHeader.SetType(ICMP::TimeExceeded);
		icmpHeader.SetIdentifier(RNG16());
		byte* buffer = new byte[ipHeader->GetSize()];
		ipHeader->GetRawData(buffer);
		icmpHeader.AddPayload(buffer, ipHeader->GetHeaderSize() + 8);
		IP icmpIPHeader;
		icmpIPHeader.SetDestinationIP(ipHeader->GetSourceIP());
		icmpIPHeader.SetSourceIP(GetMyIP(myIface));
		Ethernet icmpEthHeader;
		icmpEthHeader.SetSourceMAC(GetMyMAC(myIface));
		icmpEthHeader.SetDestinationMAC(ethHeader->GetSourceMAC());
		Packet icmpPkt;
		icmpPkt.PushLayer(icmpEthHeader);
		icmpPkt.PushLayer(icmpIPHeader);
		icmpPkt.PushLayer(icmpHeader);
		icmpPkt.Send(myIface);
		return;
	}
	ipHeader->SetTTL(ttl);
	
	auto headerIter = nextHopToHeaderFields.find(destIter->second);
	if (headerIter == nextHopToHeaderFields.end()) {
		//somehting is realy wrong with your config, but OK
		return;
	}

	ethHeader->SetSourceMAC(headerIter->second.sourceMAC);
	ethHeader->SetDestinationMAC(headerIter->second.destMAC);

	packet->Send(headerIter->second.iface);
}

int main(int argc, char* argv[]){

    //First setup your routing table either as global variables or as objects passed to pkt_callback

	parseConfig();
	cerr<<"finished parsing config"<<endl;
	arp();
	cerr<<"finished arping"<<endl;
	string eth0 = "eth3";
	string eth2 = "eth2";
	Sniffer sniff("", eth0, packetHandler);
       	sniff.Spawn(-1, (void *)&eth0);
	Sniffer sniff2("", eth2, packetHandler);
	sniff2.Capture(-1, (void *)&eth2);
	/*
	//set up a sniffer for all interfaces
	auto beforeEnd = ifaces.end()--;
	for (auto ifaceIter = ifaces.begin(); ifaceIter != beforeEnd; ifaceIter++) {
		Sniffer sniff("", *ifaceIter, packetHandler);
		sniff.Spawn(-1, (void *)&*ifaceIter);
		cerr<<"spawn for " + *ifaceIter<<endl;
	}
	cerr<<"capture for "+*beforeEnd<<endl;
	Sniffer sniff("", *beforeEnd, packetHandler);
	sniff.Capture(-1, (void *)&*beforeEnd);
	*/
}

void parseConfig(){
	string line;
	ifstream configFile("routing.config");
	if (configFile.is_open())
	{
		while (getline(configFile, line))
		{
			string dest;
			string nextHop;
			string iface;

			//Extract all three values from the line and put 
			//them into their respective strings

			size_t pos = line.find("|");
			dest = line.substr(0, pos);
			line.erase(0, pos+1);
			pos = line.find("|");
			nextHop = line.substr(0, pos);
			line.erase(0, pos+1);
			iface = line;
			cerr<<"Parsed the line with dest: "+dest+", nextHop: "+nextHop+", and iface: "+iface<<endl;

			if(dest != "fake") {
				destToNextHop.insert(pair<string, string>(dest, nextHop));
				//Create a HeaderFields to store as much as possible without arping
				HeaderFields newHeaderField;
				newHeaderField.iface = iface;
				newHeaderField.sourceMAC = GetMyMAC(iface);

				nextHopToHeaderFields.insert(pair<string, HeaderFields>(nextHop, newHeaderField));
			}
			cerr << "found iface: "+iface << endl;
			ifaces.insert(iface);
			string myIP = GetMyIP(iface);
			string myNet = IPtoSubnet(myIP);
			cerr << "found local subnet: "+myNet<<endl;
			localIPs.insert(myNet);
		}
	}
}

void arp()
{
	Ethernet ethHeader;
	ARP arpHeader;

	for (auto &curr_pair : nextHopToHeaderFields)
	{
		ethHeader.SetSourceMAC(curr_pair.second.sourceMAC);
		ethHeader.SetDestinationMAC("ff:ff:ff:ff:ff:ff");
		
		arpHeader.SetOperation(ARP::Request);
		arpHeader.SetSenderIP(GetMyIP(curr_pair.second.iface));
		arpHeader.SetSenderMAC(curr_pair.second.sourceMAC);
		arpHeader.SetTargetIP(curr_pair.first);

		Packet* packet = new Packet;

		packet->PushLayer(ethHeader);
		packet->PushLayer(arpHeader);

		Packet* rcv = packet->SendRecv(curr_pair.second.iface);

		ARP* arp_layer = rcv->GetLayer<ARP>();
		curr_pair.second.destMAC = arp_layer->GetSenderMAC();

	}
}

string IPtoSubnet(string &ip) {
	int pos = ip.rfind(".");
	string net = ip.substr(0, pos);
	return net;
}
