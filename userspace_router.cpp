/*
 * Melissa Galonsky and Helen Woodward
 * A simple userspace router meant for HMC CS125 lab 5
 */


#include <iostream>
#include <string>
#include <crafter.h>
#include <fstream>

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

map<string, string> destToNextHop;
map<string, HeaderFields> nextHopToHeaderFields;
set<string> localIPs;
set<string> ifaces;

//Your per-packet router code goes here
void packetHandler(Packet* packet, void* user){

	Ethernet* ethHeader = packet->GetLayer<Ethernet>();
	IP* ipHeader = packet->GetLayer<IP>();

	if (ethHeader == nullptr) {
		cout << "ethHeader was null" << endl;
		return;
	}
	if (ipHeader == nullptr) {
		cout << "ipHeader was null" << endl;
		return;
	}
	
	string DestIP = ipHeader->GetDestinationIP();

	//check if local to this machine (if it is, return)
	if (localIPs.find(DestIP) != localIPs.end()) {
		return;
	}

	auto destIter = destToNextHop.find(DestIP);
	//see if DestIP is in our routing tables
	if (destIter == destToNextHop.end()) {
		//send ICMP for destination unreachable here
		return;
	}
	
	int ttl = ipHeader->GetTTL();
	ttl--;
	if(ttl == 0) {
		//send ICMP for ttl=0 here
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

	//set up a sniffer for all interfaces
	for(string iface : ifaces) {
		Sniffer sniff("", iface, packetHandler);
		sniff.Spawn(-1);
	}

	//wait forever
	while(1){}
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

			destToNextHop.insert(pair<string, string>(dest, nextHop));

			//Create a HeaderFields to store as much as possible without arping
			HeaderFields newHeaderField;
			newHeaderField.iface = iface;
			newHeaderField.sourceMAC = GetMyMAC(iface);

			nextHopToHeaderFields.insert(pair<string, HeaderFields>(nextHop, newHeaderField));
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
		
		ifaces.insert(curr_pair.second.iface);
		string myIP = GetMyIP(curr_pair.second.iface);
		localIPs.insert(myIP);

		arpHeader.SetOperation(ARP::Request);
		arpHeader.SetSenderIP(myIP);
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
