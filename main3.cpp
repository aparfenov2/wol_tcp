#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <memory>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#endif
#include <MacAddress.h>
#include <IpAddress.h>
#include <PlatformSpecificUtils.h>
#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <PayloadLayer.h>
#include <NetworkUtils.h>
#include <Logger.h>
#if !defined(WIN32) && !defined(WINx64) //for using ntohl, ntohs, etc.
#include <in.h>
#endif
#include <getopt.h>
#include <intrin.h>

using namespace std;
using namespace pcpp;

bool doWOL(PcapLiveDevice* pDevice, int sourcePort, const IPv4Address& victimAddr, MacAddress& victimMacAddress, MacAddress& wolMacAddress, int victimPort)
{
	MacAddress deviceMacAddress = pDevice->getMacAddress();
	IPv4Address srcIPAddr = pDevice->getIPv4Address();
	EthLayer ethLayer(deviceMacAddress, victimMacAddress, (uint16_t)PCPP_ETHERTYPE_IP);
	IPv4Layer ipLayer(srcIPAddr, victimAddr);
	ipLayer.getIPv4Header()->timeToLive = 128;
	TcpLayer tcpLayer(sourcePort, victimPort);
	tcpLayer.getTcpHeader()->synFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = _byteswap_ushort(8192);
	int mss = _byteswap_ushort(1350);
	tcpLayer.addTcpOption(TcpOption::TCPOPT_MSS, PCPP_TCPOLEN_MSS, (uint8_t *)&mss);
	tcpLayer.addTcpOption(TcpOption::PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, nullptr);
	uint8_t windowScale = 8;
	tcpLayer.addTcpOption(TcpOption::PCPP_TCPOPT_WINDOW, PCPP_TCPOLEN_WINDOW, &windowScale);
	tcpLayer.addTcpOption(TcpOption::PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, nullptr);
	tcpLayer.addTcpOption(TcpOption::PCPP_TCPOPT_NOP, PCPP_TCPOLEN_NOP, nullptr);
	tcpLayer.addTcpOption(TcpOption::TCPOPT_SACK_PERM, PCPP_TCPOLEN_SACK_PERM, nullptr);

	uint8_t data[17 * 6];
	for (int i = 0; i < 6; i++) {
		data[i] = 0xff;
	}
	for (int j = 1; j < 17; j++) {
		wolMacAddress.copyTo(&data[j * 6]);
	}
	uint8_t dataLen = 17 * 6;
	PayloadLayer payloadLayer(data, dataLen, true);

	Packet packet(500);
	packet.addLayer(&ethLayer);
	packet.addLayer(&ipLayer);
	packet.addLayer(&tcpLayer);
	packet.addLayer(&payloadLayer);
	packet.computeCalculateFields();

	return pDevice->sendPacket(&packet);
}

static struct option L3FwdOptions[] =
{
	{ "interface",  required_argument, 0, 'i' },
	{ "sourcePort", required_argument, 0, 's' },
	{ "victim", required_argument, 0,     'v' },
	{ "victimMac", required_argument, 0,  'm' },
	{ "wolMac", required_argument, 0,     'w' },
	{ "victimPort", required_argument, 0, 'p' },
	{ 0, 0, 0, 0 }
};

void print_usage() {
	printf("Usage: this.exe -i <INTERFACE_IP> -s <sourcePort> -v <VICTIM_IP> -m <VICTIM_MAC> -w <WOL_MAC> -p <VICTIM_PORT> \n\n");
}

int main(int argc, char* argv[])
{
	//Get arguments from user for incoming interface and outgoing interface

	string iface = "192.168.0.214", victim = "192.168.0.214", victimMac = "bc:ee:7b:9a:6e:b8", wolMac = "bc:ee:7b:9a:6e:b8";
	int optionIndex = 0;
	char opt = 0;
	int sourcePort = 5555;
	int victimPort = 9;

	while ((opt = getopt_long(argc, argv, "i:s:v:m:p:w:", L3FwdOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
		case 0:
			break;
		case 'i':
			iface = optarg;
			break;
		case 's':
			sourcePort = atoi(optarg);
			break;
		case 'v':
			victim = optarg;
			break;
		case 'm':
			victimMac = optarg;
			break;
		case 'w':
			wolMac = optarg;
			break;
		case 'p':
			victimPort = atoi(optarg);
			break;
		default:
			print_usage();
			exit(-1);
		}
	}

	//if (argc <= 1) {
	//	print_usage();
	//	exit(-1);
	//}

	//Both incoming and outgoing interfaces must be provided by user

	//Currently supports only IPv4 addresses
	IPv4Address ifaceAddr(iface);
	IPv4Address victimAddr(victim);
	MacAddress victimMacAddr(victimMac);
	MacAddress wolMacAddr(wolMac);

	PcapLiveDevice* pIfaceDevice = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ifaceAddr);

	//Verifying interface is valid
	if (pIfaceDevice == NULL)
	{
		printf("Cannot find interface. Exiting...\n");
		exit(-1);
	}

	if (!victimAddr.isValid())
	{
		printf("Victim address not valid. Exiting...\n");
		exit(-1);
	}

	//Opening interface device
	if (!pIfaceDevice->open())
	{
		printf("Cannot open interface. Exiting...\n");
		exit(-1);
	}

	return (!doWOL(pIfaceDevice, sourcePort, victimAddr, victimMacAddr, wolMacAddr, victimPort));
}
