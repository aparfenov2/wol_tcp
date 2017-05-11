#define HAVE_REMOTE
#include "pcap.h"
int main()
{
	pcap_if_t      * allAdapters;
	pcap_if_t       * adapter;
	pcap_t       * adapterHandle;
	u_char         packet[58];
	char             errorBuffer[PCAP_ERRBUF_SIZE];

	// retrieve the adapters from the computer
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,
		&allAdapters, errorBuffer) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n",
			errorBuffer);
		return -1;
	}

	// if there are no adapters, print an error
	if (allAdapters == NULL)
	{
		printf("\nNo adapters found! Make sure WinPcap is installed.\n");
		return 0;
	}

	// print the list of adapters along with basic information about an adapter
	int crtAdapter = 0;
	for (adapter = allAdapters; adapter != NULL; adapter = adapter->next)
	{
		printf("\n%d.%s ", ++crtAdapter, adapter->name);
		printf("-- %s\n", adapter->description);
	}

	printf("\n");

	int adapterNumber;

	printf("Enter the adapter number between 1 and %d:", crtAdapter);
	scanf("%d", &adapterNumber);

	if (adapterNumber < 1 || adapterNumber > crtAdapter)
	{
		printf("\nAdapter number out of range.\n");

		// Free the adapter list
		pcap_freealldevs(allAdapters);

		return -1;
	}

	// parse the list until we reach the desired adapter
	adapter = allAdapters;
	for (crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++)
		adapter = adapter->next;

	// open the adapter
	adapterHandle = pcap_open(adapter->name, // name of the adapter
		65536,         // portion of the packet to capture
					   // 65536 guarantees that the whole 
					   // packet will be captured
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
		1000,             // read timeout - 1 millisecond
		NULL,          // authentication on the remote machine
		errorBuffer    // error buffer
	);

	if (adapterHandle == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter\n", adapter->name);

		// Free the adapter list
		pcap_freealldevs(allAdapters);

		return -1;
	}

	// free the adapter list
	pcap_freealldevs(allAdapters);


	// this is the most important part of the application
	// here we send the packet

	// first we create the packet

	// set mac destination address to 01 : 01 : 01 : 01 : 01 : 01
	packet[0] = 0xbc;
	packet[1] = 0xee;
	packet[2] = 0x7b;
	packet[3] = 0x9a;
	packet[4] = 0x6e;
	packet[5] = 0xb8;

	// set mac source address to 02 : 02 : 02 : 02 : 02 : 02
	packet[6] = 0x00;
	packet[7] = 0x13;
	packet[8] = 0x8f;
	packet[9] = 0x83;
	packet[10] = 0xa9;
	packet[11] = 0xb3;

	// set the rest of the packet

	packet[12] = 0x08;
	packet[13] = 0x00;

	packet[14] = 0x45;
	packet[15] = 0x00;
	packet[16] = 0x00;
	packet[17] = 0x2c;

	packet[18] = 0x00;
	packet[19] = 0xfb;

	packet[20] = 0x40;
	packet[21] = 0x00;
	packet[22] = 0x40;
	packet[23] = 0x06;

	packet[24] = 0xb6;
	packet[25] = 0x7d;

	packet[26] = 0xc0;
	packet[27] = 0xa8;
	packet[28] = 0x01;
	packet[29] = 0x01;
	packet[30] = 0xc0;
	packet[31] = 0xa8;
	packet[32] = 0x01;
	packet[33] = 0x02;

	packet[34] = 0x04;
	packet[35] = 0x15;
	packet[36] = 0x00;
	packet[37] = 0xa6;

	packet[38] = 0x4d;
	packet[39] = 0x62;
	packet[40] = 0xfe;
	packet[41] = 0x09;

	packet[42] = 0x17;
	packet[43] = 0x46;
	packet[44] = 0x60;
	packet[45] = 0x5c;

	packet[46] = 0x50;
	packet[47] = 0x18;
	packet[48] = 0xff;
	packet[49] = 0xff;
	packet[50] = 0x7d;
	packet[51] = 0x15;
	packet[52] = 0x00;
	packet[53] = 0x00;

	packet[54] = 0x74;
	packet[55] = 0x65;
	packet[56] = 0x73;
	packet[57] = 0x74;

	// send the packet
	if (pcap_sendpacket(adapterHandle, // the adapter handle
		packet, // the packet
		58 // the length of the packet
	) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adapterHandle));
		return -1;
	}


	system("PAUSE");
	return 0;

}