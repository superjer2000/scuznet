/*
 * Copyright (C) 2019-2021 saybur
 * Copyright (C) 2021 superjer2000
 * 
 * This file is part of scuznet.
 * 
 * scuznet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * scuznet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with scuznet.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <util/delay.h>
#include "config.h"
#include "debug.h"
#include "enc.h"
#include "link.h"
#include "logic.h"
#include "net.h"


#define MAXIMUM_TRANSFER_LENGTH 1514 // This is the max length of ethernet data 1500 + MAC address data (12) plus 2 for length/type.  For the read routine it maxes out at 1518 as that includes the 4 CRC bytes which are appended by the ENC.



// Daynaport-compatible INQUIRY header response
static const __flash uint8_t inquiry_data_d[255] = {
	0x03, 0x00, 0x01, 0x00, // 4 bytes
	0x1E, 0x00, 0x00, 0x00, // 4 bytes
	// Vendor ID (8 Bytes)
	'D','a','y','n','a',' ',' ',' ',
	//'D','A','Y','N','A','T','R','N',
	// Product ID (16 Bytes)
	'S','C','S','I','/','L','i','n',
	'k',' ',' ',' ',' ',' ',' ',' ',
	// Revision Number (4 Bytes)
	'1','.','4','a',
	// Firmware Version (8 Bytes)
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	// Data
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x80,0x80,0xBA, //16 bytes
	0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x81,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, //16 bytes
	0x00,0x00,0x00 //3 bytes
};

// the selector for the TX buffer space
static uint8_t txbuf;

// the last-seen identify value
static uint8_t last_identify;

// buffers and headers used during the reading operation
static uint8_t read_buffer[6];
static NetHeader net_header;




// Destination MAC address array to hold address of packet for filtering purposes
static uint8_t dest_mac_addr[6];

// MAC address of the Scuznet.  Loaded in net.c
extern uint8_t mac_address[6];

// if true, allow in AppleTalk multicast traffic - including zoned AppleTalk traffic
static uint8_t allowAppleTalk = 0;

// Boolean indicating whether an unsent packet has already been queued up or not
uint8_t packetQueued=0;

// Length of the data to be transmitted

static uint16_t data_length;

// Pointer to the location in the ENC memory where the last packet read stopped so it can be picked up again to continue
uint16_t lastPacketReadPointer;

/*
 * ============================================================================
 * 
 *   OPERATION HANDLERS
 * 
 * ============================================================================
 * 
 * Each of these gets called from the _main() function to perform a particular
 * task on either the device or the PHY.
 */

static void daynaPort_setnetwork(uint8_t* cmd)
{
	/*
	The DaynaPort driver sends command 0D to tell the unit what types of packets to accept.  The length field of the 0D command indicates how many packet filters will be sent.  The accept our MAC and broadcast seems to be generally of the form 01 00 5E 00 00 01 whereas
	accept AppleTalk packets will be 09 00 07 FF FF FF.  The below loops through the packet filter information sent and if 09 (i.e. accept AppleTalk) is in any of the first byte positions of the packet filter information it allows Appletalk packets.
	Note that emulating this behaviour does not seem to be strictly necessary.  It IS necessary to read all of the bytes sent with the 0D command (otherwise Appletalk will fail to activate) but this behaviour is being emulated to match the actual system behaviour
	as closely as possible.
	
	*/
	uint16_t alloc = (cmd[3] << 8) + cmd[4];
	uint8_t paramSet=0;
	allowAppleTalk = 0;
	phy_phase(PHY_PHASE_DATA_OUT);
	for (uint16_t i = 0; i < alloc; i++)
	{
		paramSet = phy_data_ask();
		if ((i==0 && paramSet==0x09) || (i==6 && paramSet==0x09) || (i==12 && paramSet==0x09)) allowAppleTalk =1; // I've only ever seen two packet filters sent but this allows for 3 (i.e. activate appletalk in position 1, 2 or 3)

	}
	logic_status(LOGIC_STATUS_GOOD);
	logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);
	link_set_filter();
}

static void link_inquiry(uint8_t* cmd)
{
	
	// we ignore page code and rely on allocation length only for deciding
	// what to send, so find that first
	uint16_t alloc = ((cmd[3] & 1) << 8) + cmd[4];

	//if (cmd[1] & 1) jgk_debug('B'); // EVPD bit set  I havne't ever seen this set.
	if (alloc > 255) alloc = 255;
	
		phy_phase(PHY_PHASE_DATA_IN);
		for (uint8_t i = 0; i < alloc; i++)
		{
			phy_data_offer(inquiry_data_d[i]);
		}
		if (phy_is_atn_asserted())
		{
			logic_message_out();
		}
	

	logic_status(LOGIC_STATUS_GOOD);
	logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);
	debug(DEBUG_LINK_INQUIRY);
	
}

static void link_change_mac(void)
{
	// This doesn't really seem to be a thing with the Daynaport as the software doesn't seem to allow a permanent MAC change so not implemented.
}



void link_set_filter(void)
{
	
	enc_cmd_clear(ENC_ECON1, ENC_RXEN_bm);
	if (allowAppleTalk == 1)
	{ 
		//enc_cmd_write(ENC_ERXFCON, 163); //  163 = 10100011  Sets the ENC filter to only allow packets that 1) have correct CRC, are directed to our MAC address, OR are broadcast OR are multicast
		/*
		The below ENC filter setup is intended to reduce the number of packets that hit the MCU for further filtering.  Receiption of all multicast packets is not turned on with the filter set to 177 as per below.  Instead
		the Pattern Match filter is employed as follows:
		EPMM0 - EPMM7 - Only check the first 3 bytes of the 64 byte window
		EPMOH and EPMOL:  Offset of where the 64 byte window should start - in this case no offset so it can see the destination MAC address
		EPMCSH and EPMCSL - 0x0FFE - this is the pattern match filter calculated to allow packets that start with 09 00 07  (i.e. Appletalk multicast, either zoned or unzoned)  This was very hard to follow in the datasheet
		but it seems like it's working.
		*/
		
		
		enc_cmd_write(ENC_ERXFCON, 177); //  163 = 10110001  Sets the ENC filter to only allow packets that 1) have correct CRC, are directed to our MAC address, OR are broadcast OR meet the PATTERN MATCH filter
		enc_cmd_write(ENC_EPMM0, 7);
		enc_cmd_write(ENC_EPMM1, 0);
		enc_cmd_write(ENC_EPMM2, 0);
		enc_cmd_write(ENC_EPMM3, 0);
		enc_cmd_write(ENC_EPMM4, 0);
		enc_cmd_write(ENC_EPMM5, 0);
		enc_cmd_write(ENC_EPMM6, 0);
		enc_cmd_write(ENC_EPMM7, 0);
		enc_cmd_write(ENC_EPMOH, 0);
		enc_cmd_write(ENC_EPMOL, 0);
		enc_cmd_write(ENC_EPMCSH, 0x0F);
		enc_cmd_write(ENC_EPMCSL, 0xFE);
	}
	else
	{
		enc_cmd_write(ENC_ERXFCON, 161); //  160 = 10100001  Sets the ENC filter to only allow packets that 1) have correct CRC, are directed to our MAC address, OR are broadcast.  Multicast turned off if ATalk is turned off.
	}
	
	enc_cmd_set(ENC_ECON1, ENC_RXEN_bm);
	
}

static void link_send_packet(uint8_t* cmd)
{
	debug(DEBUG_LINK_TX_REQUESTED);


	
	uint16_t length = ((cmd[3]) << 8) + cmd[4]; // JGK 	uint16_t length = ((cmd[3] & 7) << 8) + cmd[4];
	if (length > MAXIMUM_TRANSFER_LENGTH) length = MAXIMUM_TRANSFER_LENGTH;

	// get devices in the right mode for a data transfer

	net_move_txpt(txbuf);
	enc_write_start();
	phy_phase(PHY_PHASE_DATA_OUT);

	// write the status byte
	while (! (ENC_USART.STATUS & USART_DREIF_bm));
	ENC_USART.DATA = 0x00;
	
	
	
	/*
	Per Anodyne spec:
	Command:  0a 00 00 LL LL XX (LLLL is data length, XX = 80 or 00)
	if XX = 00, LLLL is the packet length, and the data to be sent
	must be an image of the data packet
	. if XX = 80, LLLL is the packet length + 8, and the data to be
	sent is:
	PP PP 00 00 XX XX XX ... 00 00 00 00
	where:
	PPPP      is the actual (2-byte big-endian) packet length
	XX XX ... is the actual packet
	
	
	Note that for packet send type 0x00 the length is in position 3 and 4 for the Daynaport just as it is for the Nuvolink so the length calculation above is OK
	I have never seen an xx = 00 packet.  And for the XX=80, all I have ever seen is where LLLL = PPPP
	
	*/
	
	if (cmd[5]==0x00) // Simpler packet format I've never seen this.
	{
		phy_data_ask_stream(&ENC_USART, length);
		while (! (ENC_USART.STATUS & USART_TXCIF_bm));
		enc_data_end();
		net_transmit(txbuf, length +1); //length + 1
		txbuf = txbuf ? 0 : 1;
	}
	else if (cmd[5]==0x80)
	{
		
		phy_data_ask_stream_0x80(&ENC_USART, length+8); // Read the extra 8 bytes
		
		while (! (ENC_USART.STATUS & USART_TXCIF_bm));
		enc_data_end();
		net_transmit(txbuf, length +1); //length + 1
		txbuf = txbuf ? 0 : 1;	
	}
	logic_status(LOGIC_STATUS_GOOD);
	logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);
}

static void link_read_packet_header(void)
{
	enc_read_start();
	ENC_USART.DATA = 0xFF;
	while (! (ENC_USART.STATUS & USART_RXCIF_bm));
	ENC_USART.DATA; // junk RBM response
	for (uint8_t i = 0; i < 6; i++)
	{
		ENC_USART.DATA = 0xFF;
		while (! (ENC_USART.STATUS & USART_RXCIF_bm));
		read_buffer[i] = ENC_USART.DATA;
	}
	net_process_header(read_buffer, &net_header);
}


static void link_read_dest_addr(void)
{
	ENC_USART.DATA = 0xFF;

	for (uint8_t i = 0; i < 6; i++)
	{
		ENC_USART.DATA = 0xFF;
		while (! (ENC_USART.STATUS & USART_RXCIF_bm));
		dest_mac_addr[i] = ENC_USART.DATA;
	}
	
}

// The queue_packet function finds a valid packet (i.e. packet we want to send to the host).  If there are pending packets in the ENC, it will loop through them, check them against the MAC address filter we process here
// and then if it finds a packet, it will flip the packetQueued flag to true.

void queue_packet(void)
{
	
	uint8_t total_packets=0;
	uint8_t packet_counter=0;
	uint8_t found_packet=0;
	uint8_t packetPointer;
	enc_cmd_read(ENC_EPKTCNT, &total_packets); // Read number of read packets from packet counter  APPEARS THAT THIS NEEDS TO OCCUR BEFORE THE HEADER IS READ AND THE ENC SWITCHES TO READ_START MODE.
	
		
		for (packet_counter=total_packets;packet_counter>0;packet_counter--) 
		{
			
			link_read_packet_header(); // Starts the enc read process
			link_read_dest_addr(); // Destination address is read to allow firmware to filter out remaining extraneous multicast packets that EXCEPT for Appletalk multicast, that slipped past the ENC filter.
			if (dest_mac_addr[0] == mac_address[0] && dest_mac_addr[1] == mac_address[1] && dest_mac_addr[2] == mac_address[2] && dest_mac_addr[3] == mac_address[3] && dest_mac_addr[4] == mac_address[4] && dest_mac_addr[5] == mac_address[5]) found_packet = 1;
			if (dest_mac_addr[0] == 0xFF && dest_mac_addr[1] == 0xFF && dest_mac_addr[2] == 0xFF && dest_mac_addr[3] == 0xFF && dest_mac_addr[4] == 0xFF && dest_mac_addr[5] == 0xFF) found_packet = 1;
			if (allowAppleTalk==1) if (dest_mac_addr[0] == 0x09 && dest_mac_addr[1] == 0x00 && dest_mac_addr[2] == 0x07 && dest_mac_addr[3] == 0x00 && dest_mac_addr[4] == 0x00) found_packet = 1;
			if (allowAppleTalk==1) if (dest_mac_addr[0] == 0x09 && dest_mac_addr[1] == 0x00 && dest_mac_addr[2] == 0x07 && dest_mac_addr[3] == 0xFF && dest_mac_addr[4] == 0xFF && dest_mac_addr[5] == 0xFF) found_packet = 1;

			enc_data_end();
			
			if (found_packet == 1) 
			{			
				break;		// Found a valid packet so exit the loop			
			}
			else
			{
				// Did not find a valid packet so loop again if there are still packets in the ENC per the initial count.
				net_move_rxpt(net_header.next_packet, 1);
				enc_cmd_set(ENC_ECON2, ENC_PKTDEC_bm);
			}
				
			

		}
		
		if(found_packet==1)
		{
			// JGK:  Move the length bytes into the correct position for the Dayna Port.  The length bytes for both Daynaport and Nuvolink seem to be the same - length of the payload excluding length and flag bytes, except little endian vs big endian
			
			read_buffer[0] = read_buffer[3];
			read_buffer[1] = read_buffer[2];
			
			data_length = (uint16_t)((read_buffer[0]) << 8) + (uint16_t)read_buffer[1];

			// See anodyne spec
			read_buffer[2] = 0x00;
			read_buffer[3] = 0x00;
			read_buffer[4] = 0x00;
			read_buffer[5] = 0x00;
			
			packetQueued = 1;

			// We found a packet and queued it up.  We aren't sending it to the host yet, so save the ENC memory read location so we can start to read from that same place again afterwards.
			enc_cmd_read(ENC_ERDPTL, &packetPointer);
			lastPacketReadPointer = (uint16_t) packetPointer;
			enc_cmd_read(ENC_ERDPTH, &packetPointer);
			lastPacketReadPointer = lastPacketReadPointer + (uint16_t)(packetPointer<<8);			
		}
	
	
}


static void link_read_packet(uint8_t* cmd) 
{
	
	uint16_t transfer_length = ((cmd[3]) << 8) + cmd[4];
	uint16_t transmitted_length = 0; // Total length of packet data already transmitted to the host for the current READ command.
	uint8_t transmit_packet = 0;
	if (transfer_length == 1) // The driver will occasionally issue a read with a transfer length of 1.  No data is to be returned.
	{
		
		logic_status(LOGIC_STATUS_GOOD);
		logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);
		return;
	}
	
	


	if ((!(ENC_PORT.IN & ENC_PIN_INT)) && packetQueued == 0) // if there are no pending packets in the ENC and no packet has been previously queued up then send back the no packet message to the host.
	{
		
		read_buffer[0] = 0x00;
		read_buffer[1] = 0x00;
		read_buffer[2] = 0x00;
		read_buffer[3] = 0x00;
		read_buffer[4] = 0x00;
		read_buffer[5] = 0x00;
		
		phy_phase(PHY_PHASE_DATA_IN);
		for (uint16_t i = 0; i < 6; i++)
		{
			phy_data_offer(read_buffer[i]);
		}
		
	}
	else	// There is either a packet in the ENC or a packet has been previously queued.
	{	
		while (1) // This is the Daynaport "Packet Stuffing" approach.  If used elsewhere, please credit superjer2000 as I'm not aware of this having been documented elsewhere.
		{
			transmit_packet = 0; // Transmit Packet boolean.  This routine will keep transmitting packets to the host for a single read command as long as there is still space remaining based on the transfer length data the driver issued with the read command.
			// Note that the driver always (as far as I can tell) indicates an allowable transfer length of 05F4 which is 1,524, enough for a full data payload of 1500 bytes, 6 preamble bytes for the driver, 12 MAC Address bytes, 2 frame type bytes and 4 CRC bytes.
			// If the appropriate pauses are made, the driver will allow the device to keep sending packets until it reaches the total of 1,524 bytes (or whatever is specified by the driver in the read command).
			
			if (packetQueued == 1) // We already have a packet queued so see it it will fit within our data length limit.
				{
					if (data_length > 1518) data_length=1518;
					if ((transmitted_length + data_length + 6) <= (transfer_length)) transmit_packet = 1;
				}
			else // We don't have a packet queued, so get one and then see if it will fit within our data length limit.
				{
					queue_packet();
					if (packetQueued == 1)
					{
						if (data_length > 1518) data_length=1518;
						if ((transmitted_length + data_length + 6) <= (transfer_length)) transmit_packet = 1;
					}
				}

					
		
			if (transmit_packet== 0) // Didn't find a packet to transmit.
			{
				if (transmitted_length == 0) // No packets have been been transmitted yet and no packet to transmit so send standard no packet response and exit the loop.
				{
					read_buffer[0] = 0x00;
					read_buffer[1] = 0x00;
					read_buffer[2] = 0x00;
					read_buffer[3] = 0x00;
					read_buffer[4] = 0x00;
					read_buffer[5] = 0x00;
					if ((ENC_PORT.IN & ENC_PIN_INT)) read_buffer[5] = 0x10; // If there happens to be another packet now in the ENC memory, let the driver know.
					phy_phase(PHY_PHASE_DATA_IN);
					for (uint16_t i = 0; i < 6; i++)
					{
						phy_data_offer(read_buffer[i]);
					}
				}
				break;
			
			}
			else // There is a packet to transmit.
			{
				if ((ENC_PORT.IN & ENC_PIN_INT)) read_buffer[5] = 0x10; // If there happens to be another packet now in the ENC memory, let the driver know.
				phy_phase(PHY_PHASE_DATA_IN);
		
				// Send the header

				for (uint16_t i = 0; i < 6; i++) 
				{
					phy_data_offer(read_buffer[i]); // Send initial bytes required by the driver
				}
		

				_delay_us(100); // This pause necessary for the driver to properly read the packets. It might need to have time to parse the length out before reading the rest of it. 30us - 60us seemed to work reliably on my SE/30.  The SE did not work with 40 or 60 but did with 100.  There doesn't seem to be an significant performance penalty but there is a significant increase in compatibility.  
			
				for (uint16_t i = 0; i < 6; i++)
				{
					phy_data_offer(dest_mac_addr[i]); // Send Dest MAC address information already read for filter purposes
					
		
				}
		
				_delay_us(175); // This pause is new.  I am not sure if it's needed due to sending multiple packets in one READ command or due to some other change i haven't tracked down.  It became necessary when I was experimenting with trying to pre-buffer information to speed up Daynaport emulation.  I haven't check to see if it's sufficiently large for machines slower than an SE/30.  
				// NOTE, if this delay isn't here, my SE/30 won't work with AppleTalk.  If it's less than 150 microseconds, the SE/30 will work but it seems to have some troubles processing some READ commands.  100us seems like a sweet spot for my SE/30, delivering 75kB/s on AppleShare transfers but i want to experiment with my SE as well.
				
				net_move_rxpt(lastPacketReadPointer-2, 1); // we're going to finish reading the packet we queued up earlier, so move back to that same location in the ENC memory.
				enc_read_start();
				ENC_USART.DATA = 0xFF;
				while (! (ENC_USART.STATUS & USART_RXCIF_bm));
				ENC_USART.DATA; // junk RBM response
				phy_data_offer_stream(&ENC_USART,data_length-6);  // Call the version that doesn't check for _atn as it seems to run about 15% faster for some reason.  Send packet, substracting 6 from the length to account for MAC Address info already sent.
				
				enc_data_end();
				net_move_rxpt(net_header.next_packet, 1);
				enc_cmd_set(ENC_ECON2, ENC_PKTDEC_bm);
			
				transmitted_length = data_length + 6;
				packetQueued = 0; // Sent the queued packet, so flip the flag.
			}
		}
		
		
	}
	
	// Close out transaction

	if (phy_is_atn_asserted())
	{
		logic_message_out();
	}
	
	
	logic_status(LOGIC_STATUS_GOOD);
	logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);			
		
		
		
		
		
		
		
			
}




/*
 * ============================================================================
 * 
 *   EXTERNAL FUNCTIONS
 * 
 * ============================================================================
 */

void link_init(void)
{
	// Used for reselection - Reselection code doesn't seem to cause any issues so not removed.
	//target_mask = target;
	

}


void retrieve_statistics(void)
{
	
	// Per Anodyne spec, the 5th byte is always 0x12.  I have only ever seen CMD 0x09 called with byte 5 == 0x012 so this isn't checked and a 0x09 CMD always returns the below.

	
	phy_phase(PHY_PHASE_DATA_IN);
	
	// Send MAC address from config read at net_setup
	phy_data_offer(mac_address[0]);
	phy_data_offer(mac_address[1]);
	phy_data_offer(mac_address[2]);
	phy_data_offer(mac_address[3]);
	phy_data_offer(mac_address[4]);
	phy_data_offer(mac_address[5]);

	// Send back 3  2-byte statistics all set to 0

	for (uint8_t i = 0; i < 12; i++)
	{
		phy_data_offer(0x00);
	}
	if (phy_is_atn_asserted())
	{
		logic_message_out();
	}
	logic_status(LOGIC_STATUS_GOOD);
	logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);
}

void link_request_sense(void)
{
	
	// JGK This has not been observed by me yet.  This just returns a simple sense response based on what I read of the SCSI spec at https://www.staff.uni-mainz.de/tacke/scsi/SCSI2-06.html
	phy_phase(PHY_PHASE_DATA_IN);
	
	
	phy_data_offer(0x70);
	for (uint8_t i = 0; i < 8; i++)
	{
		phy_data_offer(0x00);
	}
	
	if (phy_is_atn_asserted())
	{
		logic_message_out();
	}
	logic_status(LOGIC_STATUS_GOOD);
	logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);
}





uint8_t link_main(void)
{
	
	if (! logic_ready()) return 0;
	if (config_enet.id == 255) return 0;
		// normal selection by initiator
		logic_start(1, 1);
		uint8_t cmd[10];
		if (! logic_command(cmd)) return 0;
	
		uint8_t identify = logic_identify();
		if (identify != 0) last_identify = identify;
		
		/* if (cmd[0]!=0x08)
		 {
			 
			 jgk_debug(cmd[0]);
			 jgk_debug(cmd[1]);
			 jgk_debug(cmd[2]);
			 jgk_debug(cmd[3]);
			 jgk_debug(cmd[4]);
			 jgk_debug(cmd[5]);
			 jgk_debug(0x2F);
		 }
		*/
		switch (cmd[0])
		
		{
			
			case 0x03: // REQUEST SENSE
				link_request_sense();
				break;
			case 0x0A: // "Send Packet"
				link_send_packet(cmd);
				break;
			case 0x0C: // Per Anodyne spec, this is set interface mode/change Mac.  Doesn't seem to be a permanent change so ignored.
				link_change_mac();
				break;
			case 0x09: 
				
				retrieve_statistics();
		
				break;
			case 0x08: // "Read Packet from device"
				
				link_read_packet(cmd);
				break;	
			case 0x12: // INQUIRY
				
				link_inquiry(cmd);
				break;
			case 0x0D: // Set packet filtering
				daynaPort_setnetwork(cmd);
				break;
			
			case 0x00: // TEST UNIT READY
			case 0x02: // From Nuvolink - not observed with Daynaport so essentially ignored but left in as doesn't seem to cause any issue.
			case 0x0E: // Observed with Daynaport, Seems to be enable/disable interface per Anodyne spec but I always have interface enabled.
			case 0x06: // From Nuvolink - not observed with Daynaport so essentially ignored but left in as doesn't seem to cause any issue.
			case 0x1C: // From Nuvolink - not observed with Daynaport so essentially ignored but left in as doesn't seem to cause any issue.
			case 0x1D: // From Nuvolink - not observed with Daynaport so essentially ignored but left in as doesn't seem to cause any issue.
			case 0x80: // From Nuvolink - not observed with Daynaport so essentially ignored but left in as doesn't seem to cause any issue.
				logic_status(LOGIC_STATUS_GOOD);
				logic_message_in(LOGIC_MSG_COMMAND_COMPLETE);
				break;

			default:
				logic_cmd_illegal_op(cmd[0]);
		}

		
	logic_done();
	return 1;
}
