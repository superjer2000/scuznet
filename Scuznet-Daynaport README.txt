Daynaport Firmware for Scuznet ("Scuznet-Daynaport")

* Thanks to Saybur @ 68kMLA for designing Scuznet and writing the firmware - The hardware has been rock solid and the firmware programming was EXTREMELY easy to follow (very organized and well-commented).  I am sure that others would easily be able to extend the capabilities of this to support CD-ROM support given the awesome library of SCSI commands Saybur has included.  I would also think that it would be fairly straightforward to replace the current network hardware with a Wiznet WiFi alternative providing a wireless ethernet/SCSI2SD alternative for PowerBook users.

* Comments on the Scuznet-Daynaport firmware to superjer2000 on 68kMLA

BACKGROUND
~~~~~~~~~~
* Scuznet is an incredible device - solid state storage and SCSI-based Ethernet for about US$38.00
* The main project is designed to emulate the Nuvolink/Etherlan SC device.  Although this emulation mode offers strong performance, the Nuvolink and it's drivers are relatively complicated in their operation and at least two Scuznet users experienced various issues with the Nuvolink Ethernet emulation (initially freezes which were largely resolved but bus errors at shutdown/restart or when turning off Appletalk remained)
* This version of Scuznet firmware swaps out the Nuvolink device emulation for an emulation of a simpler Ethernet device called the Daynaport ("Scuznet-Daynaport")
* Initial tests of this firmware seem to indicate better stability versus Nuvolink firmware.  This updated firmware seems to run at speeds comparable to Nuvolink for AppleTalk, and better than Nuvolink for FTP.
DAYNAPORT EMULATION
~~~~~~~~~~~~~~~~~~~
* Protocol data sourced from http://anodynesoftware.com/ethernet/main.html [Anodyne]
* Inquiry Data from RaSCSI DaynaPort project

EMULATED COMMANDS
~~~~~~~~~~~~~~~~~

0x03: REQUEST SENSE
-------------------
Not yet observed but documented by Anodyne.  System responds with 0x70 and then eight bytes of 0x00 which seems to be appropriate based on what I read of the SCSI spec at https://www.staff.uni-mainz.de/tacke/scsi/SCSI2-06.html

0x0A: SEND PACKET
-----------------
Per Anodyne, two potential commands options with the format of:
0A 00 00 LL LL XX where XX = 00 or 80.  I have only observed XX=80.

Per Anodyne LL LL is big-endian packet length, although Anodyne indicates that if XX=80 LL LL is "the packet length + 8, and the data to be sent is PP PP 00 00 XX XX XX ... 00 00 00 00" where PP PP is the actual length of the packet and XX is the packet.  My reading of the Anodyne spec differs from what I experienced which is:

For XX=80 LL LL is big-endian length of the packet to be sent.  An extra 8 bytes needs to be read from the Macintosh for the PP PP 00 00 and the trailing 00 00 00 00.  All cases I noted during porting of Daynaport firmware where XX = 80 (again XX=00 hasn't been observed) has been that LL LL == PP PP.

The if XX = 80 the Scuznet Daynaport firmware reads the extra eight bytes and then sends the related packet to the network.

0x08: READ PACKET
-----------------
Per the Anodyne spec the command format is 08 00 00 LL LL XX where LL LL is the data length and XX is either C0 or 80 (only C0 has been observed).  LL LL seems to just reflect the max buffer size the driver can receive which I have always observed be 1,524 (05F4).  As most packets are smaller than this, I had tried sending multiple packets to the driver at once to improve performance without success.

Per Anodyne, the driver expects a response of LL LL NN NN NN NN followed by the packet with CRC.

LL LL is the length of the packet (including CRC).

NN NN NN NN is set to either 00 00 00 00 or 00 00 00 10:

Scuznet-Daynaport checks if there is another packet that has been read by the network controller and if so the last NN is set to 0x10 instead of 0x00.  I am assuming that this tells the driver to request another packet before it's regular polling interval.  Not following this (i.e. always returning all 0x00s) does negatively impact performance.

When the driver polls, if there isn't any packet to send, Scuznet-Daynaport returns 00 00 00 00 00 00.

I don't report skipped packets to the driver.  Anodyne seems to indicate there are specific flags sent in this case but I haven't had any issues not monitoring for this or emulating the related response.

Important:  The Macintosh driver seems to require a delay after the first six bytes are sent.  Scuznet-Daynaport has a delay of 100us after the first six pre-amble bytes (i.e. LL LL NN NN NN NN) are sent before the actual packet is sent.  Without this delay, the Mac doesn't recognize the read packet properly.  A delay of 30us worked on an SE/30 but an SE required a longer delay.  100us worked fine with the SE and SE/30 and didn't have any negative impact on the SE/30's network performance (it may have actually improved it slightly).

When the Mac driver first starts up it sends a READ with a length of 1.  Scuznet-Daynaport responds with just a STATUS GOOD and COMMAND COMPLETE.

UPDATE - After a bit of trial and error, I confirmed that the Mac driver sends the device the max buffer size (generally 0x05F4) as it accepts packets from the device until that buffer size is reached.  As AppleTalk packets are generally less than 1500 bytes, multiple AppleTalk packets ~6) can be incorporated into a single READ transaction.  I haven't seen this behaviour documented elsewhere, if you incorporate it, please credit superjer2000.

0x09 RETRIEVE STATS
-------------------
Per Anodyne spec, the driver expects the MAC address followed by three 4 byte counters.  Scuznet-Daynaport pulls the MAC address read from the config (or default) and simply returns 00 00 00 00 for each of those counters.

0x12 INQUIRY
------------
Gets called twice when the driver loads.  Expects Daynaport identification response.  Credit to the RaSCSI project for the appropriate response.

0x0D ACTIVATE APPLETALK
-----------------------
The device turns on and off acceptance of AppleTalk packets based on this command.

FILTERING
~~~~~~~~~			
Scuznet-Daynaport network filter works as follows:

ENC Level: Only allow packets that are for the Scuznet MAC address or are broadcast.  If command 0x0D indicates to activate AppleTalk then the pattern match filter is activated to also allow packets that are AppleTalk Multicast (09:00:07:xx:xx:xx).  This is intended to reduce the amount of traffic that reaches the main program.  The multicast pattern match filter will allow a limited amount of other multicast packets through as it's based on a checksum approach.  As such, the main program then performs a further filtering step to only allow valid packets (MAC, Broadcast or ATalk Multicast (if Atalk is turned on via 0xD)) to reach the Macintosh driver.