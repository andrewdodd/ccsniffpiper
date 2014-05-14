ccsniffpiper
============

*Live Packet Sniffer to Wireshark bridge for IEEE 802.15.4 networks.*

NOTE WELL: I have implemented a new python script that does the same job as the TI Sniffer, but on the console. See **[pyCCSniffer](https://github.com/andrewdodd/pyCCSniffer)** for more details!

A Python module that uses a Texas Instruments CC2531emk USB dongle to sniff packets and pipe them to (primarily) wireshark.

This tool is a mashup of two existing GitHub projects:
 * **[sensniff](https://github.com/g-oikonomou/sensniff)**: A python tool by George Oikonomou to capture packets with the "sensniff" firmware for the TI CC2531 sniffer.
 * **[ccsniffer](https://github.com/christianpanton/ccsniffer)**: A python module by Christian Panton to capture packets with the original TI firmware and print them to stdout.

This tool attempts to take the usefulness of the **ccsniffer** not needing different firmware to the default TI firmware (so you can still use TI's Windows-based program) and combine it with the usefulness of live Wireshark capture. It is mostly based on the **sensniff** project, as that project already had more functionality.


Requires: pyusb >= 1.0



**ccsniffpiper** can run in interactive or headless mode. In interactive mode, the user can change the radio channel while running.

**ccsniffpiper** has been developed on Mac OS X. Like **sensniff**, it will probably not work on Windows (I haven't looked into whether Wireshark for Windows supports named pipes).

How to Use
==========
Run ccsniffpiper
----------------
**ccsniffpiper**'s main role it to read from the CC2531 USB packet sniffer and pipe the packets in PCAP format to a named pipe (by default "/tmp/ccsniffpiper").

To get this default behaviour, just run the command:
`python ccsniffpiper.py`

To see further information, run the help command:
`python ccsniffpiper.py -h`


Run Wireshark
-------------
To receive the packets from **ccsniffpiper** you need to use Wireshark to start a capture using a FIFO file as the 'interface'. By default, **ccsniffpiper** will use `/tmp/ccsniffpiper`. 

To setup Wireshark correctly, perform the following steps:
 * Go to Capture -> options -> Manage Interfaces -> New (under Pipes) -> type `/tmp/ccsniffpiper` and save.
 * The pipe will then appear as an interface. Start a capture on it.

Additional settings that might be important include:
 * Open Wireshark's preferences and select 'TI CC24xx FCS format' under Protocols -> IEEE 802.15.4.
 * Enable/disable the protocols you need (e.g. when I made this tool I was not using Zigbee)


TI's Packet Sniffer Payload Definition
======================================
This is just documentation of the packet format from the TI USB dongle. It is not complete and is based on mostly guesswork from the user manual for the TI dongle (which is now out of date) and the existing code in **ccsniffer**. 


    0       1       2       3       4       5       6       7       8       9       10      11 >>
    |_______|_______|_______|_______|_______|_______|_______|_______|_______|_______|_______|_ >>
    |COMMAND|   Length      |           Timestamp           |Packet |  MAC Layer PDU >>>
    |       |               |                               |Length | i.e. the packet
    
    
    
 * **COMMAND**: (1 byte) - Not entirely sure of all of these values. Currently there are only 2:
  * 0x00 - Message is a captured frame
  * 0x01 - Message appears to be a heartbeat of some sort (seems to include the "captured count")
 * **Length**: (2 bytes) - The length of the rest of the message
 * **Timestamp**: (4 bytes) - The sniffer's timestamp of the captured packet since the "start" of the capture.
   * **Note Well**: This timestamp is in usecs and is multiplied by 32 (see CC2531 user guide for info)
 * **Packet Length**: (1 byte) - Length of the MAC Layer PDU (i.e. the "frame length" / PHY Header byte)
 * **MAC Layer PDU**: Variable length specified in Packet Length.

