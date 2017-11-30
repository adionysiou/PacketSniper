# PacketSniper
This software is an analyzer that produces valuable information, given a captured trace file using libpcap.

Getting Started:
----------------
This software is an analizer that takes a captured trace file as an input and detects valuable information regarding the packets of the trace and according to the arguments given. PacketSniper stores results found in .txt files. USE IT ONLY FOR SECURITY PUROPOSES. 

Installation Instructions:
--------------------------
1. Clone or download this repository.
2. Download and install libpcap (http://www.tcpdump.org/).
3. Compile and enjoy! :)

Compile using:
--------------
gcc -Wall -lpcap packetSniper.c -o packetSniper

Execute using:
--------------
./packetSniper (show help)
or
./packetSniper trace_filename (show total packets of ‘trace_filename’)
or
./packetSniper trace_filename arg1 arg2 -… (extract other information)

Available arguments to give:
----------------------------
-p or -protocol: to create the file 'protocols_used.txt' that shows all protocols used for each packet.

-ip_add or -ip_src_dest_address: to create the file 'ipaddresess_used.txt' that shows src,dest ip addresses used for each packet.

-f or -tcp_flags: to create the file 'tcpflags_used.txt' that shows all raised tcp flags for each packet.

-dport or -destination_port: to create the file 'destports_used.txt' that shows destination port used, for each packet.

-sport or -source_port: to create the file 'srcports_used.txt' that shows source port used, for each packet.

-pl or -payload: to create the file 'payload_of_packets.txt' that shows the payload of all packets.

NOTE THAT THE TRACE_FILENAME SHOULD BE THE FIRST ARGUMENT GIVEN!!!

Authors:
--------
Antreas Dionysiou(@dionisole)

Licence:
--------
Please see LICENSE.md file for details

General Notes:
--------------
Please feel free to use PacketSniper. Enjoy :)
