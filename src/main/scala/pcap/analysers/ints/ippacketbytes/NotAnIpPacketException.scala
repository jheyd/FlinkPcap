package pcap.analysers.ints.ippacketbytes

class NotAnIpPacketException extends Exception("Ethernet packet payload does not contain an ip packet")