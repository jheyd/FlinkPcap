package pcap.analysers.ints.ippacketbytes

class IpPacketBytesPerDestIpAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(ipPacket: MyIpPacket): String = ipPacket.getDstIp
}
