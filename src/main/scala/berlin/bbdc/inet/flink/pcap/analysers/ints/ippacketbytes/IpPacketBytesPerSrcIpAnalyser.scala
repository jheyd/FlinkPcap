package berlin.bbdc.inet.flink.pcap.analysers.ints.ippacketbytes

class IpPacketBytesPerSrcIpAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(ipPacket: MyIpPacket): String = ipPacket.getSrcIp
}
