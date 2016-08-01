package berlin.bbdc.inet.flink.pcap.analysers.ints.ippacketbytes

class IpPacketBytesPerPortsAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(ipPacket: MyIpPacket): String = ipPacket.getPorts.getOrElse("no port information available")
}