package pcap.analysers.ints.ippacketbytes

trait IpPacketBytesPerKeyAnalyser extends IpIntAnalyser {

  override def ipBasedValue(ipPacket: MyIpPacket): Int = ipPacket.length

  override def aggregate(left: Int, right: Int): Int = left + right

}
