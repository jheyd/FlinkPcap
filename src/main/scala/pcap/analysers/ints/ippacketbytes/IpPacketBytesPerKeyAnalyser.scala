package pcap.analysers.ints.ippacketbytes

trait IpPacketBytesPerKeyAnalyser extends IpIntAnalyser {

  override def ipBasedValue(rawIpPacket: Array[Byte]): Int = new MyIpPacket(rawIpPacket).length

  override def aggregate(left: Int, right: Int): Int = left + right

}
