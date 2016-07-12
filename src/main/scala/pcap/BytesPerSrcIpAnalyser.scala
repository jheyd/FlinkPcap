package pcap

import org.pcap4j.packet.{EthernetPacket, IllegalRawDataException, IpV4Packet}

class BytesPerSrcIpAnalyser extends IpPacketBytesPerKeyAnalyser {
  override def ipBasedKey(rawIpPacket: Array[Byte]): String = srcIp(rawIpPacket)

  def srcIp(rawIpPacket: Array[Byte]): String = {
    try {
      val ipPacket = IpV4Packet.newPacket(rawIpPacket, 0, rawIpPacket.length)
      ipPacket.getHeader.getSrcAddr.getHostAddress
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }

}
