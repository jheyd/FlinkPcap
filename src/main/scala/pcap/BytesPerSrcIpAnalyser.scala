package pcap

import org.pcap4j.packet.{EthernetPacket, IllegalRawDataException, IpV4Packet}

class BytesPerSrcIpAnalyser extends IntAnalyser {
  override def key(rawEthernetPacket: Array[Byte]): String = srcIp(extractRawIpPacket(rawEthernetPacket))

  override def aggregate(left: Int, right: Int): Int = left + right

  override def value(rawEthernetPacket: Array[Byte]): Int = extractRawIpPacket(rawEthernetPacket).length

  def extractRawIpPacket(rawEthernetPacket: Array[Byte]): Array[Byte] = {
    val ethernetPacket = EthernetPacket.newPacket(rawEthernetPacket, 0, rawEthernetPacket.length)
    val rawIpPacket = ethernetPacket.getPayload.getRawData
    rawIpPacket
  }

  def srcIp(rawIpPacket: Array[Byte]): String = {
    try {
      val ipPacket = IpV4Packet.newPacket(rawIpPacket, 0, rawIpPacket.length)
      ipPacket.getHeader.getSrcAddr.getHostAddress
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }

}
