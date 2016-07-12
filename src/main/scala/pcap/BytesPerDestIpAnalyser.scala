package pcap

import org.pcap4j.packet.{EthernetPacket, IllegalRawDataException, IpV4Packet}

class BytesPerDestIpAnalyser extends IntAnalyser{

  override def key(rawEthernetPacket: Array[Byte]): String = destIp(extractRawIpPacket(rawEthernetPacket))

  override def aggregate(left: Int, right: Int): Int = left + right

  override def value(rawEthernetPacket: Array[Byte]): Int = extractRawIpPacket(rawEthernetPacket).length

  def extractRawIpPacket(rawEthernetPacket: Array[Byte]): Array[Byte] = {
    val ethernetPacket = EthernetPacket.newPacket(rawEthernetPacket, 0, rawEthernetPacket.length)
    val rawIpPacket = ethernetPacket.getPayload.getRawData
    rawIpPacket
  }

  def destIp(rawIpPacket: Array[Byte]): String = {
    try {
      val ipPacket = IpV4Packet.newPacket(rawIpPacket, 0, rawIpPacket.length)
      ipPacket.getHeader.getDstAddr.getHostAddress
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }



}
