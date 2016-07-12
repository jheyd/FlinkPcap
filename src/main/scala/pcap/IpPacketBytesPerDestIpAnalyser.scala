package pcap

import org.pcap4j.packet.{EthernetPacket, IllegalRawDataException, IpV4Packet}

class IpPacketBytesPerDestIpAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(rawIpPacket: Array[Byte]): String = destIp(rawIpPacket)

  def destIp(rawIpPacket: Array[Byte]): String = {
    try {
      val ipPacket = IpV4Packet.newPacket(rawIpPacket, 0, rawIpPacket.length)
      ipPacket.getHeader.getDstAddr.getHostAddress
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }

}
