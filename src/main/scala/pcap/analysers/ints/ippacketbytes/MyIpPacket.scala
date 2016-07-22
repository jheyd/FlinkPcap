package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{IpV4Packet, TcpPacket, UdpPacket}

case class MyIpPacket(rawPacket: Array[Byte]) {
  def length: Int = rawPacket.length

  def getDstIp: String = IpV4Packet.newPacket(rawPacket, 0, rawPacket.length).getHeader.getDstAddr.getHostAddress

  def getSrcIp: String = IpV4Packet.newPacket(rawPacket, 0, rawPacket.length).getHeader.getSrcAddr.getHostAddress

  def getPorts: Option[String] = {
    val ipPacket = IpV4Packet.newPacket(rawPacket, 0, rawPacket.length)
    ipPacket.getPayload match {
      case tcp: TcpPacket => {
        val header = tcp.getHeader
        Option(header.getSrcPort.valueAsInt() + " -> " + header.getDstPort.valueAsInt())
      }
      case udp: UdpPacket => {
        val header = udp.getHeader
        Option(header.getSrcPort.valueAsInt() + " -> " + header.getDstPort.valueAsInt())
      }
      case _ => Option.empty

    }
  }
}
