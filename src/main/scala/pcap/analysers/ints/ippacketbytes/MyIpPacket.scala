package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{IpV4Packet, TcpPacket, UdpPacket}

case class MyIpPacket(rawPacket: Array[Byte]) {
  def length: Int = rawPacket.length

  def getDstIp: String = ipPacket.getHeader.getDstAddr.getHostAddress

  def getSrcIp: String = ipPacket.getHeader.getSrcAddr.getHostAddress

  private def ipPacket: IpV4Packet = IpV4Packet.newPacket(rawPacket, 0, rawPacket.length)

  def getPorts: Option[String] = {
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
