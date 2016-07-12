package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{IllegalRawDataException, IpV4Packet, TcpPacket, UdpPacket}

class IpPacketBytesPerPortsAnalyser extends IpPacketBytesPerKeyAnalyser{

  override def ipBasedKey(rawIpPacket: Array[Byte]): String = ports(rawIpPacket)

  def ports(rawIpPacket: Array[Byte]): String = {
    try {
      val ipPacket = IpV4Packet.newPacket(rawIpPacket, 0, rawIpPacket.length)
      ipPacket.getPayload match {
        case tcp: TcpPacket => {
          val header = tcp.getHeader
          header.getSrcPort.valueAsInt() + " -> " + header.getDstPort.valueAsInt()
        }
        case udp: UdpPacket => {
          val header = udp.getHeader
          header.getSrcPort.valueAsInt() + " -> " + header.getDstPort.valueAsInt()
        }
        case _ => "no port information available"
      }
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }

  }
}