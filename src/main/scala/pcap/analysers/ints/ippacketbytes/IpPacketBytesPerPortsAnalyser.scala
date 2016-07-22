package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{IllegalRawDataException, IpV4Packet, TcpPacket, UdpPacket}

class IpPacketBytesPerPortsAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(rawIpPacket: Array[Byte]): String = ports(rawIpPacket)

  def ports(rawIpPacket: Array[Byte]): String = {
    try {
      new MyIpPacket(rawIpPacket).getPorts
        .getOrElse("no port information available")
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }

  }
}