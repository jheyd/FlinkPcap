package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{IllegalRawDataException, IpV4Packet}

class IpPacketBytesPerDestIpAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(rawIpPacket: Array[Byte]): String = destIp(rawIpPacket)

  def destIp(rawIpPacket: Array[Byte]): String = {
    try {
      new MyIpPacket(rawIpPacket).getDstIp
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }

}
