package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{IllegalRawDataException, IpV4Packet}

class IpPacketBytesPerSrcIpAnalyser extends IpPacketBytesPerKeyAnalyser {
  override def ipBasedKey(rawIpPacket: Array[Byte]): String = srcIp(rawIpPacket)

  def srcIp(rawIpPacket: Array[Byte]): String = {
    try {
      new MyIpPacket(rawIpPacket).getSrcIp
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }

}
