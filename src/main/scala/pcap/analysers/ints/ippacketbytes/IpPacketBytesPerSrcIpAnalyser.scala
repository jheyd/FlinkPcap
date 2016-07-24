package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.IllegalRawDataException

class IpPacketBytesPerSrcIpAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(ipPacket: MyIpPacket): String = {
    try {
      ipPacket.getSrcIp
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }
}
