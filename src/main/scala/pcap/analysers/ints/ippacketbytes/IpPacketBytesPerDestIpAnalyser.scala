package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.IllegalRawDataException

class IpPacketBytesPerDestIpAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(ipPacket: MyIpPacket): String = {
    try {
      ipPacket.getDstIp
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }
}
