package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.IllegalRawDataException

class IpPacketBytesPerPortsAnalyser extends IpPacketBytesPerKeyAnalyser {

  override def ipBasedKey(ipPacket: MyIpPacket): String = {
    try {
      ipPacket.getPorts
        .getOrElse("no port information available")
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }
}