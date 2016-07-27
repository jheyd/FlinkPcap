package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{EthernetPacket, IpV4Packet}

case class MyEthernetPacket(rawPacket: Array[Byte]) {
  def getIpPacketFromPayload: Option[MyIpPacket] = {
    val ethernetPacket = EthernetPacket.newPacket(rawPacket, 0, rawPacket.length)
    val payload = ethernetPacket.getPayload
    payload match {
      case ipPacket: IpV4Packet => Option(new MyIpPacket(payload.getRawData))
      case _ => Option.empty
    }
  }
}
