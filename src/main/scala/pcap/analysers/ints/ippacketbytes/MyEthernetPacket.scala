package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{EthernetPacket, IpV4Packet}

case class MyEthernetPacket(rawPacket: Array[Byte]) {
  def getIpPacketFromPayload: MyIpPacket = {
    val ethernetPacket = EthernetPacket.newPacket(rawPacket, 0, rawPacket.length)
    val payload = ethernetPacket.getPayload
    payload match {
      case ipPacket: IpV4Packet => new MyIpPacket(payload.getRawData)
      case _ => throw new NotAnIpPacketException

    }
  }
}
