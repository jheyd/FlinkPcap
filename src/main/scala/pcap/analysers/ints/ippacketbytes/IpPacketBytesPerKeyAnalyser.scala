package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.EthernetPacket
import pcap.analysers.ints.IntAnalyser

trait IpPacketBytesPerKeyAnalyser extends IntAnalyser{

  def ipBasedKey(rawIpPacket: Array[Byte]): String

  override def key(rawEthernetPacket: Array[Byte]): String = ipBasedKey(extractRawIpPacket(rawEthernetPacket))

  override def aggregate(left: Int, right: Int): Int = left + right

  override def value(rawEthernetPacket: Array[Byte]): Int = extractRawIpPacket(rawEthernetPacket).length

  def extractRawIpPacket(rawEthernetPacket: Array[Byte]): Array[Byte] = {
    val ethernetPacket = EthernetPacket.newPacket(rawEthernetPacket, 0, rawEthernetPacket.length)
    val rawIpPacket = ethernetPacket.getPayload.getRawData
    rawIpPacket
  }


}
