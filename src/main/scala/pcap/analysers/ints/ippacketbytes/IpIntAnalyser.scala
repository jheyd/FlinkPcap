package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.EthernetPacket
import pcap.analysers.Analyser

trait IpIntAnalyser extends Analyser[Int] {

  def ipBasedKey(rawIpPacket: Array[Byte]): String

  def ipBasedValue(rawIpPacket: Array[Byte]): Int

  override def key(rawEthernetPacket: Array[Byte]): String = ipBasedKey(extractRawIpPacket(rawEthernetPacket))

  override def value(rawEthernetPacket: Array[Byte]): Int = ipBasedValue(extractRawIpPacket(rawEthernetPacket))

  def extractRawIpPacket(rawEthernetPacket: Array[Byte]): Array[Byte] = {
    val ethernetPacket = EthernetPacket.newPacket(rawEthernetPacket, 0, rawEthernetPacket.length)
    val rawIpPacket = ethernetPacket.getPayload.getRawData
    rawIpPacket
  }


}
