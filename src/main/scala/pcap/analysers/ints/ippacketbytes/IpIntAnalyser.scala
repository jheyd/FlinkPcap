package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.{EthernetPacket, IpV4Packet}
import pcap.analysers.Analyser

trait IpIntAnalyser extends Analyser[Int] {

  def ipBasedKey(ipPacket: MyIpPacket): String

  def ipBasedValue(ipPacket: MyIpPacket): Int

  override def key(rawEthernetPacket: Array[Byte]): String = {
    try {
      ipBasedKey(extractIpPacket(rawEthernetPacket))
    } catch {
      case e: NotAnIpPacketException => e.getMessage
    }
  }

  override def value(rawEthernetPacket: Array[Byte]): Int = {
    try {
      val ipPacket = extractIpPacket(rawEthernetPacket)
      ipBasedValue(ipPacket)
    } catch {
      // TODO jheyd 2016-07-24: better way to handle this?
      case e: NotAnIpPacketException => 1
    }
  }

  def extractIpPacket(rawEthernetPacket: Array[Byte]): MyIpPacket = {
    new MyIpPacket(extractRawIpPacket(rawEthernetPacket))
  }

  def extractRawIpPacket(rawEthernetPacket: Array[Byte]): Array[Byte] = {
    val ethernetPacket = EthernetPacket.newPacket(rawEthernetPacket, 0, rawEthernetPacket.length)
    val ethernetPayload = ethernetPacket.getPayload
    ethernetPayload match {
      case ipPacket: IpV4Packet => ipPacket.getRawData
      case _ => throw new NotAnIpPacketException
    }
  }

}
