package pcap.analysers.ints.ippacketbytes

import pcap.analysers.Analyser

trait IpIntAnalyser extends Analyser[Int] {

  def ipBasedKey(ipPacket: MyIpPacket): String

  def ipBasedValue(ipPacket: MyIpPacket): Int

  override def key(ethernetPacket: MyEthernetPacket): String = {
    try {
      ipBasedKey(ethernetPacket.getIpPacketFromPayload)
    } catch {
      case e: NotAnIpPacketException => e.getMessage
    }
  }

  override def value(ethernetPacket: MyEthernetPacket): Int = {
    try {
      val ipPacket = ethernetPacket.getIpPacketFromPayload
      ipBasedValue(ipPacket)
    } catch {
      // TODO jheyd 2016-07-24: better way to handle this?
      case e: NotAnIpPacketException => 1
    }
  }

  def extractIpPacket(rawEthernetPacket: Array[Byte]): MyIpPacket = new MyEthernetPacket(rawEthernetPacket).getIpPacketFromPayload

}
