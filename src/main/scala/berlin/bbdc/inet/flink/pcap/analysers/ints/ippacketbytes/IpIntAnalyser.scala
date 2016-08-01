package berlin.bbdc.inet.flink.pcap.analysers.ints.ippacketbytes

import berlin.bbdc.inet.flink.pcap.analysers.Analyser

trait IpIntAnalyser extends Analyser[Int] {

  def ipBasedKey(ipPacket: MyIpPacket): String

  def ipBasedValue(ipPacket: MyIpPacket): Int

  override def key(ethernetPacket: MyEthernetPacket): String = {
    ethernetPacket.getIpPacketFromPayload
      .map(ipBasedKey(_))
      .getOrElse("Ethernet packet payload does not contain an ip packet")
  }

  override def value(ethernetPacket: MyEthernetPacket): Int = {
    ethernetPacket.getIpPacketFromPayload
      // TODO jheyd 2016-07-24: better way to handle this?
      .map(ipBasedValue(_))
      .getOrElse(1)
  }

  def extractIpPacket(rawEthernetPacket: Array[Byte]): Option[MyIpPacket] = new MyEthernetPacket(rawEthernetPacket).getIpPacketFromPayload

}
