package pcap.analysers

import pcap.analysers.ints.ippacketbytes.MyEthernetPacket

// TODO Jan 2016-07-20: why does this not work as a trait?
abstract class Analyser[T] extends Serializable {

  def key(rawEthernetPacket: Array[Byte]): String

  def key(ethernetPacket: MyEthernetPacket): String = key(ethernetPacket.rawPacket)

  def value(ethernetPacket: MyEthernetPacket): T

  def aggregate(left: T, right: T): T

}
