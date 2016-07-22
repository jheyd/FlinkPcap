package pcap.analysers

// TODO Jan 2016-07-20: why does this not work as a trait?
abstract class Analyser[T] extends Serializable {

  def key(rawEthernetPacket: Array[Byte]): String

  def value(rawEthernetPacket: Array[Byte]): T

  def aggregate(left: T, right: T): T

}
