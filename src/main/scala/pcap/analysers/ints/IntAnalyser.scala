package pcap.analysers.ints

import pcap.analysers.Analyser

trait IntAnalyser extends Analyser[Int] with Serializable {
  def key(rawEthernetPacket: Array[Byte]): String
  def value(rawEthernetPacket: Array[Byte]): Int
  def aggregate(left: Int, right: Int): Int
}
