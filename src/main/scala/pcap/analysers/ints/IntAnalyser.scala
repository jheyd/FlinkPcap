package pcap.analysers.ints

trait IntAnalyser extends Serializable {
  def key(rawEthernetPacket: Array[Byte]): String
  def value(rawEthernetPacket: Array[Byte]): Int
  def aggregate(left: Int, right: Int): Int
}
