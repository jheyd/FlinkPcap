package pcap

import org.apache.flink.api.scala.DataSet
import pcap.analysers.ints.ippacketbytes.MyEthernetPacket

trait SetAnalyser[T] {
  def analysePackets(ethernetPackets: DataSet[MyEthernetPacket]): DataSet[(String, T)]

}
