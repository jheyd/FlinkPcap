package berlin.bbdc.inet.flink.pcap

import org.apache.flink.api.scala.DataSet
import berlin.bbdc.inet.flink.pcap.analysers.ints.ippacketbytes.MyEthernetPacket

trait SetAnalyser[T] {
  def analysePackets(ethernetPackets: DataSet[MyEthernetPacket]): DataSet[(String, T)]

}
