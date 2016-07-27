package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.scala.DataSet
import pcap.analysers.Analyser
import pcap.analysers.ints.ippacketbytes.MyEthernetPacket

class KeyValueSetAnalyser[T: TypeInformation](analyser: Analyser[T]) extends SetAnalyser[T] with Serializable {
  implicit val typeInfo1 = TypeInformation.of(classOf[String])

  def analysePackets(ethernetPackets: DataSet[MyEthernetPacket]): DataSet[(String, T)] = {
    val grouped = ethernetPackets.groupBy(analyser.key(_))
    implicit val typeInfo_ = TypeInformation.of(classOf[(String, T)])
    val totalSizesBySrcIp = grouped.reduceGroup(iterator => {
      iterator
        .map(packet => (analyser.key(packet), analyser.value(packet)))
        .reduce((left, right) => {
          val (leftKey, leftValue) = left
          val (_, rightValue) = right
          val aggregate = analyser.aggregate(leftValue, rightValue)
          (leftKey, aggregate)
        })
    })
    totalSizesBySrcIp
  }


}
