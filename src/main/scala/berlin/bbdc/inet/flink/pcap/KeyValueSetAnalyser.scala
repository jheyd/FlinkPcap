package berlin.bbdc.inet.flink.pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.scala.DataSet
import berlin.bbdc.inet.flink.pcap.analysers.Analyser
import berlin.bbdc.inet.flink.pcap.analysers.ints.ippacketbytes.MyEthernetPacket

object KeyValueSetAnalyser {
  def apply[T: TypeInformation](keyFunction: MyEthernetPacket => String, valueFunction: MyEthernetPacket => T,
               aggregationFunction: (T, T) => T): KeyValueSetAnalyser[T] = {
    new KeyValueSetAnalyser(keyFunction, valueFunction, aggregationFunction)
  }

  def apply[T: TypeInformation](analyser: Analyser[T]): KeyValueSetAnalyser[T] = apply(analyser.key, analyser.value, analyser.aggregate)
}

class KeyValueSetAnalyser[T: TypeInformation](keyFunction: MyEthernetPacket => String, valueFunction: MyEthernetPacket => T,
                                              aggregationFunction: (T, T) => T) extends SetAnalyser[T] with Serializable {
  implicit val typeInfo1 = TypeInformation.of(classOf[String])

  def analysePackets(ethernetPackets: DataSet[MyEthernetPacket]): DataSet[(String, T)] = {
    val grouped = ethernetPackets.groupBy(keyFunction)
    implicit val typeInfo_ = TypeInformation.of(classOf[(String, T)])
    val totalSizesBySrcIp = grouped.reduceGroup(iterator => {
      iterator
        .map(packet => (keyFunction.apply(packet), valueFunction.apply(packet)))
        .reduce((left, right) => {
          val (leftKey, leftValue) = left
          val (_, rightValue) = right
          val aggregate = aggregationFunction.apply(leftValue, rightValue)
          (leftKey, aggregate)
        })
    })
    totalSizesBySrcIp
  }


}
