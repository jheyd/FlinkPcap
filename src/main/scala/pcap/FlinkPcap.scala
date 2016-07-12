package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.java.utils.ParameterTool
import org.apache.flink.api.scala.{DataSet, ExecutionEnvironment}
import org.pcap4j.core.{Pcaps, RawPacketListener}

import scala.collection.mutable

object FlinkPcap {

  implicit val typeInfo1 = TypeInformation.of(classOf[Array[Byte]])
  implicit val typeInfo2 = TypeInformation.of(classOf[String])
  implicit val typeInfo3 = TypeInformation.of(classOf[(String, Int)])
  implicit val typeInfo4 = TypeInformation.of(classOf[Int])

  val env: ExecutionEnvironment = ExecutionEnvironment.getExecutionEnvironment

  def main(args: Array[String]) {
    def params = ParameterTool.fromArgs(args)
    val filename = params.getRequired("inputFile")
    val analysis = params.getRequired("analysis") match {
      case "bytesPerDestIp" => new IpPacketBytesPerDestIpAnalyser
      case "bytesPerSrcIp" => new IpPacketBytesPerSrcIpAnalyser
      case "bytesPerPorts" => new IpPacketBytesPerPortsAnalyser
      case _ => {
        println("unknown analysis")
        return
      }
    }

    // read whole file by default
    val packetCount = params.getInt("packetCount", -1)

    val packetList = readPacketsFromFile(filename, packetCount)
    val ethernetPackets = env.fromCollection(packetList)

    val totalSizesBySrcIp = analysePackets(ethernetPackets, analysis)

    totalSizesBySrcIp.print()
  }

  def analysePackets(ethernetPackets: DataSet[Array[Byte]], analyser: IntAnalyser): DataSet[(String, Int)] = {
    val grouped = ethernetPackets.groupBy(analyser.key(_))
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

  def readPacketsFromFile(filename: String, packetCount: Int): Seq[Array[Byte]] = {
    val handle = Pcaps.openOffline(filename)
    val packetBuffer = mutable.Buffer[Array[Byte]]()
    val listener = new RawPacketListener {
      override def gotPacket(packetBytes: Array[Byte]): Unit = {
        packetBuffer += packetBytes
      }
    }
    handle.dispatch(packetCount, listener)

    packetBuffer.toSeq
  }

}