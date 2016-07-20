package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.java.utils.ParameterTool
import org.apache.flink.api.scala.{DataSet, ExecutionEnvironment}
import org.pcap4j.core.{Pcaps, RawPacketListener}
import pcap.analysers.Analyser
import pcap.analysers.ints.ippacketbytes.{IpPacketBytesPerDestIpAnalyser, IpPacketBytesPerPortsAnalyser, IpPacketBytesPerSrcIpAnalyser}
import pcap.analysers.ints.IntAnalyser

import scala.collection.mutable

object FlinkPcap {

  implicit val typeInfo1 = TypeInformation.of(classOf[Array[Byte]])
  implicit val typeInfo2 = TypeInformation.of(classOf[String])
  implicit val typeInfo3 = TypeInformation.of(classOf[(String, Int)])
  implicit val typeInfo4 = TypeInformation.of(classOf[Int])

  val env: ExecutionEnvironment = ExecutionEnvironment.getExecutionEnvironment

  def main(args: Array[String]) {
    def params = Params.fromArgs(args)
    val filename = params.inputFile
    val packetCount = params.packetCount
    val analysis = try {
      params.analysis
    } catch {
      case e: UnknownAnalysisException => {
        println("unknown analysis")
        return
      }
    }

    val packetList = readPacketsFromFile(filename, packetCount)
    val ethernetPackets = env.fromCollection(packetList)

    val totalSizesBySrcIp = analysePackets(ethernetPackets, analysis)

    totalSizesBySrcIp.print()
  }

  def analysePackets[T:TypeInformation](ethernetPackets: DataSet[Array[Byte]], analyser: Analyser[T]): DataSet[(String, T)] = {
    val grouped = ethernetPackets.groupBy(analyser.key(_))
    implicit val typeInfo5 = TypeInformation.of(classOf[(String, T)])
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