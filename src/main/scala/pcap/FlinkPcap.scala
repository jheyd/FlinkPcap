package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.scala.{DataSet, ExecutionEnvironment}
import org.pcap4j.core.{Pcaps, RawPacketListener}
import pcap.analysers.ints.ippacketbytes.MyEthernetPacket

import scala.collection.mutable

object FlinkPcap {

  implicit val typeInfo1 = TypeInformation.of(classOf[Array[Byte]])
  implicit val typeInfo2 = TypeInformation.of(classOf[String])
  implicit val typeInfo3 = TypeInformation.of(classOf[(String, Int)])
  implicit val typeInfo4 = TypeInformation.of(classOf[Int])
  implicit val typeInfo5 = TypeInformation.of(classOf[MyEthernetPacket])

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

    val totalSizesBySrcIp: DataSet[(String, Int)] = analyseFile(filename, packetCount, analysis)

    totalSizesBySrcIp.print()
  }

  def analyseFile(filename: String, packetCount: Int, analyser: SetAnalyser[Int]): DataSet[(String, Int)] = {
    val packetList = readPacketsFromFile(filename, packetCount)
    val ethernetPackets = env.fromCollection(packetList)

    val totalSizesBySrcIp = analyser.analysePackets(ethernetPackets)
    totalSizesBySrcIp
  }

  def readPacketsFromFile(filename: String, packetCount: Int): Seq[MyEthernetPacket] = {
    val handle = Pcaps.openOffline(filename)
    val packetBuffer = mutable.Buffer[MyEthernetPacket]()
    val listener = new RawPacketListener {
      override def gotPacket(packetBytes: Array[Byte]): Unit = {
        packetBuffer += new MyEthernetPacket(packetBytes)
      }
    }
    handle.dispatch(packetCount, listener)

    packetBuffer.toSeq
  }

}