package berlin.bbdc.inet.flink.pcap

import org.apache.flink.api.scala._
import org.pcap4j.core.{Pcaps, RawPacketListener}
import berlin.bbdc.inet.flink.pcap.analysers.ints.ippacketbytes.MyEthernetPacket

import scala.collection.mutable

object FlinkPcap {

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

    totalSizesBySrcIp.writeAsText(params.outputFile)

    env.execute("Flink Pcap")
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