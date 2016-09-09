package berlin.bbdc.inet.flink.pcap

import org.apache.flink.api.java.utils.ParameterTool
import org.apache.flink.api.scala._
import org.apache.flink.streaming.api.scala.DataStream

object Params {
  def fromArgs(args: Array[String]): Params = new Params(ParameterTool.fromArgs(args))
  def usage: String = "FlinkPcap --inputFile <filename> --outputFile <filename> --analysis <(bytesPerDestIp|bytesPerSrcIp|bytesPerPorts)> [--packetCount <Int>]"
}

class Params(parameterTool: ParameterTool) {

  def inputFile: String = parameterTool.getRequired("inputFile")

  def analysis: SetAnalyser[Int] = parameterTool.getRequired("analysis") match {
    case "bytesPerDestIp" => KeyValueSetAnalyser(
      _.getIpPacketFromPayload.map(_.getDstIp).getOrElse("Ethernet packet payload does not contain an ip packet"),
      _.getIpPacketFromPayload.map(_.length).getOrElse(1),
      _ + _)
    case "bytesPerSrcIp" => KeyValueSetAnalyser(
      _.getIpPacketFromPayload.map(_.getSrcIp).getOrElse("Ethernet packet payload does not contain an ip packet"),
      _.getIpPacketFromPayload.map(_.length).getOrElse(1),
      _ + _)
    case "bytesPerPorts" => KeyValueSetAnalyser(
      _.getIpPacketFromPayload.map(
        _.getPorts.getOrElse("no port information available")
      ).getOrElse("Ethernet packet payload does not contain an ip packet"),
      _.getIpPacketFromPayload.map(_.length).getOrElse(1),
      _ + _)
    case other => throw new UnknownAnalysisException(other)
  }

  def packetCount: Int = parameterTool.getInt("packetCount", -1)

  def outputFile: String = parameterTool.getRequired("outputFile");

}
