package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.java.utils.ParameterTool
import pcap.analysers.Analyser
import pcap.analysers.ints.ippacketbytes.{IpPacketBytesPerDestIpAnalyser, IpPacketBytesPerPortsAnalyser, IpPacketBytesPerSrcIpAnalyser}

object Params {
  def fromArgs(args: Array[String]): Params = new Params(ParameterTool.fromArgs(args))
}

class Params(parameterTool: ParameterTool) {
  implicit val typeInfo = TypeInformation.of(classOf[Int])

  def inputFile: String = parameterTool.getRequired("inputFile")

  def analysis: SetAnalyser[Int] = parameterTool.getRequired("analysis") match {
    case "bytesPerDestIp" => new KeyValueSetAnalyser(new IpPacketBytesPerDestIpAnalyser)
    case "bytesPerSrcIp" => new KeyValueSetAnalyser(new IpPacketBytesPerSrcIpAnalyser)
    case "bytesPerPorts" => new KeyValueSetAnalyser(new IpPacketBytesPerPortsAnalyser)
    case other => throw new UnknownAnalysisException(other)
  }

  def packetCount: Int = parameterTool.getInt("packetCount", -1)
}
