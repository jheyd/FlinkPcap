package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.java.utils.ParameterTool

object Params {
  def fromArgs(args: Array[String]): Params = new Params(ParameterTool.fromArgs(args))
}

class Params(parameterTool: ParameterTool) {
  implicit val typeInfo = TypeInformation.of(classOf[Int])

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
}
