package pcap

import org.apache.flink.api.java.ExecutionEnvironment
import org.apache.flink.api.scala.DataSet
import pcap.analysers.Analyser
import pcap.analysers.ints.ippacketbytes.IpPacketBytesPerDestIpAnalyser
import pcap.analysers.ints.ippacketbytes.IpPacketBytesPerPortsAnalyser
import pcap.analysers.ints.ippacketbytes.IpPacketBytesPerSrcIpAnalyser
import scala.Tuple2
import org.junit.Assert.assertEquals

class FlinkPcapShould {
  private val env: ExecutionEnvironment = ExecutionEnvironment.getExecutionEnvironment

  @org.junit.Test
  def analyzeBytesPerSrcIpFrom1000PackagesWith258ResultElements {
    val resultLength: Long = runAnalysis(new IpPacketBytesPerSrcIpAnalyser).count
    assertEquals(258, resultLength)
  }

  @org.junit.Test
  def analyzeBytesPerDestIpFrom1000PackagesWith250ResultElements {
    val resultLength: Long = runAnalysis(new IpPacketBytesPerDestIpAnalyser).count
    assertEquals(250, resultLength)
  }

  @org.junit.Test
  def analyzeBytesPerPortsFrom1000PackagesWith363ResultElements {
    val resultLength: Long = runAnalysis(new IpPacketBytesPerPortsAnalyser).count
    assertEquals(363, resultLength)
  }

  private def runAnalysis(analyser: Analyser[Int]): DataSet[(String, Int)] = {
    FlinkPcap.analyseFile("src/test/resources/200610041400_first1000.dump", 1000, analyser)
  }
}