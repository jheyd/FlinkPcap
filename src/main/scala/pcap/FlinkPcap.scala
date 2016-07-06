package pcap

import org.apache.flink.streaming.api.scala.StreamExecutionEnvironment
import org.jnetpcap.Pcap
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.util.PcapPacketArrayList

import scala.collection.JavaConverters._

object FlinkPcap {

  def main(args: Array[String]) {
    val filename = "src/test/resources/200610041400.dump"
    val packetList = readPacketsFromFile(filename)
    val packets = StreamExecutionEnvironment.getExecutionEnvironment.fromCollection(packetList)
  }

  def readPacketsFromFile(filename: String): Seq[PcapPacket] = {
    val errorBuffer = new java.lang.StringBuilder()
    val pcap = Pcap.openOffline(filename, errorBuffer)

    if (pcap == null) {
      print(errorBuffer)
      System.exit(-1)
    }

    try {
      val packets = new PcapPacketArrayList
      pcap.loop(-1, packets, null)
      return packets.asScala
    } finally {
      pcap.close
    }
  }
}
