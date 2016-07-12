package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.scala.ExecutionEnvironment
import org.pcap4j.core.{Pcaps, RawPacketListener}
import org.pcap4j.packet.{EthernetPacket, IllegalRawDataException, IpV4Packet}

import scala.collection.mutable

object FlinkPcap {

  implicit val typeInfo1 = TypeInformation.of(classOf[Array[Byte]])
  implicit val typeInfo2 = TypeInformation.of(classOf[String])
  implicit val typeInfo3 = TypeInformation.of(classOf[(String, Int)])

  val env: ExecutionEnvironment = ExecutionEnvironment.getExecutionEnvironment

  def main(args: Array[String]) {
    val filename = args(0)
    val packetCount = args(1).toInt

    analysePackets(filename, packetCount)
  }

  def analysePackets(filename: String, packetCount: Int): Unit = {
    val packetList = readPacketsFromFile(filename, packetCount)
    val ethernetPackets = env.fromCollection(packetList)
    val ipPackets = ethernetPackets.map(extractRawIpPacket(_))
    val grouped = ipPackets.groupBy(srcIp(_))
    val totalSizesBySrcIp = grouped.reduceGroup(iterator => {
      var addr = ""
      var length = 0
      iterator.foreach(packet => {
        addr = srcIp(packet)
        length += packet.length
      })
      (addr, length)
    })
    totalSizesBySrcIp.print()
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

  def extractRawIpPacket(rawEthernetPacket: Array[Byte]): Array[Byte] = {
    val ethernetPacket = EthernetPacket.newPacket(rawEthernetPacket, 0, rawEthernetPacket.length)
    val rawIpPacket = ethernetPacket.getPayload.getRawData
    rawIpPacket
  }

  def srcIp(rawPacket: Array[Byte]): String = {
    try {
      val ipPacket = IpV4Packet.newPacket(rawPacket, 0, rawPacket.length)
      ipPacket.getHeader.getSrcAddr.getHostAddress
    } catch {
      case e: IllegalRawDataException => e.getMessage
    }
  }

}