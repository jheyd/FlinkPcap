package pcap

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.api.scala.ExecutionEnvironment
import org.pcap4j.core.{PacketListener, Pcaps}
import org.pcap4j.packet.{EthernetPacket, IllegalRawDataException, IpV4Packet, Packet}

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
    val packets = env.fromCollection(packetList)
    val grouped = packets.groupBy(srcIp(_))
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
    val listener = new PacketListener {
      override def gotPacket(packet: Packet): Unit = {
        val ethernetPacket = packet match {
          case eth: EthernetPacket => eth
          case other: Any => throw new ClassCastException("Top level packet is not an EthernetPacket. Actual: " + other.getClass)
        }
        packetBuffer += ethernetPacket.getPayload.getRawData
      }
    }
    handle.dispatch(packetCount, listener)

    packetBuffer.toSeq
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