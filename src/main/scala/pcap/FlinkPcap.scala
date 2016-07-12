package pcap

import java.net.Inet4Address

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.streaming.api.scala.StreamExecutionEnvironment
import org.pcap4j.core.{PacketListener, Pcaps, RawPacketListener}
import org.pcap4j.packet.factory.PacketFactory
import org.pcap4j.packet.{EthernetPacket, IllegalRawDataException, IpV4Packet, Packet}

import scala.collection.mutable

object FlinkPcap {

  implicit val typeInfo1 = TypeInformation.of(classOf[Array[Byte]])
  implicit val typeInfo2 = TypeInformation.of(classOf[String])
  implicit val typeInfo3 = TypeInformation.of(classOf[(String, Int)])

  def main(args: Array[String]) {
    val filename = args(0)
    val packetList = readPacketsFromFile(filename)
    val env: StreamExecutionEnvironment = StreamExecutionEnvironment.getExecutionEnvironment
    val packets = env.fromCollection(packetList)
    val keyedPackets = packets.keyBy(srcIp(_))
    val windowedPackets = keyedPackets.countWindow(100)
    val totalSizesByKey = windowedPackets.fold(("", 0))((accumulator: (String, Int), value: Array[Byte]) => {
      val addr = srcIp(value)
      val newLength = accumulator._2 + value.length
      (addr, newLength)
    })
    totalSizesByKey.print()

    env.execute()
  }

  def readPacketsFromFile(filename: String): Seq[Array[Byte]] = {
    val handle = Pcaps.openOffline(filename)
    val packetBuffer = mutable.Buffer[Array[Byte]]()
    val listener = new RawPacketListener {
      override def gotPacket(packetBytes: Array[Byte]): Unit = {
        packetBuffer += EthernetPacket.newPacket(packetBytes, 0, packetBytes.length).getPayload.getRawData
      }
    }
    handle.dispatch(10000, listener)

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