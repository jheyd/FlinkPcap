package pcap.analysers.ints.ippacketbytes

import org.pcap4j.packet.EthernetPacket
import pcap.analysers.ints.IntAnalyser

trait IpPacketBytesPerKeyAnalyser extends IpIntAnalyser {

  override def ipBasedValue(rawIpPacket: Array[Byte]): Int = rawIpPacket.length

  override def aggregate(left: Int, right: Int): Int = left + right

}
