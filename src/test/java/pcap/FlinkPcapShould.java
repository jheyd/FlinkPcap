package pcap;

import org.apache.flink.api.java.ExecutionEnvironment;
import org.apache.flink.api.scala.DataSet;
import pcap.analysers.Analyser;
import pcap.analysers.ints.ippacketbytes.IpPacketBytesPerDestIpAnalyser;
import pcap.analysers.ints.ippacketbytes.IpPacketBytesPerPortsAnalyser;
import pcap.analysers.ints.ippacketbytes.IpPacketBytesPerSrcIpAnalyser;
import scala.Tuple2;

import static org.junit.Assert.assertEquals;

public class FlinkPcapShould {

    ExecutionEnvironment env = ExecutionEnvironment.getExecutionEnvironment();

    @org.junit.Test
    public void analyzeBytesPerSrcIpFrom1000PackagesWith258ResultElements() throws Exception {
        long resultLength = runAnalysis(new IpPacketBytesPerSrcIpAnalyser()).count();
        assertEquals(258, resultLength);
    }

    @org.junit.Test
    public void analyzeBytesPerDestIpFrom1000PackagesWith250ResultElements() throws Exception {
        long resultLength = runAnalysis(new IpPacketBytesPerDestIpAnalyser()).count();
        assertEquals(250, resultLength);
    }

    @org.junit.Test
    public void analyzeBytesPerPortsFrom1000PackagesWith363ResultElements() throws Exception {
        long resultLength = runAnalysis(new IpPacketBytesPerPortsAnalyser()).count();
        assertEquals(363, resultLength);
    }

    private DataSet<Tuple2<String, Object>> runAnalysis(Analyser analyser) throws Exception {
        return FlinkPcap.analyseFile("testdata/200610041400_first1000.dump", 1000, analyser);
    }

}
