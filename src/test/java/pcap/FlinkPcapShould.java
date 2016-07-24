package pcap;

public class FlinkPcapShould {

    @org.junit.Test
    public void runBytesPerSrcIpWithoutExceptions() throws Exception {
        runAnalysis("bytesPerSrcIp");
    }

    @org.junit.Test
    public void runBytesPerDestIpWithoutExceptions() throws Exception {
        runAnalysis("bytesPerDestIp");
    }

    @org.junit.Test
    public void runBytesPerPortsWithoutExceptions() throws Exception {
        runAnalysis("bytesPerPorts");
    }

    private void runAnalysis(String analysisName) {
        FlinkPcap.main(new String[]{
                "--inputFile", "testdata/200610041400_first1000.dump",
                "--analysis", analysisName
        });
    }

}
