package packetanalyzer;

public class PcapHeaders {

    public static class PcapGlobalHeader {
        public int magicNumber;
        public short versionMajor;
        public short versionMinor;
        public int thiszone;
        public int sigfigs;
        public int snaplen;
        public int network;

        public PcapGlobalHeader() {
        }

        public PcapGlobalHeader(int magicNumber, short versionMajor, short versionMinor, int thiszone, int sigfigs, int snaplen, int network) {
            this.magicNumber = magicNumber;
            this.versionMajor = versionMajor;
            this.versionMinor = versionMinor;
            this.thiszone = thiszone;
            this.sigfigs = sigfigs;
            this.snaplen = snaplen;
            this.network = network;
        }
    }

    public static class PcapPacketHeader {
        public int tsSec;
        public int tsUsec;
        public int inclLen;
        public int origLen;

        public PcapPacketHeader() {
        }

        public PcapPacketHeader(int tsSec, int tsUsec, int inclLen, int origLen) {
            this.tsSec = tsSec;
            this.tsUsec = tsUsec;
            this.inclLen = inclLen;
            this.origLen = origLen;
        }
    }
}
