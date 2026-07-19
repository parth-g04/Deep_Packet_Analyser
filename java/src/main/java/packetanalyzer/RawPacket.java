package packetanalyzer;

import packetanalyzer.PcapHeaders;

public class RawPacket {
    public PcapHeaders.PcapPacketHeader header;
    public byte[] data;

    public RawPacket() {
    }

    public RawPacket(PcapHeaders.PcapPacketHeader header, byte[] data) {
        this.header = header;
        this.data = data;
    }
}
