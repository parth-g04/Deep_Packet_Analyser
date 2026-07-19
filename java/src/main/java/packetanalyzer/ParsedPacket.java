/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

public class ParsedPacket {
    public int timestampSec;
    public int timestampUsec;
    public String srcMac = "";
    public String destMac = "";
    public int etherType;
    public boolean hasIp = false;
    public byte ipVersion;
    public String srcIp = "";
    public String destIp = "";
    public int protocol;
    public int ttl;
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort;
    public int destPort;
    public byte tcpFlags;
    public long seqNumber;
    public long ackNumber;
    public byte[] rawData;
    public int payloadOffset;
    public int payloadLength;

    public byte[] getPayloadBytes() {
        if (this.payloadLength <= 0 || this.rawData == null) {
            return new byte[0];
        }
        byte[] payload = new byte[this.payloadLength];
        System.arraycopy(this.rawData, this.payloadOffset, payload, 0, this.payloadLength);
        return payload;
    }
}
