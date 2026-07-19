/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import packetanalyzer.FiveTuple;

public class PacketJob {
    public int packetId;
    public FiveTuple tuple;
    public byte[] data;
    public int ethOffset = 0;
    public int ipOffset = 0;
    public int transportOffset = 0;
    public int payloadOffset = 0;
    public int payloadLength = 0;
    public byte tcpFlags = 0;
    public int tsSec;
    public int tsUsec;

    public PacketJob() {
    }

    public PacketJob(int packetId, FiveTuple tuple, byte[] data, int tsSec, int tsUsec) {
        this.packetId = packetId;
        this.tuple = tuple;
        this.data = data;
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
    }
}
