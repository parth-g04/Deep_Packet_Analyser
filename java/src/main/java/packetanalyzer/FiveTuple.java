/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

public class FiveTuple {
    public int srcIp;
    public int dstIp;
    public int srcPort;
    public int dstPort;
    public int protocol;

    public FiveTuple() {
    }

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FiveTuple)) {
            return false;
        }
        FiveTuple other = (FiveTuple)o;
        return this.srcIp == other.srcIp && this.dstIp == other.dstIp && this.srcPort == other.srcPort && this.dstPort == other.dstPort && this.protocol == other.protocol;
    }

    public int hashCode() {
        int h = 0;
        h ^= this.srcIp + -1640531527 + (h << 6) + (h >> 2);
        h ^= this.dstIp + -1640531527 + (h << 6) + (h >> 2);
        h ^= (this.srcPort & 0xFFFF) + -1640531527 + (h << 6) + (h >> 2);
        h ^= (this.dstPort & 0xFFFF) + -1640531527 + (h << 6) + (h >> 2);
        h ^= (this.protocol & 0xFF) + -1640531527 + (h << 6) + (h >> 2);
        return h;
    }

    public FiveTuple reverse() {
        return new FiveTuple(this.dstIp, this.srcIp, this.dstPort, this.srcPort, this.protocol);
    }

    public String toString() {
        return FiveTuple.formatIP(this.srcIp) + ":" + (this.srcPort & 0xFFFF) + " -> " + FiveTuple.formatIP(this.dstIp) + ":" + (this.dstPort & 0xFFFF) + " (" + (this.protocol == 6 ? "TCP" : (this.protocol == 17 ? "UDP" : "?")) + ")";
    }

    public static String formatIP(int ip) {
        return (ip >> 0 & 0xFF) + "." + (ip >> 8 & 0xFF) + "." + (ip >> 16 & 0xFF) + "." + (ip >> 24 & 0xFF);
    }
}
