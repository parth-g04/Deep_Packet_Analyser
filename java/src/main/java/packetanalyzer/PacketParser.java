/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import packetanalyzer.ParsedPacket;
import packetanalyzer.RawPacket;

public class PacketParser {
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        if (raw == null || raw.data == null || parsed == null) {
            return false;
        }
        parsed.rawData = raw.data;
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;
        int len = raw.data.length;
        int offset = 0;
        if (len < 14) {
            return false;
        }
        parsed.destMac = PacketParser.macToString(raw.data, 0);
        parsed.srcMac = PacketParser.macToString(raw.data, 6);
        parsed.etherType = (raw.data[12] & 0xFF) << 8 | raw.data[13] & 0xFF;
        offset = 14;
        if (parsed.etherType == 2048) {
            if (len < offset + 20) {
                return false;
            }
            int versionIhl = raw.data[offset] & 0xFF;
            parsed.ipVersion = (byte)(versionIhl >> 4 & 0xF);
            int ihl = versionIhl & 0xF;
            if (parsed.ipVersion != 4) {
                return false;
            }
            int ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || len < offset + ipHeaderLen) {
                return false;
            }
            parsed.ttl = raw.data[offset + 8] & 0xFF;
            parsed.protocol = raw.data[offset + 9] & 0xFF;
            int srcIp = (raw.data[offset + 15] & 0xFF) << 24 | (raw.data[offset + 14] & 0xFF) << 16 | (raw.data[offset + 13] & 0xFF) << 8 | raw.data[offset + 12] & 0xFF;
            int destIp = (raw.data[offset + 19] & 0xFF) << 24 | (raw.data[offset + 18] & 0xFF) << 16 | (raw.data[offset + 17] & 0xFF) << 8 | raw.data[offset + 16] & 0xFF;
            parsed.srcIp = PacketParser.ipToString(srcIp);
            parsed.destIp = PacketParser.ipToString(destIp);
            parsed.hasIp = true;
            offset += ipHeaderLen;
            if (parsed.protocol == 6) {
                if (len < offset + 20) {
                    return false;
                }
                parsed.srcPort = (raw.data[offset] & 0xFF) << 8 | raw.data[offset + 1] & 0xFF;
                parsed.destPort = (raw.data[offset + 2] & 0xFF) << 8 | raw.data[offset + 3] & 0xFF;
                parsed.seqNumber = (long)(raw.data[offset + 4] & 0xFF) << 24 | (long)((raw.data[offset + 5] & 0xFF) << 16) | (long)((raw.data[offset + 6] & 0xFF) << 8) | (long)(raw.data[offset + 7] & 0xFF);
                parsed.seqNumber &= 0xFFFFFFFFL;
                parsed.ackNumber = (long)(raw.data[offset + 8] & 0xFF) << 24 | (long)((raw.data[offset + 9] & 0xFF) << 16) | (long)((raw.data[offset + 10] & 0xFF) << 8) | (long)(raw.data[offset + 11] & 0xFF);
                parsed.ackNumber &= 0xFFFFFFFFL;
                int dataOffset = raw.data[offset + 12] >> 4 & 0xF;
                int tcpHeaderLen = dataOffset * 4;
                parsed.tcpFlags = raw.data[offset + 13];
                if (tcpHeaderLen < 20 || len < offset + tcpHeaderLen) {
                    return false;
                }
                parsed.hasTcp = true;
                offset += tcpHeaderLen;
            } else if (parsed.protocol == 17) {
                if (len < offset + 8) {
                    return false;
                }
                parsed.srcPort = (raw.data[offset] & 0xFF) << 8 | raw.data[offset + 1] & 0xFF;
                parsed.destPort = (raw.data[offset + 2] & 0xFF) << 8 | raw.data[offset + 3] & 0xFF;
                parsed.hasUdp = true;
                offset += 8;
            }
        }
        if (offset < len) {
            parsed.payloadOffset = offset;
            parsed.payloadLength = len - offset;
        } else {
            parsed.payloadOffset = 0;
            parsed.payloadLength = 0;
        }
        return true;
    }

    public static String macToString(byte[] mac, int start) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < 6) {
            if (i > 0) {
                sb.append(":");
            }
            sb.append(String.format("%02x", mac[start + i] & 0xFF));
            ++i;
        }
        return sb.toString();
    }

    public static String ipToString(int ip) {
        return (ip >> 0 & 0xFF) + "." + (ip >> 8 & 0xFF) + "." + (ip >> 16 & 0xFF) + "." + (ip >> 24 & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case 1 -> "ICMP";
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(byte flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 2) != 0) {
            sb.append("SYN ");
        }
        if ((flags & 0x10) != 0) {
            sb.append("ACK ");
        }
        if ((flags & 1) != 0) {
            sb.append("FIN ");
        }
        if ((flags & 4) != 0) {
            sb.append("RST ");
        }
        if ((flags & 8) != 0) {
            sb.append("PSH ");
        }
        if ((flags & 0x20) != 0) {
            sb.append("URG ");
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }
        return sb.length() == 0 ? "none" : sb.toString();
    }

    public static class EtherType {
        public static final int IPv4 = 2048;
        public static final int IPv6 = 34525;
        public static final int ARP = 2054;
    }

    public static class Protocol {
        public static final int ICMP = 1;
        public static final int TCP = 6;
        public static final int UDP = 17;
    }

    public static class TCPFlags {
        public static final byte FIN = 1;
        public static final byte SYN = 2;
        public static final byte RST = 4;
        public static final byte PSH = 8;
        public static final byte ACK = 16;
        public static final byte URG = 32;
    }
}
