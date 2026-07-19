package packetanalyzer;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import packetanalyzer.PacketParser;
import packetanalyzer.ParsedPacket;
import packetanalyzer.PcapReader;
import packetanalyzer.RawPacket;

public class Main {
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0 (Java)");
        System.out.println("====================================\n");
        if (args.length < 1) {
            Main.printUsage();
            System.exit(1);
        }
        String filename = args[0];
        int maxPackets = -1;
        if (args.length >= 2) {
            try {
                maxPackets = Integer.parseInt(args[1]);
            }
            catch (NumberFormatException e) {
                System.err.println("Warning: Invalid max_packets argument, displaying all packets.");
            }
        }
        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(filename)) {
                System.exit(1);
            }
            System.out.println("\n--- Reading packets ---");
            RawPacket rawPacket = new RawPacket();
            ParsedPacket parsedPacket = new ParsedPacket();
            int packetCount = 0;
            int parseErrors = 0;
            while (reader.readNextPacket(rawPacket)) {
                ++packetCount;
                if (PacketParser.parse(rawPacket, parsedPacket)) {
                    Main.printPacketSummary(parsedPacket, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    ++parseErrors;
                }
                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }
            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");
        }
        catch (Exception e) {
            System.err.println("Exception: " + e.getMessage());
        }
    }

    private static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        Instant tsInstant = Instant.ofEpochSecond(pkt.timestampSec, (long)pkt.timestampUsec * 1000L);
        String timeStr = formatter.format(tsInstant) + "." + String.format("%06d", pkt.timestampUsec);
        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.println("Time: " + timeStr);
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        System.out.printf("  EtherType:       0x%04X", pkt.etherType);
        if (pkt.etherType == 2048) {
            System.out.print(" (IPv4)");
        } else if (pkt.etherType == 34525) {
            System.out.print(" (IPv6)");
        } else if (pkt.etherType == 2054) {
            System.out.print(" (ARP)");
        }
        System.out.println();
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }
        if (pkt.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");
            System.out.print("  Preview: ");
            int previewLen = Math.min(pkt.payloadLength, 32);
            int i = 0;
            while (i < previewLen) {
                System.out.printf("%02x ", pkt.rawData[pkt.payloadOffset + i] & 0xFF);
                ++i;
            }
            if (pkt.payloadLength > 32) {
                System.out.print("...");
            }
            System.out.println();
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java -cp target/classes packetanalyzer.Main <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  java -cp target/classes packetanalyzer.Main capture.pcap 10");
    }
}
