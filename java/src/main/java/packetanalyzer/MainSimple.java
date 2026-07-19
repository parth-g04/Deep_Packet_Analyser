/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import packetanalyzer.AppType;
import packetanalyzer.FiveTuple;
import packetanalyzer.PacketParser;
import packetanalyzer.ParsedPacket;
import packetanalyzer.PcapReader;
import packetanalyzer.PcapWriter;
import packetanalyzer.RawPacket;
import packetanalyzer.SNIExtractor;

public class MainSimple {
    public static void main(String[] args) {
        if (args.length < 2) {
            MainSimple.printUsage();
            System.exit(1);
        }
        String inputFile = args[0];
        String outputFile = args[1];
        SimpleBlockingRules rules = new SimpleBlockingRules();
        int i = 2;
        while (i < args.length) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                rules.blockIP(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                rules.blockApp(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                rules.blockDomain(args[++i]);
            }
            ++i;
        }
        System.out.println("\n");
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                    DPI ENGINE v1.0 (Simple Java)              \u2551");
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");
        HashMap<FiveTuple, Flow> flows = new HashMap<FiveTuple, Flow>();
        long totalPackets = 0L;
        long forwarded = 0L;
        long dropped = 0L;
        HashMap<AppType, Long> appStats = new HashMap<AppType, Long>();
        try (PcapReader reader = new PcapReader(); PcapWriter writer = new PcapWriter()) {
            if (!reader.open(inputFile)) {
                System.exit(1);
            }
            if (!writer.open(outputFile, reader.getByteOrder())) {
                System.exit(1);
            }
            writer.writeGlobalHeader(reader.getGlobalHeader());
            RawPacket raw = new RawPacket();
            ParsedPacket parsed = new ParsedPacket();
            System.out.println("[DPI] Processing packets...");
            while (reader.readNextPacket(raw)) {
                String host;
                String sni;
                ++totalPackets;
                if (!PacketParser.parse(raw, parsed) || !parsed.hasIp || !parsed.hasTcp && !parsed.hasUdp) continue;
                int srcIp = SimpleBlockingRules.parseIP(parsed.srcIp);
                int n = SimpleBlockingRules.parseIP(parsed.destIp);
                FiveTuple fiveTuple = new FiveTuple(srcIp, n, parsed.srcPort, parsed.destPort, parsed.protocol);
                Flow flow = flows.computeIfAbsent(fiveTuple, k -> {
                    Flow f = new Flow();
                    f.tuple = k;
                    return f;
                });
                ++flow.packets;
                flow.bytes += (long)raw.data.length;
                if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS) && flow.sni.isEmpty() && parsed.hasTcp && parsed.destPort == 443 && parsed.payloadLength > 5 && (sni = SNIExtractor.extractSNI(raw.data, parsed.payloadOffset, parsed.payloadLength)) != null) {
                    flow.sni = sni;
                    flow.appType = AppType.sniToAppType(sni);
                }
                if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP) && flow.sni.isEmpty() && parsed.hasTcp && parsed.destPort == 80 && parsed.payloadLength > 0 && (host = SNIExtractor.extractHTTPHost(raw.data, parsed.payloadOffset, parsed.payloadLength)) != null) {
                    flow.sni = host;
                    flow.appType = AppType.sniToAppType(host);
                }
                if (flow.appType == AppType.UNKNOWN && (parsed.destPort == 53 || parsed.srcPort == 53)) {
                    flow.appType = AppType.DNS;
                }
                if (flow.appType == AppType.UNKNOWN) {
                    if (parsed.destPort == 443) {
                        flow.appType = AppType.HTTPS;
                    } else if (parsed.destPort == 80) {
                        flow.appType = AppType.HTTP;
                    }
                }
                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(fiveTuple.srcIp, flow.appType, flow.sni);
                    if (flow.blocked) {
                        System.out.print("[BLOCKED] " + parsed.srcIp + " -> " + parsed.destIp + " (" + flow.appType.toStringName());
                        if (!flow.sni.isEmpty()) {
                            System.out.print(": " + flow.sni);
                        }
                        System.out.println(")");
                    }
                }
                appStats.put(flow.appType, appStats.getOrDefault((Object)flow.appType, 0L) + 1L);
                if (flow.blocked) {
                    ++dropped;
                    continue;
                }
                ++forwarded;
                writer.writePacket(raw.header, raw.data);
            }
            System.out.println("\n");
            System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
            System.out.println("\u2551                      PROCESSING REPORT                       \u2551");
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            System.out.printf("\u2551 Total Packets:      %-10d                               \u2551\n", totalPackets);
            System.out.printf("\u2551 Forwarded:          %-10d                               \u2551\n", forwarded);
            System.out.printf("\u2551 Dropped:            %-10d                               \u2551\n", dropped);
            System.out.printf("\u2551 Active Flows:       %-10d                               \u2551\n", flows.size());
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            System.out.println("\u2551                    APPLICATION BREAKDOWN                     \u2551");
            System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
            ArrayList<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
            sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));
            for (Map.Entry<AppType, Long> entry : sortedApps) {
                double pct = totalPackets > 0L ? 100.0 * (double)entry.getValue().longValue() / (double)totalPackets : 0.0;
                int barLen = (int)(pct / 5.0);
                String bar = "#".repeat(barLen);
                System.out.printf("\u2551 %-15s %-8d %5.1f%% %-20s  \u2551\n", entry.getKey().toStringName(), entry.getValue(), pct, bar);
            }
            System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
            System.out.println("\n[Detected Applications/Domains]");
            HashMap<String, AppType> hashMap = new HashMap<String, AppType>();
            for (Flow flow : flows.values()) {
                if (flow.sni.isEmpty()) continue;
                hashMap.put(flow.sni, flow.appType);
            }
            for (Map.Entry<String, AppType> entry : hashMap.entrySet()) {
                System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().toStringName());
            }
            System.out.println("\nOutput written to: " + outputFile);
        } catch (Exception e) {
            System.err.println("Exception: " + e.getMessage());
        }
    }

    private static void printUsage() {
        System.out.println("DPI Engine - Deep Packet Inspection System (Simple Java)");
        System.out.println("==========================================");
        System.out.println("Usage: java -cp target/classes packetanalyzer.MainSimple <input.pcap> <output.pcap> [options]");
        System.out.println("\nOptions:");
        System.out.println("  --block-ip <ip>        Block traffic from source IP");
        System.out.println("  --block-app <app>      Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <dom>   Block domain (substring match)");
        System.out.println("\nExample:");
        System.out.println("  java -cp target/classes packetanalyzer.MainSimple capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50");
    }

    static class Flow {
        FiveTuple tuple;
        AppType appType = AppType.UNKNOWN;
        String sni = "";
        long packets = 0L;
        long bytes = 0L;
        boolean blocked = false;

        Flow() {
        }
    }

    static class SimpleBlockingRules {
        final Set<Integer> blockedIps = new HashSet<Integer>();
        final Set<AppType> blockedApps = new HashSet<AppType>();
        final List<String> blockedDomains = new ArrayList<String>();

        SimpleBlockingRules() {
        }

        void blockIP(String ip) {
            int addr = SimpleBlockingRules.parseIP(ip);
            this.blockedIps.add(addr);
            System.out.println("[Rules] Blocked IP: " + ip);
        }

        void blockApp(String app) {
            AppType[] appTypeArray = AppType.values();
            int n = appTypeArray.length;
            int n2 = 0;
            while (n2 < n) {
                AppType appType = appTypeArray[n2];
                if (appType.toStringName().equalsIgnoreCase(app)) {
                    this.blockedApps.add(appType);
                    System.out.println("[Rules] Blocked app: " + app);
                    return;
                }
                ++n2;
            }
            System.err.println("[Rules] Unknown app: " + app);
        }

        void blockDomain(String domain) {
            this.blockedDomains.add(domain);
            System.out.println("[Rules] Blocked domain: " + domain);
        }

        boolean isBlocked(int srcIp, AppType app, String sni) {
            if (this.blockedIps.contains(srcIp)) {
                return true;
            }
            if (this.blockedApps.contains((Object)app)) {
                return true;
            }
            if (sni != null && !sni.isEmpty()) {
                for (String dom : this.blockedDomains) {
                    if (!sni.contains(dom)) continue;
                    return true;
                }
            }
            return false;
        }

        private static int parseIP(String ip) {
            String[] parts = ip.split("\\.");
            int result = 0;
            result |= Integer.parseInt(parts[0]) & 0xFF;
            result |= (Integer.parseInt(parts[1]) & 0xFF) << 8;
            result |= (Integer.parseInt(parts[2]) & 0xFF) << 16;
            return result |= (Integer.parseInt(parts[3]) & 0xFF) << 24;
        }
    }
}
