/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import java.util.ArrayList;
import packetanalyzer.DpiEngine;

public class MainDpi {
    public static void main(String[] args) {
        DpiEngine engine;
        if (args.length < 2) {
            MainDpi.printUsage();
            System.exit(1);
        }
        String inputFile = args[0];
        String outputFile = args[1];
        DpiEngine.Config config = new DpiEngine.Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;
        ArrayList<String> blockIps = new ArrayList<String>();
        ArrayList<String> blockApps = new ArrayList<String>();
        ArrayList<String> blockDomains = new ArrayList<String>();
        String rulesFile = "";
        int i = 2;
        while (i < args.length) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--rules") && i + 1 < args.length) {
                rulesFile = args[++i];
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                config.numLoadBalancers = Integer.parseInt(args[++i]);
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                config.fpsPerLb = Integer.parseInt(args[++i]);
            } else if (arg.equals("--verbose")) {
                config.verbose = true;
            } else if (arg.equals("--help") || arg.equals("-h")) {
                MainDpi.printUsage();
                System.exit(0);
            }
            ++i;
        }
        if (!rulesFile.isEmpty()) {
            config.rulesFile = rulesFile;
        }
        if (!(engine = new DpiEngine(config)).initialize()) {
            System.err.println("Failed to initialize DPI engine");
            System.exit(1);
        }
        for (String ip : blockIps) {
            engine.blockIP(ip);
        }
        for (String app : blockApps) {
            engine.blockApp(app);
        }
        for (String domain : blockDomains) {
            engine.blockDomain(domain);
        }
        if (!engine.processFile(inputFile, outputFile)) {
            System.err.println("Failed to process file");
            System.exit(1);
        }
        System.out.println("\nProcessing complete!");
        System.out.println("Output written to: " + outputFile);
    }

    private static void printUsage() {
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                    DPI ENGINE v1.0 (Java)                     \u2551");
        System.out.println("\u2551               Deep Packet Inspection System                   \u2551");
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
        System.out.println("\nUsage: java -cp target/classes packetanalyzer.MainDpi <input.pcap> <output.pcap> [options]");
        System.out.println("\nArguments:");
        System.out.println("  input.pcap     Input PCAP file (captured user traffic)");
        System.out.println("  output.pcap    Output PCAP file (filtered traffic to internet)");
        System.out.println("\nOptions:");
        System.out.println("  --block-ip <ip>        Block packets from source IP");
        System.out.println("  --block-app <app>      Block application (e.g., YouTube, Facebook)");
        System.out.println("  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)");
        System.out.println("  --rules <file>         Load blocking rules from file");
        System.out.println("  --lbs <n>              Number of load balancer threads (default: 2)");
        System.out.println("  --fps <n>              FP threads per LB (default: 2)");
        System.out.println("  --verbose              Enable verbose output");
        System.out.println("\nExamples:");
        System.out.println("  java -cp target/classes packetanalyzer.MainDpi capture.pcap filtered.pcap");
        System.out.println("  java -cp target/classes packetanalyzer.MainDpi capture.pcap filtered.pcap --block-app YouTube");
        System.out.println("  java -cp target/classes packetanalyzer.MainDpi capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com");
        System.out.println("  java -cp target/classes packetanalyzer.MainDpi capture.pcap filtered.pcap --rules blocking_rules.txt");
        System.out.println("\nSupported Apps for Blocking:");
        System.out.println("  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,");
        System.out.println("  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub");
    }
}
