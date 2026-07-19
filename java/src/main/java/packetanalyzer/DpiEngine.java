package packetanalyzer;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import packetanalyzer.AppType;
import packetanalyzer.Connection;
import packetanalyzer.DpiStats;
import packetanalyzer.FPManager;
import packetanalyzer.FastPathProcessor;
import packetanalyzer.FiveTuple;
import packetanalyzer.GlobalConnectionTable;
import packetanalyzer.LBManager;
import packetanalyzer.LoadBalancer;
import packetanalyzer.PacketAction;
import packetanalyzer.PacketJob;
import packetanalyzer.PacketParser;
import packetanalyzer.ParsedPacket;
import packetanalyzer.PcapHeaders;
import packetanalyzer.PcapReader;
import packetanalyzer.PcapWriter;
import packetanalyzer.RawPacket;
import packetanalyzer.RuleManager;

public class DpiEngine
implements FastPathProcessor.PacketOutputCallback {
    private final Config config;
    private final RuleManager ruleManager;
    private final GlobalConnectionTable globalConnTable;
    private final DpiStats stats;
    private LBManager lbManager;
    private FPManager fpManager;
    private final LinkedBlockingQueue<PacketJob> outputQueue;
    private Thread outputThread;
    private final AtomicBoolean outputRunning = new AtomicBoolean(false);

    public DpiEngine(Config config) {
        this.config = config;
        this.ruleManager = new RuleManager();
        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        this.globalConnTable = new GlobalConnectionTable(totalFps);
        this.stats = new DpiStats();
        this.outputQueue = new LinkedBlockingQueue(10000);
    }

    public void blockIP(String ip) {
        this.ruleManager.blockIP(ip);
    }

    public void blockApp(String appName) {
        AppType[] appTypeArray = AppType.values();
        int n = appTypeArray.length;
        int n2 = 0;
        while (n2 < n) {
            AppType app = appTypeArray[n2];
            if (app.toStringName().equalsIgnoreCase(appName) || app.name().equalsIgnoreCase(appName)) {
                this.ruleManager.blockApp(app);
                return;
            }
            ++n2;
        }
        System.err.println("[Engine] Unknown app: " + appName);
    }

    public void blockDomain(String domain) {
        this.ruleManager.blockDomain(domain);
    }

    public boolean initialize() {
        if (this.config.rulesFile != null && !this.config.rulesFile.isEmpty()) {
            this.ruleManager.loadRules(this.config.rulesFile);
            this.ruleManager.startWatcher(this.config.rulesFile);
        }
        int totalFps = this.config.numLoadBalancers * this.config.fpsPerLb;
        this.fpManager = new FPManager(totalFps, this.ruleManager, this);
        int i = 0;
        while (i < totalFps) {
            this.globalConnTable.registerTracker(i, this.fpManager.getFP(i).getConnectionTracker());
            ++i;
        }
        this.lbManager = new LBManager(this.config.numLoadBalancers, this.config.fpsPerLb, this.fpManager.getQueuePtrs());
        return true;
    }

    @Override
    public void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.FORWARD) {
            try {
                this.outputQueue.put(job);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public boolean processFile(String inputFile, String outputFile) {
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            System.err.println("[Engine] Failed to open input PCAP: " + inputFile);
            return false;
        }
        PcapWriter writer = new PcapWriter();
        if (!writer.open(outputFile, ByteOrder.LITTLE_ENDIAN)) {
            System.err.println("[Engine] Failed to open output PCAP: " + outputFile);
            reader.close();
            return false;
        }
        writer.writeGlobalHeader(reader.getGlobalHeader());
        this.fpManager.startAll();
        this.lbManager.startAll();
        this.outputRunning.set(true);
        this.outputThread = new Thread(() -> {
            while (this.outputRunning.get() || !this.outputQueue.isEmpty()) {
                try {
                    PacketJob job = this.outputQueue.poll(50L, TimeUnit.MILLISECONDS);
                    if (job == null) continue;
                    PcapHeaders.PcapPacketHeader phdr = new PcapHeaders.PcapPacketHeader();
                    phdr.tsSec = job.tsSec;
                    phdr.tsUsec = job.tsUsec;
                    phdr.inclLen = job.data.length;
                    phdr.origLen = job.data.length;
                    writer.writePacket(phdr, job.data);
                }
                catch (InterruptedException e) {
                    break;
                }
            }
        }, "OutputWriter");
        this.outputThread.start();
        System.out.println("[Reader] Processing packets...");
        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        int packetId = 0;
        while (reader.readNextPacket(raw)) {
            ++packetId;
            if (!PacketParser.parse(raw, parsed)) {
                this.stats.otherPackets.incrementAndGet();
                continue;
            }
            if (!parsed.hasIp || !parsed.hasTcp && !parsed.hasUdp) {
                this.stats.otherPackets.incrementAndGet();
                continue;
            }
            FiveTuple tuple = new FiveTuple();
            tuple.srcIp = this.parseIP(parsed.srcIp);
            tuple.dstIp = this.parseIP(parsed.destIp);
            tuple.srcPort = parsed.srcPort;
            tuple.dstPort = parsed.destPort;
            tuple.protocol = parsed.protocol;
            PacketJob job = new PacketJob(packetId, tuple, raw.data, raw.header.tsSec, raw.header.tsUsec);
            job.payloadOffset = 14;
            if (job.data.length > 14) {
                int ipIhl = job.data[14] & 0xF;
                job.payloadOffset += ipIhl * 4;
                if (parsed.hasTcp && job.payloadOffset + 12 < job.data.length) {
                    int tcpOff = job.data[job.payloadOffset + 12] >> 4 & 0xF;
                    job.payloadOffset += tcpOff * 4;
                    job.tcpFlags = parsed.tcpFlags;
                } else if (parsed.hasUdp) {
                    job.payloadOffset += 8;
                }
                job.payloadLength = job.payloadOffset < job.data.length ? job.data.length - job.payloadOffset : 0;
            }
            this.stats.totalPackets.incrementAndGet();
            this.stats.totalBytes.addAndGet(job.data.length);
            if (parsed.hasTcp) {
                this.stats.tcpPackets.incrementAndGet();
            } else if (parsed.hasUdp) {
                this.stats.udpPackets.incrementAndGet();
            }
            LoadBalancer lb = this.lbManager.getLBForPacket(job.tuple);
            try {
                lb.getInputQueue().put(job);
            }
            catch (InterruptedException e) {
                System.err.println("[Reader] Interrupted while dispatching packet ID " + packetId);
                Thread.currentThread().interrupt();
                break;
            }
        }
        System.out.println("[Reader] Done reading " + packetId + " packets");
        reader.close();
        try {
            Thread.sleep(500L);
        }
        catch (InterruptedException tuple) {
            // empty catch block
        }
        this.lbManager.stopAll();
        this.fpManager.stopAll();
        this.ruleManager.stopWatcher();
        this.outputRunning.set(false);
        try {
            this.outputThread.join(2000L);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        writer.close();
        FPManager.AggregatedStats fpAggregated = this.fpManager.getAggregatedStats();
        this.stats.forwardedPackets.set(fpAggregated.totalForwarded);
        this.stats.droppedPackets.set(fpAggregated.totalDropped);
        this.stats.activeConnections.set(this.globalConnTable.getGlobalStats().totalActiveConnections);
        this.printReport();
        return true;
    }

    private int parseIP(String ip) {
        int result = 0;
        int octet = 0;
        int shift = 0;
        int i = 0;
        while (i < ip.length()) {
            char c = ip.charAt(i);
            if (c == '.') {
                result |= octet << shift;
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - 48);
            }
            ++i;
        }
        return result | octet << shift;
    }

    private void printReport() {
        System.out.println();
        System.out.println("+" + "-".repeat(62) + "+");
        System.out.println("|                      PROCESSING REPORT                        |");
        System.out.println("+" + "-".repeat(62) + "+");
        System.out.printf("| Total Packets:      %12d                             |\n", this.stats.totalPackets.get());
        System.out.printf("| Total Bytes:        %12d                             |\n", this.stats.totalBytes.get());
        System.out.printf("| TCP Packets:        %12d                             |\n", this.stats.tcpPackets.get());
        System.out.printf("| UDP Packets:        %12d                             |\n", this.stats.udpPackets.get());
        System.out.println("+" + "-".repeat(62) + "+");
        System.out.printf("| Forwarded:          %12d                             |\n", this.stats.forwardedPackets.get());
        System.out.printf("| Dropped:            %12d                             |\n", this.stats.droppedPackets.get());
        System.out.println("+" + "-".repeat(62) + "+");
        System.out.println("| THREAD STATISTICS                                             |");
        int i = 0;
        while (i < this.lbManager.getNumLBs()) {
            LoadBalancer.LBStats lbStats = this.lbManager.getLB(i).getStats();
            System.out.printf("|   LB%d dispatched:   %12d                             |\n", i, lbStats.packetsDispatched);
            ++i;
        }
        i = 0;
        while (i < this.fpManager.getNumFPs()) {
            System.out.printf("|   FP%d processed:    %12d                             |\n", i, this.fpManager.getFP((int)i).getStats().packetsProcessed);
            ++i;
        }
        HashMap<AppType, Long> appCounts = new HashMap<AppType, Long>();
        TreeMap<String, AppType> detectedSnis = new TreeMap<String, AppType>();
        int i2 = 0;
        while (i2 < this.fpManager.getNumFPs()) {
            FastPathProcessor fp = this.fpManager.getFP(i2);
            List<Connection> connections = fp.getConnectionTracker().getAllConnections();
            for (Connection connection : connections) {
                appCounts.put(connection.appType, appCounts.getOrDefault((Object)connection.appType, 0L) + 1L);
                if (connection.sni == null || connection.sni.isEmpty()) continue;
                detectedSnis.put(connection.sni, connection.appType);
            }
            ++i2;
        }
        System.out.println("+" + "-".repeat(62) + "+");
        System.out.println("|                   APPLICATION BREAKDOWN                       |");
        System.out.println("+" + "-".repeat(62) + "+");
        ArrayList<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        long total = this.stats.totalPackets.get();
        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0L ? 100.0 * (double)entry.getValue().longValue() / (double)total : 0.0;
            int barLen = (int)(pct / 5.0);
            String barStr = "#".repeat(barLen);
            System.out.printf("| %-15s %8d %5.1f%% %-20s         |\n", entry.getKey().toStringName(), entry.getValue(), pct, barStr);
        }
        System.out.println("+" + "-".repeat(62) + "+");
        if (!detectedSnis.isEmpty()) {
            System.out.println("\n[Detected Domains/SNIs]");
            for (Map.Entry entry : detectedSnis.entrySet()) {
                System.out.printf("  - %s -> %s\n", entry.getKey(), ((AppType)((Object)entry.getValue())).toStringName());
            }
        }
    }

    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public boolean verbose = false;
        public String rulesFile = "";
    }
}
