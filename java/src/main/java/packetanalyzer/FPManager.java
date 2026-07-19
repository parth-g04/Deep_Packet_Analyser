package packetanalyzer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import packetanalyzer.AppType;
import packetanalyzer.Connection;
import packetanalyzer.FastPathProcessor;
import packetanalyzer.PacketJob;
import packetanalyzer.RuleManager;

public class FPManager {
    private final List<FastPathProcessor> fps = new ArrayList<FastPathProcessor>();

    public FPManager(int numFps, RuleManager ruleManager, FastPathProcessor.PacketOutputCallback outputCallback) {
        int i = 0;
        while (i < numFps) {
            this.fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
            ++i;
        }
        System.out.printf("[FPManager] Created %d fast path processors\n", numFps);
    }

    public void startAll() {
        for (FastPathProcessor fp : this.fps) {
            fp.start();
        }
    }

    public void stopAll() {
        for (FastPathProcessor fp : this.fps) {
            fp.stop();
        }
    }

    public FastPathProcessor getFP(int id) {
        return this.fps.get(id);
    }

    public LinkedBlockingQueue<PacketJob> getFPQueue(int id) {
        return this.fps.get(id).getInputQueue();
    }

    public List<LinkedBlockingQueue<PacketJob>> getQueuePtrs() {
        ArrayList<LinkedBlockingQueue<PacketJob>> queues = new ArrayList<LinkedBlockingQueue<PacketJob>>();
        for (FastPathProcessor fp : this.fps) {
            queues.add(fp.getInputQueue());
        }
        return queues;
    }

    public int getNumFPs() {
        return this.fps.size();
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (FastPathProcessor fp : this.fps) {
            FastPathProcessor.FPStats fpStats = fp.getStats();
            stats.totalProcessed += fpStats.packetsProcessed;
            stats.totalForwarded += fpStats.packetsForwarded;
            stats.totalDropped += fpStats.packetsDropped;
            stats.totalConnections += fpStats.connectionsTracked;
        }
        return stats;
    }

    public String generateClassificationReport() {
        HashMap<AppType, Long> appCounts = new HashMap<AppType, Long>();
        HashMap<String, Long> domainCounts = new HashMap<String, Long>();
        long totalClassified = 0L;
        long totalUnknown = 0L;
        for (FastPathProcessor fp : this.fps) {
            List<Connection> connections = fp.getConnectionTracker().getAllConnections();
            for (Connection conn : connections) {
                appCounts.put(conn.appType, appCounts.getOrDefault((Object)conn.appType, 0L) + 1L);
                if (conn.appType == AppType.UNKNOWN) {
                    ++totalUnknown;
                } else {
                    ++totalClassified;
                }
                if (conn.sni == null || conn.sni.isEmpty()) continue;
                domainCounts.put(conn.sni, domainCounts.getOrDefault(conn.sni, 0L) + 1L);
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n");
        sb.append("\u2551                 APPLICATION CLASSIFICATION REPORT             \u2551\n");
        sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0L ? 100.0 * (double)totalClassified / (double)total : 0.0;
        double unknownPct = total > 0L ? 100.0 * (double)totalUnknown / (double)total : 0.0;
        sb.append(String.format("\u2551 Total Connections:    %-10d                              \u2551\n", total));
        sb.append(String.format("\u2551 Classified:           %-10d (%5.1f%%)                     \u2551\n", totalClassified, classifiedPct));
        sb.append(String.format("\u2551 Unidentified:         %-10d (%5.1f%%)                     \u2551\n", totalUnknown, unknownPct));
        sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        sb.append("\u2551                    APPLICATION DISTRIBUTION                   \u2551\n");
        sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        ArrayList<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0L ? 100.0 * (double)entry.getValue().longValue() / (double)total : 0.0;
            int barLen = (int)(pct / 5.0);
            String bar = "#".repeat(barLen);
            sb.append(String.format("\u2551 %-15s %-8d %5.1f%% %-20s   \u2551\n", entry.getKey().toStringName(), entry.getValue(), pct, bar));
        }
        sb.append("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");
        return sb.toString();
    }

    public static class AggregatedStats {
        public long totalProcessed;
        public long totalForwarded;
        public long totalDropped;
        public long totalConnections;
    }
}
