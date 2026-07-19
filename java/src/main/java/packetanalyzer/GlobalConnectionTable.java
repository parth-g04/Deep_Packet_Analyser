/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import packetanalyzer.AppType;
import packetanalyzer.ConnectionTracker;

public class GlobalConnectionTable {
    private final List<ConnectionTracker> trackers;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        this.trackers = new ArrayList<ConnectionTracker>(Collections.nCopies(numFps, null));
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        this.lock.writeLock().lock();
        try {
            if (fpId >= 0 && fpId < this.trackers.size()) {
                this.trackers.set(fpId, tracker);
            }
        }
        finally {
            this.lock.writeLock().unlock();
        }
    }

    public GlobalStats getGlobalStats() {
        this.lock.readLock().lock();
        try {
            GlobalStats stats = new GlobalStats();
            HashMap<String, Integer> domainCounts = new HashMap<>();
            for (ConnectionTracker tracker : this.trackers) {
                if (tracker == null) continue;
                ConnectionTracker.TrackerStats tStats = tracker.getStats();
                stats.totalActiveConnections += tStats.activeConnections;
                stats.totalConnectionsSeen += tStats.totalConnectionsSeen;
                tracker.forEach(conn -> {
                    stats.appDistribution.put(conn.appType, stats.appDistribution.getOrDefault(conn.appType, 0) + 1);
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.put(conn.sni, domainCounts.getOrDefault(conn.sni, 0) + 1);
                    }
                });
            }
            ArrayList<Map.Entry<String, Integer>> domainList = new ArrayList<>(domainCounts.entrySet());
            domainList.sort((a, b) -> b.getValue().compareTo(a.getValue()));
            int topCount = Math.min(domainList.size(), 20);
            stats.topDomains = new ArrayList<Map.Entry<String, Integer>>(domainList.subList(0, topCount));
            GlobalStats globalStats = stats;
            return globalStats;
        }
        finally {
            this.lock.readLock().unlock();
        }
    }

    public String generateReport() {
        GlobalStats stats = this.getGlobalStats();
        StringBuilder sb = new StringBuilder();
        sb.append("\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n");
        sb.append("\u2551               CONNECTION STATISTICS REPORT                    \u2551\n");
        sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        sb.append(String.format("\u2551 Active Connections:     %-10d                                  \u2551\n", stats.totalActiveConnections));
        sb.append(String.format("\u2551 Total Connections Seen: %-10d                                  \u2551\n", stats.totalConnectionsSeen));
        sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        sb.append("\u2551                    APPLICATION BREAKDOWN                      \u2551\n");
        sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
        int total = stats.appDistribution.values().stream().mapToInt(Integer::intValue).sum();
        ArrayList<Map.Entry<AppType, Integer>> sortedApps = new ArrayList<Map.Entry<AppType, Integer>>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> ((Integer)b.getValue()).compareTo((Integer)a.getValue()));
        for (Map.Entry<AppType, Integer> entry : sortedApps) {
            double pct = total > 0 ? 100.0 * (double)entry.getValue().intValue() / (double)total : 0.0;
            sb.append(String.format("\u2551 %-20s %-10d (%5.1f%%)                         \u2551\n", entry.getKey().toStringName(), entry.getValue(), pct));
        }
        if (!stats.topDomains.isEmpty()) {
            sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
            sb.append("\u2551                      TOP DOMAINS                             \u2551\n");
            sb.append("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n");
            for (Map.Entry<String, Integer> entry : stats.topDomains) {
                String domain = entry.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                sb.append(String.format("\u2551 %-40s %-10d                    \u2551\n", domain, entry.getValue()));
            }
        }
        sb.append("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n");
        return sb.toString();
    }

    public static class GlobalStats {
        public int totalActiveConnections;
        public long totalConnectionsSeen;
        public Map<AppType, Integer> appDistribution = new HashMap<AppType, Integer>();
        public List<Map.Entry<String, Integer>> topDomains = new ArrayList<Map.Entry<String, Integer>>();
    }
}
