/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import packetanalyzer.FiveTuple;
import packetanalyzer.LoadBalancer;
import packetanalyzer.PacketJob;

public class LBManager {
    private final List<LoadBalancer> lbs = new ArrayList<LoadBalancer>();
    private final int fpsPerLb;

    public LBManager(int numLbs, int fpsPerLb, List<LinkedBlockingQueue<PacketJob>> fpQueues) {
        this.fpsPerLb = fpsPerLb;
        int lbId = 0;
        while (lbId < numLbs) {
            ArrayList<LinkedBlockingQueue<PacketJob>> lbFpQueues = new ArrayList<LinkedBlockingQueue<PacketJob>>();
            int fpStart = lbId * fpsPerLb;
            int i = 0;
            while (i < fpsPerLb) {
                lbFpQueues.add(fpQueues.get(fpStart + i));
                ++i;
            }
            this.lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
            ++lbId;
        }
        System.out.printf("[LBManager] Created %d load balancers, %d FPs each\n", numLbs, fpsPerLb);
    }

    public void startAll() {
        for (LoadBalancer lb : this.lbs) {
            lb.start();
        }
    }

    public void stopAll() {
        for (LoadBalancer lb : this.lbs) {
            lb.stop();
        }
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        int hash = tuple.hashCode();
        int lbIndex = Math.abs(hash) % this.lbs.size();
        return this.lbs.get(lbIndex);
    }

    public LoadBalancer getLB(int id) {
        return this.lbs.get(id);
    }

    public int getNumLBs() {
        return this.lbs.size();
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats stats = new AggregatedStats();
        for (LoadBalancer lb : this.lbs) {
            LoadBalancer.LBStats lbStats = lb.getStats();
            stats.totalReceived += lbStats.packetsReceived;
            stats.totalDispatched += lbStats.packetsDispatched;
        }
        return stats;
    }

    public static class AggregatedStats {
        public long totalReceived;
        public long totalDispatched;
    }
}
