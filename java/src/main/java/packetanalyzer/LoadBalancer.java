package packetanalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import packetanalyzer.FiveTuple;
import packetanalyzer.PacketJob;

public class LoadBalancer
implements Runnable {
    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final LinkedBlockingQueue<PacketJob> inputQueue;
    private final List<LinkedBlockingQueue<PacketJob>> fpQueues;
    private final AtomicLong packetsReceived = new AtomicLong(0L);
    private final AtomicLong packetsDispatched = new AtomicLong(0L);
    private final List<LongAdder> perFpCounts;
    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, List<LinkedBlockingQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new LinkedBlockingQueue(10000);
        this.fpQueues = fpQueues;
        this.perFpCounts = new ArrayList<LongAdder>(this.numFps);
        int i = 0;
        while (i < this.numFps) {
            this.perFpCounts.add(new LongAdder());
            ++i;
        }
    }

    public void start() {
        if (this.running) {
            return;
        }
        this.running = true;
        this.thread = new Thread(this, "LoadBalancer-" + this.lbId);
        this.thread.start();
        System.out.printf("[LB%d] Started (serving FP%d-FP%d)\n", this.lbId, this.fpStartId, this.fpStartId + this.numFps - 1);
    }

    public void stop() {
        if (!this.running) {
            return;
        }
        this.running = false;
        if (this.thread != null) {
            this.thread.interrupt();
            try {
                this.thread.join(1000L);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.printf("[LB%d] Stopped\n", this.lbId);
    }

    @Override
    public void run() {
        while (this.running) {
            try {
                PacketJob job = this.inputQueue.poll(100L, TimeUnit.MILLISECONDS);
                if (job == null) continue;
                this.packetsReceived.incrementAndGet();
                int fpIndex = this.selectFP(job.tuple);
                this.fpQueues.get(fpIndex).put(job);
                this.packetsDispatched.incrementAndGet();
                this.perFpCounts.get(fpIndex).increment();
            }
            catch (InterruptedException e) {
                break;
            }
        }
    }

    private int selectFP(FiveTuple tuple) {
        int hash = tuple.hashCode();
        return Math.abs(hash) % this.numFps;
    }

    public LinkedBlockingQueue<PacketJob> getInputQueue() {
        return this.inputQueue;
    }

    public int getId() {
        return this.lbId;
    }

    public boolean isRunning() {
        return this.running;
    }

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packetsReceived = this.packetsReceived.get();
        stats.packetsDispatched = this.packetsDispatched.get();
        stats.perFpPackets = new ArrayList<Long>(this.numFps);
        for (LongAdder count : this.perFpCounts) {
            stats.perFpPackets.add(count.sum());
        }
        return stats;
    }

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public List<Long> perFpPackets;
    }
}
