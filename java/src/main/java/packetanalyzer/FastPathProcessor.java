/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import packetanalyzer.AppType;
import packetanalyzer.Connection;
import packetanalyzer.ConnectionState;
import packetanalyzer.ConnectionTracker;
import packetanalyzer.PacketAction;
import packetanalyzer.PacketJob;
import packetanalyzer.RuleManager;
import packetanalyzer.SNIExtractor;

public class FastPathProcessor
implements Runnable {
    private final int fpId;
    private final LinkedBlockingQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;
    private final AtomicLong packetsProcessed = new AtomicLong(0L);
    private final AtomicLong packetsForwarded = new AtomicLong(0L);
    private final AtomicLong packetsDropped = new AtomicLong(0L);
    private final AtomicLong sniExtractions = new AtomicLong(0L);
    private final AtomicLong classificationHits = new AtomicLong(0L);
    private volatile boolean running = false;
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new LinkedBlockingQueue(10000);
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public void start() {
        if (this.running) {
            return;
        }
        this.running = true;
        this.thread = new Thread(this, "FastPath-" + this.fpId);
        this.thread.start();
        System.out.printf("[FP%d] Started\n", this.fpId);
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
        System.out.printf("[FP%d] Stopped (processed %d packets)\n", this.fpId, this.packetsProcessed.get());
    }

    @Override
    public void run() {
        while (this.running) {
            try {
                PacketJob job = this.inputQueue.poll(100L, TimeUnit.MILLISECONDS);
                if (job == null) {
                    this.connTracker.cleanupStale(300000L);
                    continue;
                }
                this.packetsProcessed.incrementAndGet();
                PacketAction action = this.processPacket(job);
                if (this.outputCallback != null) {
                    this.outputCallback.handleOutput(job, action);
                }
                if (action == PacketAction.DROP) {
                    this.packetsDropped.incrementAndGet();
                    continue;
                }
                this.packetsForwarded.incrementAndGet();
            }
            catch (InterruptedException e) {
                break;
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = this.connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) {
            return PacketAction.FORWARD;
        }
        this.connTracker.updateConnection(conn, job.data.length, true);
        if (job.tuple.protocol == 6) {
            this.updateTCPState(conn, job.tcpFlags);
        }
        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }
        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            this.inspectPayload(job, conn);
        }
        return this.checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        String domain;
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) {
            return;
        }
        if (this.tryExtractSNI(job, conn)) {
            return;
        }
        if (this.tryExtractHTTPHost(job, conn)) {
            return;
        }
        if ((job.tuple.dstPort == 53 || job.tuple.srcPort == 53) && (domain = SNIExtractor.extractDNSQuery(job.data, job.payloadOffset, job.payloadLength)) != null) {
            this.connTracker.classifyConnection(conn, AppType.DNS, domain);
            return;
        }
        if (job.tuple.dstPort == 80) {
            this.connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            this.connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) {
            return false;
        }
        String sni = SNIExtractor.extractSNI(job.data, job.payloadOffset, job.payloadLength);
        if (sni != null) {
            this.sniExtractions.incrementAndGet();
            AppType app = AppType.sniToAppType(sni);
            this.connTracker.classifyConnection(conn, app, sni);
            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                this.classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80) {
            return false;
        }
        String host = SNIExtractor.extractHTTPHost(job.data, job.payloadOffset, job.payloadLength);
        if (host != null) {
            AppType app = AppType.sniToAppType(host);
            this.connTracker.classifyConnection(conn, app, host);
            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                this.classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (this.ruleManager == null) {
            return PacketAction.FORWARD;
        }
        RuleManager.BlockReason blockReason = this.ruleManager.shouldBlock(job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);
        if (blockReason != null) {
            String reasonText = switch (blockReason.type) {
                case RuleManager.BlockReason.Type.IP -> "IP " + blockReason.detail;
                case RuleManager.BlockReason.Type.APP -> "App " + blockReason.detail;
                case RuleManager.BlockReason.Type.DOMAIN -> "Domain " + blockReason.detail;
                case RuleManager.BlockReason.Type.PORT -> "Port " + blockReason.detail;
                default -> throw new MatchException(null, null);
            };
            System.out.printf("[FP%d] BLOCKED packet: %s\n", this.fpId, reasonText);
            this.connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }
        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, byte flags) {
        boolean rst;
        boolean syn = (flags & 2) != 0;
        boolean ack = (flags & 0x10) != 0;
        boolean fin = (flags & 1) != 0;
        boolean bl = rst = (flags & 4) != 0;
        if (syn) {
            if (ack) {
                conn.synAckSeen = true;
            } else {
                conn.synSeen = true;
            }
        }
        if (conn.synSeen && conn.synAckSeen && ack && conn.state == ConnectionState.NEW) {
            conn.state = ConnectionState.ESTABLISHED;
        }
        if (fin) {
            conn.finSeen = true;
        }
        if (rst) {
            conn.state = ConnectionState.CLOSED;
        }
        if (conn.finSeen && ack) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public LinkedBlockingQueue<PacketJob> getInputQueue() {
        return this.inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return this.connTracker;
    }

    public int getId() {
        return this.fpId;
    }

    public boolean isRunning() {
        return this.running;
    }

    public FPStats getStats() {
        FPStats stats = new FPStats();
        stats.packetsProcessed = this.packetsProcessed.get();
        stats.packetsForwarded = this.packetsForwarded.get();
        stats.packetsDropped = this.packetsDropped.get();
        stats.connectionsTracked = this.connTracker.getActiveCount();
        stats.sniExtractions = this.sniExtractions.get();
        stats.classificationHits = this.classificationHits.get();
        return stats;
    }

    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public long connectionsTracked;
        public long sniExtractions;
        public long classificationHits;
    }

    public static interface PacketOutputCallback {
        public void handleOutput(PacketJob var1, PacketAction var2);
    }
}
