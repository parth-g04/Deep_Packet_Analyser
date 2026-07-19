package packetanalyzer;

import java.util.concurrent.atomic.AtomicLong;

public class DpiStats {
    public final AtomicLong totalPackets = new AtomicLong(0L);
    public final AtomicLong totalBytes = new AtomicLong(0L);
    public final AtomicLong forwardedPackets = new AtomicLong(0L);
    public final AtomicLong droppedPackets = new AtomicLong(0L);
    public final AtomicLong tcpPackets = new AtomicLong(0L);
    public final AtomicLong udpPackets = new AtomicLong(0L);
    public final AtomicLong otherPackets = new AtomicLong(0L);
    public final AtomicLong activeConnections = new AtomicLong(0L);
}
