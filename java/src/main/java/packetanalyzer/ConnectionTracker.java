package packetanalyzer;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import packetanalyzer.AppType;
import packetanalyzer.Connection;
import packetanalyzer.ConnectionState;
import packetanalyzer.FiveTuple;
import packetanalyzer.PacketAction;

public class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections;
    private long totalSeen = 0L;
    private long classifiedCount = 0L;
    private long blockedCount = 0L;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
        this.connections = new LinkedHashMap<FiveTuple, Connection>(16, 0.75f, true){

            @Override
            protected boolean removeEldestEntry(Map.Entry<FiveTuple, Connection> eldest) {
                return this.size() > ConnectionTracker.this.maxConnections;
            }
        };
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            Connection conn = this.connections.get(tuple);
            if (conn != null) {
                return conn;
            }
            conn = new Connection();
            conn.tuple = tuple;
            conn.lastSeen = conn.firstSeen = System.currentTimeMillis();
            this.connections.put(tuple, conn);
            ++this.totalSeen;
            return conn;
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public Connection getConnection(FiveTuple tuple) {
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            Connection conn = this.connections.get(tuple);
            if (conn != null) {
                return conn;
            }
            return this.connections.get(tuple.reverse());
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) {
            return;
        }
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            conn.lastSeen = System.currentTimeMillis();
            if (isOutbound) {
                ++conn.packetsOut;
                conn.bytesOut += packetSize;
            } else {
                ++conn.packetsIn;
                conn.bytesIn += packetSize;
            }
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) {
            return;
        }
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            if (conn.state != ConnectionState.CLASSIFIED) {
                conn.appType = app;
                conn.sni = sni != null ? sni : "";
                conn.state = ConnectionState.CLASSIFIED;
                ++this.classifiedCount;
            }
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void blockConnection(Connection conn) {
        if (conn == null) {
            return;
        }
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            conn.state = ConnectionState.BLOCKED;
            conn.action = PacketAction.DROP;
            ++this.blockedCount;
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void closeConnection(FiveTuple tuple) {
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            Connection conn = this.connections.get(tuple);
            if (conn != null) {
                conn.state = ConnectionState.CLOSED;
            }
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public int cleanupStale(long timeoutMs) {
        long now = System.currentTimeMillis();
        int removed = 0;
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            Iterator<Map.Entry<FiveTuple, Connection>> it = this.connections.entrySet().iterator();
            while (it.hasNext()) {
                Connection conn = it.next().getValue();
                long age = now - conn.lastSeen;
                if (age <= timeoutMs && conn.state != ConnectionState.CLOSED) continue;
                it.remove();
                ++removed;
            }
        }
        return removed;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public List<Connection> getAllConnections() {
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            ArrayList<Connection> result = new ArrayList<Connection>(this.connections.size());
            for (Connection conn : this.connections.values()) {
                Connection copy = new Connection();
                copy.tuple = conn.tuple;
                copy.state = conn.state;
                copy.appType = conn.appType;
                copy.sni = conn.sni;
                copy.packetsIn = conn.packetsIn;
                copy.packetsOut = conn.packetsOut;
                copy.bytesIn = conn.bytesIn;
                copy.bytesOut = conn.bytesOut;
                copy.firstSeen = conn.firstSeen;
                copy.lastSeen = conn.lastSeen;
                copy.action = conn.action;
                copy.synSeen = conn.synSeen;
                copy.synAckSeen = conn.synAckSeen;
                copy.finSeen = conn.finSeen;
                result.add(copy);
            }
            return result;
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public int getActiveCount() {
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            return this.connections.size();
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            stats.activeConnections = this.connections.size();
            stats.totalConnectionsSeen = this.totalSeen;
            stats.classifiedConnections = this.classifiedCount;
            stats.blockedConnections = this.blockedCount;
        }
        return stats;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void clear() {
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            this.connections.clear();
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public void forEach(Consumer<Connection> callback) {
        Map<FiveTuple, Connection> map = this.connections;
        synchronized (map) {
            for (Connection conn : this.connections.values()) {
                callback.accept(conn);
            }
        }
    }

    public static class TrackerStats {
        public int activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }
}
