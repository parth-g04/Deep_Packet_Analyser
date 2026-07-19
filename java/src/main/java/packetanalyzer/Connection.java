/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import packetanalyzer.AppType;
import packetanalyzer.ConnectionState;
import packetanalyzer.FiveTuple;
import packetanalyzer.PacketAction;

public class Connection {
    public FiveTuple tuple;
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";
    public long packetsIn = 0L;
    public long packetsOut = 0L;
    public long bytesIn = 0L;
    public long bytesOut = 0L;
    public long firstSeen;
    public long lastSeen;
    public PacketAction action = PacketAction.FORWARD;
    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;

    public Connection() {
        long now;
        this.firstSeen = now = System.currentTimeMillis();
        this.lastSeen = now;
    }
}
