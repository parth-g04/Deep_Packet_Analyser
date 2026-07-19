/*
 * Decompiled with CFR 0.152.
 */
package packetanalyzer;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import packetanalyzer.PcapHeaders;
import packetanalyzer.RawPacket;

public class PcapReader
implements AutoCloseable {
    private BufferedInputStream inputStream;
    private PcapHeaders.PcapGlobalHeader globalHeader;
    private ByteOrder byteOrder = ByteOrder.BIG_ENDIAN;
    private boolean isOpen = false;

    public boolean open(String filename) {
        byte[] headerBytes;
        block7: {
            block6: {
                try {
                    this.close();
                    this.inputStream = new BufferedInputStream(new FileInputStream(filename));
                    headerBytes = new byte[24];
                    int read = this.inputStream.read(headerBytes);
                    if (read >= 24) break block6;
                    System.err.println("Error: Could not read PCAP global header");
                    this.close();
                    return false;
                }
                catch (IOException e) {
                    System.err.println("Error: Could not open file: " + filename + " (" + e.getMessage() + ")");
                    this.close();
                    return false;
                }
            }
            int magic = (headerBytes[0] & 0xFF) << 24 | (headerBytes[1] & 0xFF) << 16 | (headerBytes[2] & 0xFF) << 8 | headerBytes[3] & 0xFF;
            if (magic == -1582119980) {
                this.byteOrder = ByteOrder.BIG_ENDIAN;
                break block7;
            }
            if (magic == -725372255) {
                this.byteOrder = ByteOrder.LITTLE_ENDIAN;
                break block7;
            }
            System.err.printf("Error: Invalid PCAP magic number: 0x%08X\n", magic);
            this.close();
            return false;
        }
        ByteBuffer buf = ByteBuffer.wrap(headerBytes);
        buf.order(this.byteOrder);
        this.globalHeader = new PcapHeaders.PcapGlobalHeader();
        this.globalHeader.magicNumber = buf.getInt();
        this.globalHeader.versionMajor = buf.getShort();
        this.globalHeader.versionMinor = buf.getShort();
        this.globalHeader.thiszone = buf.getInt();
        this.globalHeader.sigfigs = buf.getInt();
        this.globalHeader.snaplen = buf.getInt();
        this.globalHeader.network = buf.getInt();
        this.isOpen = true;
        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + this.globalHeader.versionMajor + "." + this.globalHeader.versionMinor);
        System.out.println("  Snaplen: " + this.globalHeader.snaplen + " bytes");
        System.out.println("  Link type: " + this.globalHeader.network + (this.globalHeader.network == 1 ? " (Ethernet)" : ""));
        return true;
    }

    @Override
    public void close() {
        if (this.inputStream != null) {
            try {
                this.inputStream.close();
            }
            catch (IOException iOException) {
                // empty catch block
            }
            this.inputStream = null;
        }
        this.isOpen = false;
        this.globalHeader = null;
    }

    public boolean readNextPacket(RawPacket packet) {
        if (!this.isOpen || this.inputStream == null) {
            return false;
        }
        try {
            byte[] headerBytes = new byte[16];
            int read = this.readFully(this.inputStream, headerBytes);
            if (read < 16) {
                return false;
            }
            ByteBuffer buf = ByteBuffer.wrap(headerBytes);
            buf.order(this.byteOrder);
            PcapHeaders.PcapPacketHeader pktHeader = new PcapHeaders.PcapPacketHeader();
            pktHeader.tsSec = buf.getInt();
            pktHeader.tsUsec = buf.getInt();
            pktHeader.inclLen = buf.getInt();
            pktHeader.origLen = buf.getInt();
            if (pktHeader.inclLen > this.globalHeader.snaplen || pktHeader.inclLen > 65535 || pktHeader.inclLen < 0) {
                System.err.println("Error: Invalid packet length: " + pktHeader.inclLen);
                return false;
            }
            byte[] dataBytes = new byte[pktHeader.inclLen];
            int dataRead = this.readFully(this.inputStream, dataBytes);
            if (dataRead < pktHeader.inclLen) {
                System.err.println("Error: Could not read packet data");
                return false;
            }
            packet.header = pktHeader;
            packet.data = dataBytes;
            return true;
        }
        catch (IOException e) {
            System.err.println("Error: Exception reading packet: " + e.getMessage());
            return false;
        }
    }

    private int readFully(BufferedInputStream in, byte[] b) throws IOException {
        int total = 0;
        while (total < b.length) {
            int result = in.read(b, total, b.length - total);
            if (result == -1) break;
            total += result;
        }
        return total;
    }

    public PcapHeaders.PcapGlobalHeader getGlobalHeader() {
        return this.globalHeader;
    }

    public boolean isOpen() {
        return this.isOpen;
    }

    public ByteOrder getByteOrder() {
        return this.byteOrder;
    }
}
