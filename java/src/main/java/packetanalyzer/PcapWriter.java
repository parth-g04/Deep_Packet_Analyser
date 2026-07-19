package packetanalyzer;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import packetanalyzer.PcapHeaders;

public class PcapWriter
implements AutoCloseable {
    private BufferedOutputStream outputStream;
    private ByteOrder byteOrder = ByteOrder.BIG_ENDIAN;
    private boolean isOpen = false;

    public boolean open(String filename, ByteOrder byteOrder) {
        try {
            this.close();
            this.byteOrder = byteOrder;
            this.outputStream = new BufferedOutputStream(new FileOutputStream(filename));
            this.isOpen = true;
            return true;
        }
        catch (IOException e) {
            System.err.println("Error: Cannot open output file " + filename + " (" + e.getMessage() + ")");
            this.close();
            return false;
        }
    }

    @Override
    public void close() {
        if (this.outputStream != null) {
            try {
                this.outputStream.flush();
                this.outputStream.close();
            }
            catch (IOException iOException) {
                // empty catch block
            }
            this.outputStream = null;
        }
        this.isOpen = false;
    }

    public boolean writeGlobalHeader(PcapHeaders.PcapGlobalHeader header) {
        if (!this.isOpen || this.outputStream == null) {
            return false;
        }
        try {
            byte[] bytes = new byte[24];
            ByteBuffer buf = ByteBuffer.wrap(bytes);
            buf.order(this.byteOrder);
            buf.putInt(header.magicNumber);
            buf.putShort(header.versionMajor);
            buf.putShort(header.versionMinor);
            buf.putInt(header.thiszone);
            buf.putInt(header.sigfigs);
            buf.putInt(header.snaplen);
            buf.putInt(header.network);
            this.outputStream.write(bytes);
            return true;
        }
        catch (IOException e) {
            System.err.println("Error: Writing global header: " + e.getMessage());
            return false;
        }
    }

    public boolean writePacket(PcapHeaders.PcapPacketHeader header, byte[] data) {
        if (!this.isOpen || this.outputStream == null) {
            return false;
        }
        try {
            byte[] headerBytes = new byte[16];
            ByteBuffer buf = ByteBuffer.wrap(headerBytes);
            buf.order(this.byteOrder);
            buf.putInt(header.tsSec);
            buf.putInt(header.tsUsec);
            buf.putInt(header.inclLen);
            buf.putInt(header.origLen);
            this.outputStream.write(headerBytes);
            this.outputStream.write(data);
            return true;
        }
        catch (IOException e) {
            System.err.println("Error: Writing packet: " + e.getMessage());
            return false;
        }
    }

    public boolean isOpen() {
        return this.isOpen;
    }
}
