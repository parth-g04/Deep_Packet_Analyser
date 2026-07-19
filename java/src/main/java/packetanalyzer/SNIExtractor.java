package packetanalyzer;

import java.nio.charset.StandardCharsets;

public class SNIExtractor {
    private static final byte CONTENT_TYPE_HANDSHAKE = 22;
    private static final byte HANDSHAKE_CLIENT_HELLO = 1;
    private static final int EXTENSION_SNI = 0;
    private static final byte SNI_TYPE_HOSTNAME = 0;

    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9) {
            return false;
        }
        if (payload[offset] != 22) {
            return false;
        }
        int version = SNIExtractor.readUint16BE(payload, offset + 1);
        if (version < 768 || version > 772) {
            return false;
        }
        int recordLength = SNIExtractor.readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) {
            return false;
        }
        return payload[offset + 5] == 1;
    }

    public static String extractSNI(byte[] payload, int offset, int length) {
        if (!SNIExtractor.isTLSClientHello(payload, offset, length)) {
            return null;
        }
        int idx = offset + 5;
        idx += 4; // skip handshake type and length
        idx += 2; // skip client version
        idx += 32; // skip client random
        
        if (idx >= offset + length) {
            return null;
        }
        int sessionIdLength = payload[idx] & 0xFF;
        idx += 1 + sessionIdLength;
        
        if (idx + 2 > offset + length) {
            return null;
        }
        int cipherSuitesLength = SNIExtractor.readUint16BE(payload, idx);
        idx += 2 + cipherSuitesLength;
        
        if (idx >= offset + length) {
            return null;
        }
        int compressionMethodsLength = payload[idx] & 0xFF;
        idx += 1 + compressionMethodsLength;
        
        if (idx + 2 > offset + length) {
            return null;
        }
        int extensionsLength = SNIExtractor.readUint16BE(payload, idx);
        idx += 2;
        
        int extensionsEnd = idx + extensionsLength;
        if (extensionsEnd > offset + length) {
            extensionsEnd = offset + length;
        }
        while (idx + 4 <= extensionsEnd) {
            int extensionType = SNIExtractor.readUint16BE(payload, idx);
            int extensionLength = SNIExtractor.readUint16BE(payload, idx + 2);
            idx += 4;
            if (idx + extensionLength > extensionsEnd) {
                break;
            }
            if (extensionType == 0) {
                if (extensionLength < 5) break;
                int sniListLength = SNIExtractor.readUint16BE(payload, idx);
                if (sniListLength < 3) break;
                int sniType = payload[idx + 2] & 0xFF;
                int sniLength = SNIExtractor.readUint16BE(payload, idx + 3);
                if (sniType != 0 || sniLength > extensionLength - 5) break;
                return new String(payload, idx + 5, sniLength, StandardCharsets.US_ASCII);
            }
            idx += extensionLength;
        }
        return null;
    }

    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        String[] methods;
        if (length < 4) {
            return false;
        }
        String[] stringArray = methods = new String[]{"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        int n = methods.length;
        int n2 = 0;
        while (n2 < n) {
            String method = stringArray[n2];
            boolean match = true;
            int j = 0;
            while (j < 4) {
                if (payload[offset + j] != method.charAt(j)) {
                    match = false;
                    break;
                }
                ++j;
            }
            if (match) {
                return true;
            }
            ++n2;
        }
        return false;
    }

    public static String extractHTTPHost(byte[] payload, int offset, int length) {
        if (!SNIExtractor.isHTTPRequest(payload, offset, length)) {
            return null;
        }
        int i = offset;
        while (i + 5 < offset + length) {
            if (!(payload[i] != 72 && payload[i] != 104 || payload[i + 1] != 111 && payload[i + 1] != 79 || payload[i + 2] != 115 && payload[i + 2] != 83 || payload[i + 3] != 116 && payload[i + 3] != 84 || payload[i + 4] != 58)) {
                int start = i + 5;
                while (start < offset + length && (payload[start] == 32 || payload[start] == 9)) {
                    ++start;
                }
                int end = start;
                while (end < offset + length && payload[end] != 13 && payload[end] != 10) {
                    ++end;
                }
                if (end > start) {
                    String host = new String(payload, start, end - start, StandardCharsets.UTF_8).trim();
                    int colonPos = host.indexOf(58);
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }
                    return host;
                }
            }
            ++i;
        }
        return null;
    }

    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        if (length < 12) {
            return false;
        }
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0) {
            return false;
        }
        int qdcount = (payload[offset + 4] & 0xFF) << 8 | payload[offset + 5] & 0xFF;
        return qdcount != 0;
    }

    public static String extractDNSQuery(byte[] payload, int offset, int length) {
        if (!SNIExtractor.isDNSQuery(payload, offset, length)) {
            return null;
        }
        int idx = offset + 12;
        StringBuilder domain = new StringBuilder();
        while (idx < offset + length) {
            int labelLength = payload[idx] & 0xFF;
            if (labelLength == 0 || labelLength > 63 || ++idx + labelLength > offset + length) break;
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, idx, labelLength, StandardCharsets.UTF_8));
            idx += labelLength;
        }
        return domain.length() == 0 ? null : domain.toString();
    }

    public static boolean isQUICInitial(byte[] payload, int offset, int length) {
        if (length < 5) {
            return false;
        }
        int firstByte = payload[offset] & 0xFF;
        return (firstByte & 0x80) != 0;
    }

    public static String extractQUICSNI(byte[] payload, int offset, int length) {
        if (!SNIExtractor.isQUICInitial(payload, offset, length)) {
            return null;
        }
        int i = offset;
        while (i + 50 < offset + length) {
            String sni;
            int tlsRecordOffset;
            if (payload[i] == 1 && (tlsRecordOffset = i - 5) >= offset && (sni = SNIExtractor.extractSNI(payload, tlsRecordOffset, offset + length - tlsRecordOffset)) != null) {
                return sni;
            }
            ++i;
        }
        return null;
    }

    private static int readUint16BE(byte[] data, int offset) {
        return (data[offset] & 0xFF) << 8 | data[offset + 1] & 0xFF;
    }

    private static int readUint24BE(byte[] data, int offset) {
        return (data[offset] & 0xFF) << 16 | (data[offset + 1] & 0xFF) << 8 | data[offset + 2] & 0xFF;
    }
}
