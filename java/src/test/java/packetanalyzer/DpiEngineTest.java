package packetanalyzer;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public class DpiEngineTest {

    @Test
    public void testFiveTupleEqualityAndHash() {
        FiveTuple t1 = new FiveTuple(0x01020304, 0x05060708, 1234, 443, 6);
        FiveTuple t2 = new FiveTuple(0x01020304, 0x05060708, 1234, 443, 6);
        FiveTuple t3 = new FiveTuple(0x01020304, 0x05060708, 1234, 80, 6);

        assertEquals(t1, t2);
        assertNotEquals(t1, t3);
        assertEquals(t1.hashCode(), t2.hashCode());
    }

    @Test
    public void testRuleManagerSubstringDomainBlocking() {
        RuleManager ruleManager = new RuleManager();
        ruleManager.blockDomain("facebook");

        // "www.facebook.com" contains "facebook", so it should block
        RuleManager.BlockReason reason = ruleManager.shouldBlock(0, 443, AppType.HTTPS, "www.facebook.com");
        assertNotNull(reason);
        assertEquals(RuleManager.BlockReason.Type.DOMAIN, reason.type);
        assertEquals("www.facebook.com", reason.detail);

        // "www.google.com" does not contain "facebook", so it should not block
        RuleManager.BlockReason reason2 = ruleManager.shouldBlock(0, 443, AppType.HTTPS, "www.google.com");
        assertNull(reason2);
    }

    @Test
    public void testSNIExtractor() throws Exception {
        byte[] payload = createTlsClientHello("www.youtube.com");
        
        assertTrue(SNIExtractor.isTLSClientHello(payload, 0, payload.length));
        
        String sni = SNIExtractor.extractSNI(payload, 0, payload.length);
        assertEquals("www.youtube.com", sni);
        assertEquals(AppType.YOUTUBE, AppType.sniToAppType(sni));
    }

    private byte[] createTlsClientHello(String sni) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        byte[] sniBytes = sni.getBytes(StandardCharsets.US_ASCII);
        
        ByteArrayOutputStream sniEntry = new ByteArrayOutputStream();
        sniEntry.write(0); // Hostname type
        sniEntry.write((sniBytes.length >> 8) & 0xFF);
        sniEntry.write(sniBytes.length & 0xFF);
        sniEntry.write(sniBytes);
        byte[] sniEntryData = sniEntry.toByteArray();
        
        ByteArrayOutputStream sniList = new ByteArrayOutputStream();
        sniList.write((sniEntryData.length >> 8) & 0xFF);
        sniList.write(sniEntryData.length & 0xFF);
        sniList.write(sniEntryData);
        byte[] sniListData = sniList.toByteArray();
        
        ByteArrayOutputStream sniExt = new ByteArrayOutputStream();
        sniExt.write(0); // SNI extension type (0x0000)
        sniExt.write(0);
        sniExt.write((sniListData.length >> 8) & 0xFF);
        sniExt.write(sniListData.length & 0xFF);
        sniExt.write(sniListData);
        byte[] sniExtData = sniExt.toByteArray();
        
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        extensions.write((sniExtData.length >> 8) & 0xFF);
        extensions.write(sniExtData.length & 0xFF);
        extensions.write(sniExtData);
        byte[] extensionsData = extensions.toByteArray();
        
        ByteArrayOutputStream clientHelloBody = new ByteArrayOutputStream();
        clientHelloBody.write(new byte[]{0x03, 0x03}); // Version TLS 1.2
        clientHelloBody.write(new byte[32]); // Client Random
        clientHelloBody.write(0); // Session ID length
        clientHelloBody.write(new byte[]{0x00, 0x02, 0x00, 0x2f}); // Cipher Suites
        clientHelloBody.write(new byte[]{0x01, 0x00}); // Compression methods
        clientHelloBody.write(extensionsData);
        byte[] bodyData = clientHelloBody.toByteArray();
        
        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        handshake.write(1); // Client Hello
        handshake.write((bodyData.length >> 16) & 0xFF);
        handshake.write((bodyData.length >> 8) & 0xFF);
        handshake.write(bodyData.length & 0xFF);
        handshake.write(bodyData);
        byte[] handshakeData = handshake.toByteArray();
        
        out.write(0x16); // Handshake record
        out.write(new byte[]{0x03, 0x01}); // TLS 1.0
        out.write((handshakeData.length >> 8) & 0xFF);
        out.write(handshakeData.length & 0xFF);
        out.write(handshakeData);
        
        return out.toByteArray();
    }
}
