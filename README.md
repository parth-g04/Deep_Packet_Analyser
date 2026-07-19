# DPI Engine - Deep Packet Inspection System (Java)

A high-performance, multi-threaded Deep Packet Inspection (DPI) Engine built from scratch in core Java (no high-level wrapper libraries). By manually decoding Layer 2 (Ethernet), Layer 3 (IPv4), and Layer 4 (TCP/UDP) headers using Java's `ByteBuffer`, the engine extracts plaintext SNI fields from TLS Client Hello handshakes to classify and block encrypted traffic (e.g. YouTube, Facebook) in real-time. Features sharded load balancing, thread-safe rule managers, and consistent packet-flow hashing.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Performance Benchmark & Concurrency Analysis](#12-performance-benchmark--concurrency-analysis)
13. [Extending the Project](#13-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers" of the OSI model:

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │  ← Look inside payload
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │  ← Source/Dest Ports
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │  ← Source/Dest IPs
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│  ← Source/Dest MACs
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) or UDP (17) | Transport Layer Protocol |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection.
- If we block one packet of a connection, we should block all of them.
- This is how we "track" conversations between computers.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message.
2. This message includes the domain name in **plaintext** (not encrypted yet!).
3. The server uses this to know which certificate to send.

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first handshake packet.

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Three Run Configurations

This Java implementation of the DPI Engine consists of:
1. **Base Analyzer (`Main.java`)**: Reads a PCAP file and prints detailed summaries of the headers of each packet.
2. **Simple DPI Engine (`MainSimple.java`)**: A single-threaded DPI engine that parses packets, extracts Host/SNI, matches against rules, and writes a filtered PCAP file.
3. **Multi-threaded DPI Engine (`MainDpi.java`)**: High-performance architecture using worker thread pools, load balancers, and shared statistics.

---

## 4. File Structure

```
packet_analyzer/
├── java/
│   ├── compile_and_run.bat            # Windows batch script helper to compile and run
│   ├── src/
│   │   └── main/java/packetanalyzer/
│   │       ├── AppType.java           # App types enum (YouTube, Facebook, etc.) and signatures
│   │       ├── Connection.java        # Stateful connection properties
│   │       ├── ConnectionState.java   # Stateful connection tracker states
│   │       ├── ConnectionTracker.java # Manages active connections per worker thread
│   │       ├── DpiEngine.java         # Orchestrator for multi-threaded system
│   │       ├── DpiStats.java          # Thread-safe stats counters
│   │       ├── FastPathProcessor.java # DPI worker thread (deep parsing and rule matching)
│   │       ├── FiveTuple.java         # Connection identification structure
│   │       ├── FPManager.java         # Manages and aggregates stats from FastPathProcessors
│   │       ├── GlobalConnectionTable.java # Central statistics table
│   │       ├── LBManager.java         # Manages LoadBalancer threads
│   │       ├── LoadBalancer.java      # Distributes incoming packets using consistent hashing
│   │       ├── Main.java              # Base packet analyzer entry point
│   │       ├── MainDpi.java           # Multi-threaded DPI engine entry point
│   │       ├── MainSimple.java        # Simple single-threaded DPI engine entry point
│   │       ├── PacketAction.java      # Decisions (FORWARD, DROP)
│   │       ├── PacketJob.java         # Data wrapper passed via concurrent queues
│   │       ├── PacketParser.java      # Protocol parsing (Ethernet, IPv4, TCP, UDP)
│   │       ├── ParsedPacket.java      # Structured representation of packet fields
│   │       ├── PcapHeaders.java       # Struct-equivalent classes for PCAP headers
│   │       ├── PcapReader.java        # Reads binary PCAP files
│   │       ├── PcapWriter.java        # Writes binary PCAP files
│   │       ├── RawPacket.java         # Holds raw packet byte buffer and header
│   │       ├── RuleManager.java       # Dynamic rules manager (IP, App, Domain, Port)
│   │       └── SNIExtractor.java      # Extracts SNI (TLS) and Host (HTTP) from payload
│   │
│   └── target/classes/packetanalyzer/ # Compiled Java .class files
│
├── generate_test_pcap.py              # Python script to generate sample traffic PCAP
├── test_dpi.pcap                      # Sample capture file
└── README.md                          # This documentation file
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `MainSimple.java`:

### Step 1: Read PCAP File

```java
try (PcapReader reader = new PcapReader()) {
    reader.open("capture.pcap");
    // Reads 24-byte global header and verifies link type
}
```

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```java
RawPacket raw = new RawPacket();
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

### Step 3: Parse Protocol Headers

```java
ParsedPacket parsed = new ParsedPacket();
PacketParser.parse(raw, parsed);
```

**Header offsets in `PacketParser.java`:**
```
raw.data bytes:
[0-13]   Ethernet Header (14 bytes)
[14-33]  IP Header (20 bytes)
[34-53]  TCP Header (20 bytes)
[54+]    Payload
```

**Parsing the Ethernet Header (14 bytes):**
```java
// Extracts MAC addresses and EtherType (e.g. 0x0800 = IPv4)
parsed.destMac = formatMac(raw.data, 0);
parsed.srcMac = formatMac(raw.data, 6);
parsed.etherType = (buf.getShort(12) & 0xFFFF);
```

**Parsing the IP Header (20+ bytes):**
```java
// Extracts IPs, TTL, and protocol (6=TCP, 17=UDP)
parsed.ipVersion = (raw.data[14] >> 4) & 0x0F;
parsed.protocol = raw.data[23] & 0xFF;
parsed.srcIp = formatIP(raw.data, 26);
parsed.destIp = formatIP(raw.data, 30);
```

**Parsing the TCP Header (20+ bytes):**
```java
// Extracts ports, flags, sequence/ack numbers
parsed.srcPort = buf.getShort(34) & 0xFFFF;
parsed.destPort = buf.getShort(36) & 0xFFFF;
parsed.seqNumber = buf.getInt(38);
parsed.ackNumber = buf.getInt(42);
parsed.tcpFlags = raw.data[47] & 0xFF;
```

### Step 4: Create Five-Tuple and Look Up Flow

```java
int srcIp = SimpleBlockingRules.parseIP(parsed.srcIp);
int dstIp = SimpleBlockingRules.parseIP(parsed.destIp);
FiveTuple fiveTuple = new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);

Flow flow = flows.computeIfAbsent(fiveTuple, k -> {
    Flow f = new Flow();
    f.tuple = k;
    return f;
});
```

- If this 5-tuple exists in the `flows` map, we get the existing flow.
- If not, a new flow is created.
- All packets with the same 5-tuple share the same flow.

### Step 5: Extract SNI (Deep Packet Inspection)

```java
// For HTTPS traffic (port 443)
if (parsed.destPort == 443 && parsed.payloadLength > 5) {
    String sni = SNIExtractor.extractSNI(raw.data, parsed.payloadOffset, parsed.payloadLength);
    if (sni != null) {
        flow.sni = sni;
        flow.appType = AppType.sniToAppType(sni);
    }
}
```

- We inspect the payload bytes to search for application names.
- We extract the server name (SNI) from the TLS Client Hello.
- If found, we classify the application (e.g. YouTube, Facebook).

### Step 6: Evaluate Rules

```java
flow.blocked = rules.isBlocked(fiveTuple.srcIp, flow.appType, flow.sni);
```

### Step 7: Forward or Drop

```java
if (flow.blocked) {
    dropped++;
    continue; // DROP: skip writing to output
}
forwarded++;
writer.writePacket(raw.header, raw.data); // FORWARD: write packet
```

### Step 8: Generate Report

After processing all packets:
```java
for (Flow flow : flows.values()) {
    appStats.put(flow.appType, appStats.getOrDefault(flow.appType, 0L) + 1L);
}
// Outputs counts and percentages for each app
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`MainDpi.java` / `DpiEngine.java`) scales processing across threads:

### Thread Architecture

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
               ┌──────────────┴──────────────┐
               │    Consistent Hashing       │ (hash(5-tuple) % NumLBs)
               ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │ (Load Balancers)
    └────────┬────────┘           └────────┬────────┘
             │                             │
       ┌──────┴──────┐               ┌──────┴──────┐
       ▼             ▼               ▼             ▼
 ┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
 │FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│ (Fast Path Workers)
 └─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
       │            │              │            │
       └────────────┴──────────────┴────────────┘
                           │ (DPI Output Callback)
                           ▼
               ┌───────────────────────┐
               │  Output Writer Thread │ (writes to PCAP)
               └───────────────────────┘
```

### Step 1: Reader Thread
Reads packets from the PCAP file, parses the basic 5-tuple, and dispatches it to a Load Balancer thread:
```java
int lbIndex = Math.abs(tuple.hashCode()) % numLoadBalancers;
lbManager.getLB(lbIndex).enqueue(job);
```

### Step 2: LoadBalancer Thread
Runs a loop, takes packet jobs, hashes the 5-tuple, and forwards them to a FastPath queue:
```java
int fpIndex = Math.abs(job.tuple.hashCode()) % fpsPerLb;
FastPathProcessor fp = fpManager.getFP(lbId * fpsPerLb + fpIndex);
fp.enqueue(job);
```

### Step 3: FastPathProcessor Thread
Performs protocol parsing, payload inspection, and rule evaluation:
```java
public void run() {
    while (this.running) {
        try {
            PacketJob job = this.inputQueue.poll(100L, TimeUnit.MILLISECONDS);
            if (job == null) continue;

            Connection conn = this.connTracker.getOrCreateConnection(job.tuple);
            inspectPayload(job, conn);

            PacketAction action = this.checkRules(job, conn);
            if (this.outputCallback != null) {
                this.outputCallback.handleOutput(job, action);
            }
        } catch (InterruptedException e) {
            break;
        }
    }
}
```

### Step 4: Output Callback
Writes the non-dropped packets to the output PCAP file:
```java
public void handleOutput(PacketJob job, PacketAction action) {
    if (action != PacketAction.DROP) {
        try {
            this.writer.writePacket(job.header, job.data);
        } catch (IOException e) {
            System.err.println("Error writing packet: " + e.getMessage());
        }
    }
}
```

### Thread-Safe Queue
Rather than manual mutexes, this Java version utilizes the standard concurrent library class `LinkedBlockingQueue` for thread-safe FIFO queue operations:
```java
private final LinkedBlockingQueue<PacketJob> inputQueue = new LinkedBlockingQueue<>(10000);
```

---

## 7. Deep Dive: Each Component

### PcapHeaders.java

Encapsulates binary PCAP global and packet header definitions:

```java
public static class PcapGlobalHeader {
    public int magicNumber;   // 0xa1b2c3d4 identifies PCAP
    public short versionMajor; // Usually 2
    public short versionMinor; // Usually 4
    public int thiszone;       // GMT to local correction
    public int sigfigs;        // Accuracy of timestamps
    public int snaplen;        // Max length of captured packets
    public int network;        // Data link type (1 = Ethernet)
}

public static class PcapPacketHeader {
    public int tsSec;         // Timestamp seconds
    public int tsUsec;        // Timestamp microseconds
    public int inclLen;       // Number of octets of packet saved in file
    public int origLen;       // Actual length of packet on wire
}
```

### PacketParser.java

Handles Layer 2, 3, and 4 protocol headers parsing. We use `ByteBuffer` to easily wrap network bytes and extract values:

```java
public static boolean parse(RawPacket raw, ParsedPacket parsed) {
    if (raw.data.length < 14) return false;
    
    // Parse Ethernet Header
    parsed.etherType = ((raw.data[12] & 0xFF) << 8) | (raw.data[13] & 0xFF);
    
    if (parsed.etherType == 0x0800) { // IPv4
        parsed.hasIp = true;
        parsed.ipVersion = 4;
        parsed.protocol = raw.data[23] & 0xFF;
        parsed.srcIp = formatIP(raw.data, 26);
        parsed.destIp = formatIP(raw.data, 30);
        
        int ipHeaderLen = (raw.data[14] & 0x0F) * 4;
        int transportOffset = 14 + ipHeaderLen;
        parsed.payloadOffset = transportOffset;
        
        if (parsed.protocol == 6) { // TCP
            parsed.hasTcp = true;
            parsed.srcPort = getShortBE(raw.data, transportOffset);
            parsed.destPort = getShortBE(raw.data, transportOffset + 2);
            int tcpHeaderLen = ((raw.data[transportOffset + 12] >> 4) & 0x0F) * 4;
            parsed.payloadOffset = transportOffset + tcpHeaderLen;
            parsed.payloadLength = raw.data.length - parsed.payloadOffset;
        } else if (parsed.protocol == 17) { // UDP
            parsed.hasUdp = true;
            parsed.srcPort = getShortBE(raw.data, transportOffset);
            parsed.destPort = getShortBE(raw.data, transportOffset + 2);
            parsed.payloadOffset = transportOffset + 8;
            parsed.payloadLength = raw.data.length - parsed.payloadOffset;
        }
    }
    return true;
}
```

### SNIExtractor.java

Extracts Server Name Indication (SNI) string from TLS handshakes or Host header from HTTP payloads.

```java
public static String extractSNI(byte[] data, int offset, int length) {
    if (length < 5) return null;
    
    // 1. Verify TLS Handshake Record
    if ((data[offset] & 0xFF) != 0x16) return null; // 0x16 = Handshake
    
    // 2. Verify Client Hello Handshake Type
    if ((data[offset + 5] & 0xFF) != 0x01) return null; // 0x01 = Client Hello
    
    // 3. Skip to Extensions List
    int curr = offset + 43; // Handshake header + Random + Version
    int sessionLen = data[curr] & 0xFF;
    curr += 1 + sessionLen;
    
    int cipherLen = ((data[curr] & 0xFF) << 8) | (data[curr + 1] & 0xFF);
    curr += 2 + cipherLen;
    
    int compLen = data[curr] & 0xFF;
    curr += 1 + compLen;
    
    if (curr + 2 > offset + length) return null;
    int extListLen = ((data[curr] & 0xFF) << 8) | (data[curr + 1] & 0xFF);
    curr += 2;
    
    // 4. Parse Extensions
    int extEnd = curr + extListLen;
    while (curr + 4 <= extEnd) {
        int extType = ((data[curr] & 0xFF) << 8) | (data[curr + 1] & 0xFF);
        int extLen = ((data[curr + 2] & 0xFF) << 8) | (data[curr + 3] & 0xFF);
        curr += 4;
        
        if (extType == 0x0000) { // SNI
            int serverNameListLen = ((data[curr] & 0xFF) << 8) | (data[curr + 1] & 0xFF);
            int nameType = data[curr + 2] & 0xFF; // 0 = Hostname
            int nameLen = ((data[curr + 3] & 0xFF) << 8) | (data[curr + 4] & 0xFF);
            if (nameType == 0 && curr + 5 + nameLen <= extEnd) {
                return new String(data, curr + 5, nameLen, StandardCharsets.US_ASCII);
            }
        }
        curr += extLen;
    }
    return null;
}
```

### FiveTuple.java

Represents the unique identity of a stateful flow. Overrides `equals` and `hashCode` to allow usage as keys in hash-based maps:

```java
public class FiveTuple {
    public int srcIp;
    public int dstIp;
    public int srcPort;
    public int dstPort;
    public int protocol;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple other = (FiveTuple) o;
        return this.srcIp == other.srcIp &&
               this.dstIp == other.dstIp &&
               this.srcPort == other.srcPort &&
               this.dstPort == other.dstPort &&
               this.protocol == other.protocol;
    }

    @Override
    public int hashCode() {
        int h = 0;
        h ^= this.srcIp + -1640531527 + (h << 6) + (h >> 2);
        h ^= this.dstIp + -1640531527 + (h << 6) + (h >> 2);
        h ^= (this.srcPort & 0xFFFF) + -1640531527 + (h << 6) + (h >> 2);
        h ^= (this.dstPort & 0xFFFF) + -1640531527 + (h << 6) + (h >> 2);
        h ^= (this.protocol & 0xFF) + -1640531527 + (h << 6) + (h >> 2);
        return h;
    }
}
```

### RuleManager.java

Thread-safe manager for evaluating rules. It uses read-write locks (`ReentrantReadWriteLock`) to ensure high-performance concurrent evaluation and dynamic rule updates:

```java
public class RuleManager {
    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<AppType> blockedApps = new HashSet<>();
    private final Set<String> blockedDomains = new HashSet<>();
    private final Set<Integer> blockedPorts = new HashSet<>();
    
    private final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();
    // Locks for app, domain, port lists...
    
    public BlockReason evaluate(FiveTuple tuple, AppType app, String domain) {
        if (this.isIpBlocked(tuple.srcIp)) {
            return new BlockReason(BlockReason.Type.IP, formatIP(tuple.srcIp));
        }
        if (this.isPortBlocked(tuple.dstPort)) {
            return new BlockReason(BlockReason.Type.PORT, String.valueOf(tuple.dstPort));
        }
        if (this.isAppBlocked(app)) {
            return new BlockReason(BlockReason.Type.APP, app.toStringName());
        }
        if (domain != null && !domain.isEmpty() && this.isDomainBlocked(domain)) {
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        }
        return null;
    }
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
 Browser                                       Server
   │                                             │
   │ ──── Client Hello ─────────────────────────►│ (Plain Text SNI: www.youtube.com)
   │                                             │
   │ ◄─── Server Hello & Certificate ─────────── │
   │                                             │
   │ ◄═══ Encrypted Session established ═══════► │
```

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake Record)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `facebook` | Any SNI containing "facebook" |
| Port | `80` | All HTTP traffic |

### Stateful Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow state as BLOCKED
                           │
                           ▼ DROP this packet
  Packet 5 (Data)          → Flow state is BLOCKED → DROP
  Packet 6 (Data)          → Flow state is BLOCKED → DROP
  ...all subsequent packets of this 5-tuple → DROP
```

---

## 10. Building and Running

### Prerequisites

- **Java Development Kit (JDK)** version 17 or higher.

---

### Running on Windows

A compilation and execution helper batch script `compile_and_run.bat` is located in the `java` directory.

```powershell
cd java

# 1. Base Analyzer
.\compile_and_run.bat run ..\test_dpi.pcap 10

# 2. Simple Single-threaded DPI Engine
.\compile_and_run.bat run-simple ..\test_dpi.pcap ..\output_simple.pcap --block-app YouTube

# 3. Multi-threaded DPI Engine
.\compile_and_run.bat run-multi ..\test_dpi.pcap ..\output_java.pcap --block-app YouTube --block-domain facebook
```

---

### Running on Linux / macOS

```bash
cd java

# 1. Compile
mkdir -p target/classes
javac -d target/classes src/main/java/packetanalyzer/*.java

# 2. Run Base Analyzer
java -cp target/classes packetanalyzer.Main ../test_dpi.pcap 10

# 3. Run Simple DPI Engine
java -cp target/classes packetanalyzer.MainSimple ../test_dpi.pcap ../output_simple.pcap --block-app YouTube

# 4. Run Multi-threaded DPI Engine
java -cp target/classes packetanalyzer.MainDpi ../test_dpi.pcap ../output_java.pcap --block-app YouTube --block-domain facebook
```

---

## 11. Understanding the Output

Running the multi-threaded Java DPI Engine outputs detailed statistics and classification summaries:

```
Compiling Java files...
Compilation successful.
Running MainDpi...
[FPManager] Created 4 fast path processors
[LBManager] Created 2 load balancers, 2 FPs each
[RuleManager] Blocked app: YouTube
[RuleManager] Blocked domain: facebook
Opened PCAP file: ..\test_dpi.pcap
  Version: 2.4
  Snaplen: 65535 bytes
  Link type: 1 (Ethernet)
[FP0] Started
[FP1] Started
[FP2] Started
[FP3] Started
[LB0] Started (serving FP0-FP1)
[LB1] Started (serving FP2-FP3)
[Reader] Processing packets...
[FP0] BLOCKED packet: App YouTube
[FP0] BLOCKED packet: Domain www.facebook.com
[Reader] Done reading 77 packets
[LB0] Stopped
[LB1] Stopped
[FP0] Stopped (processed 53 packets)
[FP1] Stopped (processed 0 packets)
[FP2] Stopped (processed 0 packets)
[FP3] Stopped (processed 24 packets)

+--------------------------------------------------------------+
|                      PROCESSING REPORT                        |
+--------------------------------------------------------------+
| Total Packets:                77                             |
| Total Bytes:                5738                             |
| TCP Packets:                  77                             |
| UDP Packets:                   0                             |
+--------------------------------------------------------------+
| Forwarded:                    75                             |
| Dropped:                       2                             |
+--------------------------------------------------------------+
| THREAD STATISTICS                                             |
|   LB0 dispatched:             53                             |
|   LB1 dispatched:             24                             |
|   FP0 processed:              53                             |
|   FP1 processed:               0                             |
|   FP2 processed:               0                             |
|   FP3 processed:              24                             |
+--------------------------------------------------------------+
|                   APPLICATION BREAKDOWN                       |
+--------------------------------------------------------------+
| Unknown               25  32.5% ######                       |
| HTTPS                  2   2.6%                              |
| Amazon                 1   1.3%                              |
| YouTube                1   1.3%                              |
| Cloudflare             1   1.3%                              |
| Microsoft              1   1.3%                              |
| TikTok                 1   1.3%                              |
| Zoom                   1   1.3%                              |
| GitHub                 1   1.3%                              |
| Spotify                1   1.3%                              |
| Instagram              1   1.3%                              |
| Twitter/X              1   1.3%                              |
| Netflix                1   1.3%                              |
| Telegram               1   1.3%                              |
| Discord                1   1.3%                              |
| Apple                  1   1.3%                              |
| Facebook               1   1.3%                              |
| Google                 1   1.3%                              |
+--------------------------------------------------------------+

[Detected Domains/SNIs]
  - discord.com -> Discord
  - example.com -> HTTPS
  - github.com -> GitHub
  - httpbin.org -> HTTPS
  - open.spotify.com -> Spotify
  - twitter.com -> Twitter/X
  - web.telegram.org -> Telegram
  - www.amazon.com -> Amazon
  - www.apple.com -> Apple
  - www.cloudflare.com -> Cloudflare
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - www.instagram.com -> Instagram
  - www.microsoft.com -> Microsoft
  - www.netflix.com -> Netflix
  - www.tiktok.com -> TikTok
  - www.youtube.com -> YouTube
  - zoom.us -> Zoom

Processing complete!
Output written to: ..\output_java.pcap
```

---

## 12. Performance Benchmark & Concurrency Analysis

To evaluate the throughput of our DPI system under load, we ran a performance benchmark processing **42,240 packets** containing 10,000 distinct flows (simulating TCP TLS Client Hello connections and UDP DNS queries). We compared our single-threaded engine (`MainSimple`) against our multi-threaded, load-balanced engine (`MainDpi` utilizing 4 fast-path workers and 2 load balancers).

### Benchmark Results
| Metric | Single-threaded (`MainSimple`) | Multi-threaded (`MainDpi`) |
| :--- | :--- | :--- |
| **Total Packets** | 42,240 | 42,240 |
| **Execution Time** | 683.96 ms | 1,241.12 ms |
| **Throughput** | **61,758.03 packets/sec** | **34,033.69 packets/sec** |
| **Relative Performance** | **1.0x** (Baseline) | **0.55x** |

### Concurrency Deep-Dive: Understanding the 0.55x Bottleneck

At first glance, one might expect a multi-threaded engine to run faster. However, in low-level systems programming, parallelizing extremely lightweight tasks introduces classic synchronization and scheduling bottlenecks:

1. **High Synchronization-to-Work Ratio**:
   Byte-level header decoding (IP/TCP) and SNI extraction take **less than 1 microsecond** of CPU time per packet. In contrast, transferring a `PacketJob` across a `LinkedBlockingQueue` involves reentrant lock acquisition, condition variable signaling, and CPU cache line invalidations, which takes **5 to 10 microseconds** per queue.
2. **Multi-Stage Queue Contention**:
   The multi-threaded engine transfers each packet across **three queue boundaries**:
   `Reader (Main Thread) ➔ [Queue] ➔ Load Balancer Thread ➔ [Queue] ➔ Fast Path Worker Thread ➔ [Queue] ➔ Output Writer Thread`
   This triple-queuing structure multiplies lock contention, turning thread synchronization into the primary bottleneck.
3. **Single File I/O Serialization**:
   Because both engines read from a single PCAP input file and write to a single PCAP output file, the disk I/O serialized at the beginning and end of the pipeline limits overall speedup.
4. **When Multi-threading Wins**:
   In production setups, multi-threaded pipelines out-perform single-threaded ones under two conditions:
   - **Expensive Inspection Rules**: If Layer-7 inspection involves regex searching, payload decompression, or intrusion detection signatures (which are highly CPU-intensive and take milliseconds), the queue overhead is fully amortized.
   - **Hardware NIC Queues**: If packets are read from sharded hardware receive queues (RSS) and processed entirely in memory without writing to a single serialized file.

---

## 13. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**:
   Add a signature to `AppType` enum class for new apps:
   ```java
   // In AppType.java
   TWITCH("Twitch");
   
   // In AppType.sniToAppType:
   if (sni.contains("twitch")) {
       return AppType.TWITCH;
   }
   ```

2. **Add Bandwidth Throttling**:
   Instead of dropping the packet immediately, we can sleep the FastPath thread briefly to throttle connection speeds:
   ```java
   if (action == PacketAction.THROTTLE) {
       Thread.sleep(10);
   }
   ```

3. **Dynamic Rule Reloading using Java WatchService**:
   Listen to file modifications on rules files and dynamically reload them asynchronously:
   ```java
   WatchService watchService = FileSystems.getDefault().newWatchService();
   path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
   ```

---

## Summary

This Java DPI engine demonstrates:
1. **Network Protocol Parsing** - Parsing raw network frames.
2. **Deep Packet Inspection** - Reconstructing TLS Client Hello SNI.
3. **Stateful Connection Tracking** - Managing session tables concurrently.
4. **Load Balancer Hashing** - Consistent flow hashing to workers.
5. **Thread Concurrency** - Efficient concurrent pipelines using `LinkedBlockingQueue` and `ReentrantReadWriteLock`.
