package packetanalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import packetanalyzer.AppType;
import packetanalyzer.FiveTuple;

public class RuleManager {
    private final Set<Integer> blockedIps = new HashSet<Integer>();
    private final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = new HashSet<AppType>();
    private final ReentrantReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<String>();
    private final List<String> domainPatterns = new ArrayList<String>();
    private final ReentrantReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<Integer>();
    private final ReentrantReadWriteLock portLock = new ReentrantReadWriteLock();
    private Thread watcherThread;
    private volatile boolean watcherRunning = false;

    public void blockIP(int ip) {
        this.ipLock.writeLock().lock();
        try {
            this.blockedIps.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + FiveTuple.formatIP(ip));
        }
        finally {
            this.ipLock.writeLock().unlock();
        }
    }

    public void blockIP(String ipStr) {
        this.blockIP(RuleManager.parseIP(ipStr));
    }

    public void unblockIP(int ip) {
        this.ipLock.writeLock().lock();
        try {
            this.blockedIps.remove(ip);
            System.out.println("[RuleManager] Unblocked IP: " + FiveTuple.formatIP(ip));
        }
        finally {
            this.ipLock.writeLock().unlock();
        }
    }

    public void unblockIP(String ipStr) {
        this.unblockIP(RuleManager.parseIP(ipStr));
    }

    public boolean isIPBlocked(int ip) {
        this.ipLock.readLock().lock();
        try {
            boolean bl = this.blockedIps.contains(ip);
            return bl;
        }
        finally {
            this.ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        this.ipLock.readLock().lock();
        try {
            ArrayList<String> result = new ArrayList<String>();
            for (int ip : this.blockedIps) {
                result.add(FiveTuple.formatIP(ip));
            }
            ArrayList<String> arrayList = result;
            return arrayList;
        }
        finally {
            this.ipLock.readLock().unlock();
        }
    }

    public void blockApp(AppType app) {
        this.appLock.writeLock().lock();
        try {
            this.blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + app.toStringName());
        }
        finally {
            this.appLock.writeLock().unlock();
        }
    }

    public void unblockApp(AppType app) {
        this.appLock.writeLock().lock();
        try {
            this.blockedApps.remove((Object)app);
            System.out.println("[RuleManager] Unblocked app: " + app.toStringName());
        }
        finally {
            this.appLock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        this.appLock.readLock().lock();
        try {
            boolean bl = this.blockedApps.contains((Object)app);
            return bl;
        }
        finally {
            this.appLock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        this.appLock.readLock().lock();
        try {
            ArrayList<AppType> arrayList = new ArrayList<AppType>(this.blockedApps);
            return arrayList;
        }
        finally {
            this.appLock.readLock().unlock();
        }
    }

    public void blockDomain(String domain) {
        this.domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                this.domainPatterns.add(domain);
            } else {
                this.blockedDomains.add(domain);
            }
            System.out.println("[RuleManager] Blocked domain: " + domain);
        }
        finally {
            this.domainLock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        this.domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                this.domainPatterns.remove(domain);
            } else {
                this.blockedDomains.remove(domain);
            }
            System.out.println("[RuleManager] Unblocked domain: " + domain);
        }
        finally {
            this.domainLock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        this.domainLock.readLock().lock();
        try {
            String lowerDomain = domain.toLowerCase();
            for (String blockedDomain : this.blockedDomains) {
                if (lowerDomain.contains(blockedDomain.toLowerCase())) {
                    return true;
                }
            }
            for (String pattern : this.domainPatterns) {
                String lowerPattern = pattern.toLowerCase();
                if (!RuleManager.domainMatchesPattern(lowerDomain, lowerPattern)) continue;
                return true;
            }
            return false;
        }
        finally {
            this.domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        this.domainLock.readLock().lock();
        try {
            ArrayList<String> result = new ArrayList<String>(this.blockedDomains);
            result.addAll(this.domainPatterns);
            ArrayList<String> arrayList = result;
            return arrayList;
        }
        finally {
            this.domainLock.readLock().unlock();
        }
    }

    public static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            if (domain.endsWith(suffix)) {
                return true;
            }
            if (domain.equals(pattern.substring(2))) {
                return true;
            }
        }
        return false;
    }

    public void blockPort(int port) {
        this.portLock.writeLock().lock();
        try {
            this.blockedPorts.add(port);
            System.out.println("[RuleManager] Blocked port: " + port);
        }
        finally {
            this.portLock.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        this.portLock.writeLock().lock();
        try {
            this.blockedPorts.remove(port);
            System.out.println("[RuleManager] Unblocked port: " + port);
        }
        finally {
            this.portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        this.portLock.readLock().lock();
        try {
            boolean bl = this.blockedPorts.contains(port);
            return bl;
        }
        finally {
            this.portLock.readLock().unlock();
        }
    }

    public BlockReason shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (this.isIPBlocked(srcIp)) {
            return new BlockReason(BlockReason.Type.IP, FiveTuple.formatIP(srcIp));
        }
        if (this.isPortBlocked(dstPort)) {
            return new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort));
        }
        if (this.isAppBlocked(app)) {
            return new BlockReason(BlockReason.Type.APP, app.toStringName());
        }
        if (domain != null && !domain.isEmpty() && this.isDomainBlocked(domain)) {
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        }
        return null;
    }

    public boolean saveRules(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("[BLOCKED_IPS]");
            for (String ip : this.getBlockedIPs()) {
                writer.println(ip);
            }
            writer.println("\n[BLOCKED_APPS]");
            for (AppType app : this.getBlockedApps()) {
                writer.println(app.toStringName());
            }
            writer.println("\n[BLOCKED_DOMAINS]");
            for (String domain : this.getBlockedDomains()) {
                writer.println(domain);
            }
            writer.println("\n[BLOCKED_PORTS]");
            this.portLock.readLock().lock();
            try {
                for (int port : this.blockedPorts) {
                    writer.println(port);
                }
            }
            finally {
                this.portLock.readLock().unlock();
            }
            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        }
        catch (IOException e) {
            System.err.println("Error saving rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentSection = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[") && line.endsWith("]")) {
                    currentSection = line;
                    continue;
                }
                switch (currentSection) {
                    case "[BLOCKED_IPS]": {
                        this.blockIP(line);
                        break;
                    }
                    case "[BLOCKED_APPS]": {
                        for (AppType app : AppType.values()) {
                            if (app.toStringName().equalsIgnoreCase(line)) {
                                this.blockApp(app);
                                break;
                            }
                        }
                        break;
                    }
                    case "[BLOCKED_DOMAINS]": {
                        this.blockDomain(line);
                        break;
                    }
                    case "[BLOCKED_PORTS]": {
                        try {
                            this.blockPort(Integer.parseInt(line));
                        } catch (NumberFormatException e) {
                            System.err.println("Warning: Invalid port in rules file: " + line);
                        }
                        break;
                    }
                }
            }
            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        }
        catch (IOException e) {
            System.err.println("Error loading rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        this.ipLock.writeLock().lock();
        try {
            this.blockedIps.clear();
        }
        finally {
            this.ipLock.writeLock().unlock();
        }
        this.appLock.writeLock().lock();
        try {
            this.blockedApps.clear();
        }
        finally {
            this.appLock.writeLock().unlock();
        }
        this.domainLock.writeLock().lock();
        try {
            this.blockedDomains.clear();
            this.domainPatterns.clear();
        }
        finally {
            this.domainLock.writeLock().unlock();
        }
        this.portLock.writeLock().lock();
        try {
            this.blockedPorts.clear();
        }
        finally {
            this.portLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        RuleStats stats = new RuleStats();
        this.ipLock.readLock().lock();
        try {
            stats.blockedIps = this.blockedIps.size();
        }
        finally {
            this.ipLock.readLock().unlock();
        }
        this.appLock.readLock().lock();
        try {
            stats.blockedApps = this.blockedApps.size();
        }
        finally {
            this.appLock.readLock().unlock();
        }
        this.domainLock.readLock().lock();
        try {
            stats.blockedDomains = this.blockedDomains.size() + this.domainPatterns.size();
        }
        finally {
            this.domainLock.readLock().unlock();
        }
        this.portLock.readLock().lock();
        try {
            stats.blockedPorts = this.blockedPorts.size();
        }
        finally {
            this.portLock.readLock().unlock();
        }
        return stats;
    }

    public boolean reloadRules(String filename) {
        HashSet<Integer> tempIps = new HashSet<Integer>();
        HashSet<AppType> tempApps = new HashSet<AppType>();
        HashSet<String> tempDomains = new HashSet<String>();
        ArrayList<String> tempPatterns = new ArrayList<String>();
        HashSet<Integer> tempPorts = new HashSet<Integer>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentSection = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (line.startsWith("[") && line.endsWith("]")) {
                    currentSection = line;
                    continue;
                }
                switch (currentSection) {
                    case "[BLOCKED_IPS]": {
                        tempIps.add(RuleManager.parseIP(line));
                        break;
                    }
                    case "[BLOCKED_APPS]": {
                        for (AppType app : AppType.values()) {
                            if (app.toStringName().equalsIgnoreCase(line)) {
                                tempApps.add(app);
                                break;
                            }
                        }
                        break;
                    }
                    case "[BLOCKED_DOMAINS]": {
                        if (line.contains("*")) {
                            tempPatterns.add(line);
                        } else {
                            tempDomains.add(line);
                        }
                        break;
                    }
                    case "[BLOCKED_PORTS]": {
                        try {
                            tempPorts.add(Integer.parseInt(line));
                        } catch (NumberFormatException e) {
                            System.err.println("Warning: Invalid port in reload rules: " + line);
                        }
                        break;
                    }
                }
            }
        }
        catch (IOException e) {
            System.err.println("[RuleManager] Error loading rules: " + e.getMessage());
            return false;
        }
        this.ipLock.writeLock().lock();
        try {
            this.blockedIps.clear();
            this.blockedIps.addAll(tempIps);
        }
        finally {
            this.ipLock.writeLock().unlock();
        }
        this.appLock.writeLock().lock();
        try {
            this.blockedApps.clear();
            this.blockedApps.addAll(tempApps);
        }
        finally {
            this.appLock.writeLock().unlock();
        }
        this.domainLock.writeLock().lock();
        try {
            this.blockedDomains.clear();
            this.blockedDomains.addAll(tempDomains);
            this.domainPatterns.clear();
            this.domainPatterns.addAll(tempPatterns);
        }
        finally {
            this.domainLock.writeLock().unlock();
        }
        this.portLock.writeLock().lock();
        try {
            this.blockedPorts.clear();
            this.blockedPorts.addAll(tempPorts);
        }
        finally {
            this.portLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Rules dynamically reloaded from: " + filename + " (Total Rules: " + (tempIps.size() + tempApps.size() + tempDomains.size() + tempPatterns.size() + tempPorts.size()) + ")");
        return true;
    }

    public void startWatcher(String filepath) {
        if (this.watcherRunning) {
            return;
        }
        this.watcherRunning = true;
        File file = new File(filepath);
        if (!file.exists()) {
            try {
                File parent = file.getAbsoluteFile().getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                file.createNewFile();
            }
            catch (IOException e) {
                System.err.println("[RuleManager] Could not create rules file: " + e.getMessage());
                return;
            }
        }
        this.watcherThread = new Thread(() -> {
            try {
                Path parentPath = file.getAbsoluteFile().getParentFile().toPath();
                WatchService watcher = FileSystems.getDefault().newWatchService();
                parentPath.register(watcher, StandardWatchEventKinds.ENTRY_MODIFY);
                System.out.println("[RuleManager] Started watching rules file: " + file.getAbsolutePath());
                while (this.watcherRunning) {
                    WatchKey key = watcher.poll(500L, TimeUnit.MILLISECONDS);
                    if (key == null) continue;
                    for (WatchEvent<?> event : key.pollEvents()) {
                        WatchEvent<?> ev;
                        Path changedFilename;
                        WatchEvent.Kind<?> kind = event.kind();
                        if (kind == StandardWatchEventKinds.OVERFLOW || !(changedFilename = (Path)(ev = event).context()).toString().equals(file.getName())) continue;
                        Thread.sleep(100L);
                        this.reloadRules(file.getAbsolutePath());
                    }
                    boolean valid = key.reset();
                    if (valid) {
                        continue;
                    }
                    break;
                }
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            catch (Exception e) {
                System.err.println("[RuleManager] Watcher thread error: " + e.getMessage());
            }
        }, "RuleWatcherThread");
        this.watcherThread.setDaemon(true);
        this.watcherThread.start();
    }

    public void stopWatcher() {
        this.watcherRunning = false;
        if (this.watcherThread != null) {
            this.watcherThread.interrupt();
        }
    }

    private static int parseIP(String ipStr) {
        String[] parts = ipStr.split("\\.");
        int result = 0;
        result |= Integer.parseInt(parts[0]) & 0xFF;
        result |= (Integer.parseInt(parts[1]) & 0xFF) << 8;
        result |= (Integer.parseInt(parts[2]) & 0xFF) << 16;
        return result |= (Integer.parseInt(parts[3]) & 0xFF) << 24;
    }

    public static class BlockReason {
        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }

        public static enum Type {
            IP,
            APP,
            DOMAIN,
            PORT;

        }
    }

    public static class RuleStats {
        public int blockedIps;
        public int blockedApps;
        public int blockedDomains;
        public int blockedPorts;
    }
}
