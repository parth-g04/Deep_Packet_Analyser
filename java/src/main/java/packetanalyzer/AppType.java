package packetanalyzer;

public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    public static final int APP_COUNT;

    static {
        APP_COUNT = AppType.values().length;
    }

    public String toStringName() {
        return switch (this) {
            case UNKNOWN -> "Unknown";
            case HTTP -> "HTTP";
            case HTTPS -> "HTTPS";
            case DNS -> "DNS";
            case TLS -> "TLS";
            case QUIC -> "QUIC";
            case GOOGLE -> "Google";
            case FACEBOOK -> "Facebook";
            case YOUTUBE -> "YouTube";
            case TWITTER -> "Twitter/X";
            case INSTAGRAM -> "Instagram";
            case NETFLIX -> "Netflix";
            case AMAZON -> "Amazon";
            case MICROSOFT -> "Microsoft";
            case APPLE -> "Apple";
            case WHATSAPP -> "WhatsApp";
            case TELEGRAM -> "Telegram";
            case TIKTOK -> "TikTok";
            case SPOTIFY -> "Spotify";
            case ZOOM -> "Zoom";
            case DISCORD -> "Discord";
            case GITHUB -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
            default -> throw new MatchException(null, null);
        };
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }
        String lowerSni = sni.toLowerCase();
        
        if (matchesDomainOrSubdomain(lowerSni, "google.com") || 
            matchesDomainOrSubdomain(lowerSni, "gstatic.com") || 
            matchesDomainOrSubdomain(lowerSni, "googleapis.com") || 
            matchesDomainOrSubdomain(lowerSni, "ggpht.com") || 
            matchesDomainOrSubdomain(lowerSni, "gvt1.com") ||
            lowerSni.contains("google")) {
            return GOOGLE;
        }
        if (matchesDomainOrSubdomain(lowerSni, "youtube.com") || 
            matchesDomainOrSubdomain(lowerSni, "youtu.be") || 
            matchesDomainOrSubdomain(lowerSni, "ytimg.com") || 
            matchesDomainOrSubdomain(lowerSni, "yt3.ggpht.com") ||
            lowerSni.contains("youtube")) {
            return YOUTUBE;
        }
        if (matchesDomainOrSubdomain(lowerSni, "facebook.com") || 
            matchesDomainOrSubdomain(lowerSni, "fb.com") || 
            matchesDomainOrSubdomain(lowerSni, "fbcdn.net") || 
            matchesDomainOrSubdomain(lowerSni, "fbsbx.com") || 
            matchesDomainOrSubdomain(lowerSni, "meta.com") ||
            lowerSni.contains("facebook")) {
            return FACEBOOK;
        }
        if (matchesDomainOrSubdomain(lowerSni, "instagram.com") || 
            matchesDomainOrSubdomain(lowerSni, "cdninstagram.com") ||
            lowerSni.contains("instagram")) {
            return INSTAGRAM;
        }
        if (matchesDomainOrSubdomain(lowerSni, "whatsapp.com") || 
            matchesDomainOrSubdomain(lowerSni, "wa.me") ||
            lowerSni.contains("whatsapp")) {
            return WHATSAPP;
        }
        if (matchesDomainOrSubdomain(lowerSni, "twitter.com") || 
            matchesDomainOrSubdomain(lowerSni, "x.com") || 
            matchesDomainOrSubdomain(lowerSni, "t.co") || 
            matchesDomainOrSubdomain(lowerSni, "twimg.com") ||
            lowerSni.contains("twitter")) {
            return TWITTER;
        }
        if (matchesDomainOrSubdomain(lowerSni, "netflix.com") || 
            lowerSni.contains("nflxvideo") || 
            lowerSni.contains("nflximg") ||
            lowerSni.contains("netflix")) {
            return NETFLIX;
        }
        if (matchesDomainOrSubdomain(lowerSni, "amazon.com") || 
            matchesDomainOrSubdomain(lowerSni, "amazonaws.com") || 
            matchesDomainOrSubdomain(lowerSni, "cloudfront.net") ||
            lowerSni.contains("amazon")) {
            return AMAZON;
        }
        if (matchesDomainOrSubdomain(lowerSni, "microsoft.com") || 
            matchesDomainOrSubdomain(lowerSni, "msn.com") || 
            matchesDomainOrSubdomain(lowerSni, "office.com") || 
            matchesDomainOrSubdomain(lowerSni, "office.net") || 
            matchesDomainOrSubdomain(lowerSni, "azure.com") || 
            matchesDomainOrSubdomain(lowerSni, "live.com") || 
            matchesDomainOrSubdomain(lowerSni, "outlook.com") || 
            matchesDomainOrSubdomain(lowerSni, "bing.com") ||
            lowerSni.contains("microsoft") ||
            lowerSni.contains("windows")) {
            return MICROSOFT;
        }
        if (matchesDomainOrSubdomain(lowerSni, "apple.com") || 
            matchesDomainOrSubdomain(lowerSni, "icloud.com") || 
            matchesDomainOrSubdomain(lowerSni, "mzstatic.com") || 
            matchesDomainOrSubdomain(lowerSni, "itunes.com") ||
            lowerSni.contains("apple")) {
            return APPLE;
        }
        if (matchesDomainOrSubdomain(lowerSni, "telegram.org") || 
            matchesDomainOrSubdomain(lowerSni, "t.me") ||
            lowerSni.contains("telegram")) {
            return TELEGRAM;
        }
        if (matchesDomainOrSubdomain(lowerSni, "tiktok.com") || 
            matchesDomainOrSubdomain(lowerSni, "tiktokcdn.com") || 
            matchesDomainOrSubdomain(lowerSni, "musical.ly") || 
            matchesDomainOrSubdomain(lowerSni, "bytedance.com") ||
            lowerSni.contains("tiktok")) {
            return TIKTOK;
        }
        if (matchesDomainOrSubdomain(lowerSni, "spotify.com") || 
            matchesDomainOrSubdomain(lowerSni, "scdn.co") ||
            lowerSni.contains("spotify")) {
            return SPOTIFY;
        }
        if (matchesDomainOrSubdomain(lowerSni, "zoom.us") || 
            matchesDomainOrSubdomain(lowerSni, "zoom.com") ||
            lowerSni.contains("zoom")) {
            return ZOOM;
        }
        if (matchesDomainOrSubdomain(lowerSni, "discord.com") || 
            matchesDomainOrSubdomain(lowerSni, "discordapp.com") || 
            matchesDomainOrSubdomain(lowerSni, "discord.gg") ||
            lowerSni.contains("discord")) {
            return DISCORD;
        }
        if (matchesDomainOrSubdomain(lowerSni, "github.com") || 
            matchesDomainOrSubdomain(lowerSni, "githubusercontent.com") ||
            lowerSni.contains("github")) {
            return GITHUB;
        }
        if (matchesDomainOrSubdomain(lowerSni, "cloudflare.com") || 
            lowerSni.contains("cloudflare")) {
            return CLOUDFLARE;
        }
        return HTTPS;
    }

    private static boolean matchesDomainOrSubdomain(String sni, String domain) {
        return sni.equals(domain) || sni.endsWith("." + domain);
    }
}
