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
        if (lowerSni.contains("google") || lowerSni.contains("gstatic") || lowerSni.contains("googleapis") || lowerSni.contains("ggpht") || lowerSni.contains("gvt1")) {
            return GOOGLE;
        }
        if (lowerSni.contains("youtube") || lowerSni.contains("ytimg") || lowerSni.contains("youtu.be") || lowerSni.contains("yt3.ggpht")) {
            return YOUTUBE;
        }
        if (lowerSni.contains("facebook") || lowerSni.contains("fbcdn") || lowerSni.contains("fb.com") || lowerSni.contains("fbsbx") || lowerSni.contains("meta.com")) {
            return FACEBOOK;
        }
        if (lowerSni.contains("instagram") || lowerSni.contains("cdninstagram")) {
            return INSTAGRAM;
        }
        if (lowerSni.contains("whatsapp") || lowerSni.contains("wa.me")) {
            return WHATSAPP;
        }
        if (lowerSni.contains("twitter") || lowerSni.contains("twimg") || lowerSni.contains("x.com") || lowerSni.contains("t.co")) {
            return TWITTER;
        }
        if (lowerSni.contains("netflix") || lowerSni.contains("nflxvideo") || lowerSni.contains("nflximg")) {
            return NETFLIX;
        }
        if (lowerSni.contains("amazon") || lowerSni.contains("amazonaws") || lowerSni.contains("cloudfront") || lowerSni.contains("aws")) {
            return AMAZON;
        }
        if (lowerSni.contains("microsoft") || lowerSni.contains("msn.com") || lowerSni.contains("office") || lowerSni.contains("azure") || lowerSni.contains("live.com") || lowerSni.contains("outlook") || lowerSni.contains("bing")) {
            return MICROSOFT;
        }
        if (lowerSni.contains("apple") || lowerSni.contains("icloud") || lowerSni.contains("mzstatic") || lowerSni.contains("itunes")) {
            return APPLE;
        }
        if (lowerSni.contains("telegram") || lowerSni.contains("t.me")) {
            return TELEGRAM;
        }
        if (lowerSni.contains("tiktok") || lowerSni.contains("tiktokcdn") || lowerSni.contains("musical.ly") || lowerSni.contains("bytedance")) {
            return TIKTOK;
        }
        if (lowerSni.contains("spotify") || lowerSni.contains("scdn.co")) {
            return SPOTIFY;
        }
        if (lowerSni.contains("zoom")) {
            return ZOOM;
        }
        if (lowerSni.contains("discord") || lowerSni.contains("discordapp")) {
            return DISCORD;
        }
        if (lowerSni.contains("github") || lowerSni.contains("githubusercontent")) {
            return GITHUB;
        }
        if (lowerSni.contains("cloudflare") || lowerSni.contains("cf-")) {
            return CLOUDFLARE;
        }
        return HTTPS;
    }
}
