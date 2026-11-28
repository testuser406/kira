//! Traffic classification without deep packet inspection.
//!
//! When the firewall does not run DPI, connection logs carry no application or web category, only
//! addresses, ports and (usually) a destination country. Three cheap signals recover most of it:
//! the destination port (service), the host name the address belongs to (learned from web-filter
//! logs or a reverse DNS lookup) and a small built-in table of well-known domains.

use std::net::IpAddr;

/// (domain suffix, application, category). A suffix matches the host itself or any subdomain.
const HOSTS: &[(&str, &str, &str)] = &[
    ("googlevideo.com", "YouTube", "Streaming Media"),
    ("youtube.com", "YouTube", "Streaming Media"),
    ("ytimg.com", "YouTube", "Streaming Media"),
    ("nflxvideo.net", "Netflix", "Streaming Media"),
    ("netflix.com", "Netflix", "Streaming Media"),
    ("nflximg.net", "Netflix", "Streaming Media"),
    ("primevideo.com", "Prime Video", "Streaming Media"),
    ("hotstar.com", "Hotstar", "Streaming Media"),
    ("twitch.tv", "Twitch", "Streaming Media"),
    ("ttvnw.net", "Twitch", "Streaming Media"),
    ("spotify.com", "Spotify", "Streaming Media"),
    ("scdn.co", "Spotify", "Streaming Media"),
    ("facebook.com", "Facebook", "Social Networking"),
    ("fbcdn.net", "Facebook", "Social Networking"),
    ("fbsbx.com", "Facebook", "Social Networking"),
    ("instagram.com", "Instagram", "Social Networking"),
    ("cdninstagram.com", "Instagram", "Social Networking"),
    ("whatsapp.net", "WhatsApp", "Instant Messaging"),
    ("whatsapp.com", "WhatsApp", "Instant Messaging"),
    ("tiktok.com", "TikTok", "Social Networking"),
    ("tiktokcdn.com", "TikTok", "Social Networking"),
    ("byteoversea.com", "TikTok", "Social Networking"),
    ("twitter.com", "X (Twitter)", "Social Networking"),
    ("twimg.com", "X (Twitter)", "Social Networking"),
    ("snapchat.com", "Snapchat", "Social Networking"),
    ("sc-cdn.net", "Snapchat", "Social Networking"),
    ("linkedin.com", "LinkedIn", "Social Networking"),
    ("reddit.com", "Reddit", "Social Networking"),
    ("redditstatic.com", "Reddit", "Social Networking"),
    ("telegram.org", "Telegram", "Instant Messaging"),
    ("t.me", "Telegram", "Instant Messaging"),
    ("discord.com", "Discord", "Instant Messaging"),
    ("discordapp.com", "Discord", "Instant Messaging"),
    ("zoom.us", "Zoom", "Video Conferencing"),
    ("zoomgov.com", "Zoom", "Video Conferencing"),
    (
        "teams.microsoft.com",
        "Microsoft Teams",
        "Video Conferencing",
    ),
    ("skype.com", "Skype", "Video Conferencing"),
    ("webex.com", "Webex", "Video Conferencing"),
    ("meet.google.com", "Google Meet", "Video Conferencing"),
    ("windowsupdate.com", "Windows Update", "Software Updates"),
    (
        "delivery.mp.microsoft.com",
        "Windows Update",
        "Software Updates",
    ),
    ("update.microsoft.com", "Windows Update", "Software Updates"),
    ("apple.com", "Apple Services", "Software Updates"),
    ("mzstatic.com", "Apple Services", "Software Updates"),
    ("icloud.com", "iCloud", "Cloud Storage"),
    ("office.com", "Microsoft 365", "Business Applications"),
    ("office365.com", "Microsoft 365", "Business Applications"),
    ("outlook.com", "Microsoft 365", "Business Applications"),
    ("sharepoint.com", "Microsoft 365", "Business Applications"),
    ("live.com", "Microsoft Account", "Business Applications"),
    ("microsoft.com", "Microsoft", "Business Applications"),
    (
        "microsoftonline.com",
        "Microsoft 365",
        "Business Applications",
    ),
    ("onedrive.com", "OneDrive", "Cloud Storage"),
    ("dropbox.com", "Dropbox", "Cloud Storage"),
    ("dropboxusercontent.com", "Dropbox", "Cloud Storage"),
    ("drive.google.com", "Google Drive", "Cloud Storage"),
    ("googleusercontent.com", "Google Content", "Cloud Storage"),
    ("gmail.com", "Gmail", "Business Applications"),
    ("googleapis.com", "Google Services", "Business Applications"),
    ("gstatic.com", "Google Services", "Business Applications"),
    ("google.com", "Google", "Search Engines"),
    ("bing.com", "Bing", "Search Engines"),
    ("amazonaws.com", "Amazon AWS", "Cloud Hosting"),
    ("cloudfront.net", "Amazon CloudFront", "Content Delivery"),
    ("azure.com", "Microsoft Azure", "Cloud Hosting"),
    ("azureedge.net", "Azure CDN", "Content Delivery"),
    ("cloudflare.com", "Cloudflare", "Content Delivery"),
    ("cloudflare.net", "Cloudflare", "Content Delivery"),
    ("akamaitechnologies.com", "Akamai", "Content Delivery"),
    ("akamaiedge.net", "Akamai", "Content Delivery"),
    ("akamai.net", "Akamai", "Content Delivery"),
    ("fastly.net", "Fastly", "Content Delivery"),
    ("edgecastcdn.net", "Edgecast", "Content Delivery"),
    (
        "googleusercontent.com",
        "Google Content",
        "Content Delivery",
    ),
    ("steampowered.com", "Steam", "Games"),
    ("steamcontent.com", "Steam", "Games"),
    ("epicgames.com", "Epic Games", "Games"),
    ("riotgames.com", "Riot Games", "Games"),
    ("playstation.net", "PlayStation", "Games"),
    ("xboxlive.com", "Xbox Live", "Games"),
    ("roblox.com", "Roblox", "Games"),
    ("minecraft.net", "Minecraft", "Games"),
    ("github.com", "GitHub", "Software Development"),
    ("githubusercontent.com", "GitHub", "Software Development"),
    ("docker.io", "Docker", "Software Development"),
    ("npmjs.org", "npm", "Software Development"),
    ("ubuntu.com", "Ubuntu", "Software Updates"),
    ("debian.org", "Debian", "Software Updates"),
    ("adobe.com", "Adobe", "Business Applications"),
    ("salesforce.com", "Salesforce", "Business Applications"),
    ("slack.com", "Slack", "Business Applications"),
    ("slack-edge.com", "Slack", "Business Applications"),
    ("atlassian.net", "Atlassian", "Business Applications"),
    ("torproject.org", "Tor", "Proxy and Anonymizers"),
    ("nordvpn.com", "NordVPN", "Proxy and Anonymizers"),
    ("expressvpn.com", "ExpressVPN", "Proxy and Anonymizers"),
    ("protonvpn.ch", "ProtonVPN", "Proxy and Anonymizers"),
];

/// (protocol, port, application, category). Protocol `""` matches both TCP and UDP.
const PORTS: &[(&str, i32, &str, &str)] = &[
    ("", 53, "DNS", "Network Services"),
    ("", 123, "NTP", "Network Services"),
    ("", 67, "DHCP", "Network Services"),
    ("", 161, "SNMP", "Network Management"),
    ("", 514, "Syslog", "Network Management"),
    ("", 22, "SSH", "Remote Access"),
    ("", 23, "Telnet", "Remote Access"),
    ("", 3389, "RDP", "Remote Access"),
    ("", 5900, "VNC", "Remote Access"),
    ("", 5938, "TeamViewer", "Remote Access"),
    ("", 21, "FTP", "File Transfer"),
    ("", 990, "FTPS", "File Transfer"),
    ("", 445, "SMB", "File Sharing"),
    ("", 139, "NetBIOS", "File Sharing"),
    ("", 2049, "NFS", "File Sharing"),
    ("", 25, "SMTP", "Email"),
    ("", 465, "SMTPS", "Email"),
    ("", 587, "SMTP Submission", "Email"),
    ("", 110, "POP3", "Email"),
    ("", 995, "POP3S", "Email"),
    ("", 143, "IMAP", "Email"),
    ("", 993, "IMAPS", "Email"),
    ("", 5222, "XMPP", "Instant Messaging"),
    ("", 5228, "Google Push", "Instant Messaging"),
    ("", 5223, "Apple Push", "Instant Messaging"),
    ("udp", 3478, "STUN/TURN", "Voice and Video"),
    ("udp", 3479, "STUN/TURN", "Voice and Video"),
    ("", 5060, "SIP", "Voice and Video"),
    ("", 5061, "SIP", "Voice and Video"),
    ("", 1935, "RTMP", "Streaming Media"),
    ("", 554, "RTSP", "Streaming Media"),
    ("", 1194, "OpenVPN", "VPN"),
    ("", 500, "IPsec IKE", "VPN"),
    ("", 4500, "IPsec NAT-T", "VPN"),
    ("", 1701, "L2TP", "VPN"),
    ("", 1723, "PPTP", "VPN"),
    ("", 51820, "WireGuard", "VPN"),
    ("", 1433, "SQL Server", "Database"),
    ("", 3306, "MySQL", "Database"),
    ("", 5432, "PostgreSQL", "Database"),
    ("", 1521, "Oracle DB", "Database"),
    ("", 6379, "Redis", "Database"),
    ("", 27017, "MongoDB", "Database"),
    ("", 6881, "BitTorrent", "Peer to Peer"),
    ("", 6969, "BitTorrent Tracker", "Peer to Peer"),
    ("udp", 443, "QUIC", "Unclassified (QUIC)"),
    ("", 443, "HTTPS", "Unclassified (HTTPS)"),
    ("", 8443, "HTTPS (alt)", "Unclassified (HTTPS)"),
    ("", 80, "HTTP", "Unclassified (HTTP)"),
    ("", 8080, "HTTP (alt)", "Unclassified (HTTP)"),
];

/// Application and category for a destination port, from the table above.
pub fn service_for_port(protocol: Option<&str>, port: i32) -> Option<(&'static str, &'static str)> {
    let proto = protocol.unwrap_or("").to_ascii_lowercase();
    let proto = match proto.as_str() {
        "tcp" | "udp" => proto.as_str(),
        _ => "",
    };
    PORTS
        .iter()
        .find(|(p, n, _, _)| *n == port && (p.is_empty() || *p == proto))
        .map(|(_, _, app, cat)| (*app, *cat))
}

/// Application and category for a host name (a PTR answer or a web-filter domain).
pub fn classify_host(host: &str) -> Option<(&'static str, &'static str)> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    HOSTS
        .iter()
        .find(|(suffix, _, _)| {
            host == *suffix
                || host
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
        .map(|(_, app, cat)| (*app, *cat))
}

/// `a.b.example.com` -> `example.com`; keeps three labels under common two-part public suffixes.
pub fn registrable_domain(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    let tail = labels[labels.len() - 2];
    let second_level = matches!(tail, "co" | "com" | "net" | "org" | "gov" | "edu" | "ac")
        && labels[labels.len() - 1].len() == 2;
    let keep = if second_level { 3 } else { 2 };
    labels[labels.len() - keep.min(labels.len())..].join(".")
}

/// Public, routable addresses only: private, loopback, link-local and multicast ranges are
/// neither resolved nor labelled.
pub fn is_public_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
        }
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80)
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_match_suffix_not_substring() {
        assert_eq!(
            classify_host("rr3---sn-abc.googlevideo.com"),
            Some(("YouTube", "Streaming Media"))
        );
        assert_eq!(
            classify_host("GOOGLEVIDEO.COM."),
            Some(("YouTube", "Streaming Media"))
        );
        assert_eq!(classify_host("notgooglevideo.com"), None);
        assert_eq!(
            classify_host("a.b.fbcdn.net").map(|x| x.0),
            Some("Facebook")
        );
        assert_eq!(classify_host(""), None);
    }

    #[test]
    fn ports_respect_protocol() {
        assert_eq!(
            service_for_port(Some("UDP"), 443).map(|x| x.0),
            Some("QUIC")
        );
        assert_eq!(
            service_for_port(Some("TCP"), 443).map(|x| x.0),
            Some("HTTPS")
        );
        assert_eq!(service_for_port(None, 3389).map(|x| x.0), Some("RDP"));
        assert_eq!(service_for_port(Some("tcp"), 3478), None);
        assert_eq!(
            service_for_port(Some("udp"), 3478).map(|x| x.0),
            Some("STUN/TURN")
        );
        assert_eq!(service_for_port(Some("tcp"), 40000), None);
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("a.b.example.com"), "example.com");
        assert_eq!(registrable_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("example.com."), "example.com");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[test]
    fn public_ip_detection() {
        for ip in [
            "10.1.2.3",
            "192.168.0.9",
            "172.16.5.5",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "fe80::1",
            "fd00::1",
            "::1",
            "nonsense",
        ] {
            assert!(!is_public_ip(ip), "{ip}");
        }
        for ip in ["8.8.8.8", "142.250.1.1", "2606:4700::1111"] {
            assert!(is_public_ip(ip), "{ip}");
        }
    }
}
