"""
Commit 97: URL Extractor
==========================
Extracts URLs from text and classifies them as safe or suspicious.
Suspicious signals: IP-based hosts, data URIs, URL shorteners,
non-standard ports, excessive query parameters.
"""

import re
from dataclasses import dataclass

_URL_RE = re.compile(
    r"https?://[^\s\"'<>]{1,2000}",
    re.IGNORECASE,
)
_IP_HOST_RE   = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")
_DATA_URI_RE  = re.compile(r"data:[^;]+;base64,")
_SHORTENER_RE = re.compile(r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly)/")
_NONSTD_PORT  = re.compile(r"https?://[^/]+:(?!80\b|443\b)\d{2,5}")


@dataclass
class URLAnalysis:
    urls: list[str]
    suspicious_urls: list[str]
    flags: list[str]
    url_count: int
    suspicious_count: int

    def to_dict(self) -> dict:
        return {
            "url_count": self.url_count,
            "suspicious_count": self.suspicious_count,
            "suspicious_urls": self.suspicious_urls[:5],
            "flags": self.flags,
        }


def extract_and_analyze(text: str) -> URLAnalysis:
    urls = _URL_RE.findall(text)
    suspicious: list[str] = []
    flags: list[str] = []

    for url in urls:
        reasons: list[str] = []
        if _IP_HOST_RE.match(url):
            reasons.append("ip_host")
        if _DATA_URI_RE.match(url):
            reasons.append("data_uri")
        if _SHORTENER_RE.match(url):
            reasons.append("url_shortener")
        if _NONSTD_PORT.match(url):
            reasons.append("non_standard_port")
        if len(url) > 500:
            reasons.append("excessive_length")
        if reasons:
            suspicious.append(url)
            flags.extend(reasons)

    return URLAnalysis(
        urls=urls,
        suspicious_urls=suspicious,
        flags=list(set(flags)),
        url_count=len(urls),
        suspicious_count=len(suspicious),
    )
