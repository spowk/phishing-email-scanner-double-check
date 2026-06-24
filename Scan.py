import sys
import os
import re
import time
import hashlib
import requests
from pathlib import Path
from urllib.parse import urljoin
from bs4 import BeautifulSoup

VT_BASE = "https://www.virustotal.com/api/v3"
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
REQUEST_TIMEOUT = 10
MAX_DEPTH = 2
MAX_LINKS_PER_PAGE = 10

FILE_SIGNATURES = {
    b"\x4D\x5A": "Windows EXE/DLL (PE)",
    b"\x7F\x45\x4C\x46": "Linux ELF executable",
    b"\x25\x50\x44\x46": "PDF",
    b"\x50\x4B\x03\x04": "ZIP/Office (docx,xlsx,jar,apk...)",
    b"\xD0\xCF\x11\xE0": "Legacy MS Office (doc/xls, OLE)",
    b"\x52\x61\x72\x21": "RAR archive",
    b"\x1F\x8B": "GZIP",
    b"\x4D\x53\x43\x46": "MS Cabinet (.cab)",
    b"\xFF\xD8\xFF": "JPEG image",
    b"\x89\x50\x4E\x47": "PNG image",
    b"\x23\x21": "Script (shebang #!)",
}
SAFE_DOC_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png"}
DANGEROUS_SIGNATURES = {"Windows EXE/DLL (PE)", "Linux ELF executable", "Script (shebang #!)"}

visited = set()


def identify_real_type(content: bytes) -> str:
    for sig, label in FILE_SIGNATURES.items():
        if content.startswith(sig):
            return label
    return "Unknown/raw binary"


def extract_links(file_path: str) -> list[str]:
    links = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            soup = BeautifulSoup(f.read(), "html.parser")
            for a in soup.find_all("a"):
                href = a.get("href")
                if href and href.startswith(("http://", "https://")):
                    links.append(href)
    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}")
    return links


def extract_links_from_html(html: str, base_url: str) -> list[str]:
    links = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href")
            if href:
                links.append(urljoin(base_url, href))
        for tag in soup.find_all(attrs={"onclick": True}):
            match = re.search(r"""['"](https?://[^'"]+|/[^'"]+)['"]""", tag["onclick"])
            if match:
                links.append(urljoin(base_url, match.group(1)))
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            content = meta.get("content", "")
            match = re.search(r"url=(.+)", content, re.I)
            if match:
                links.append(urljoin(base_url, match.group(1).strip()))
    except Exception as e:
        print(f"  [!] Could not parse landing page HTML: {e}")
    seen = []
    for l in links:
        if l not in seen:
            seen.append(l)
    return seen[:MAX_LINKS_PER_PAGE]


def vt_check_url(url: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No API key provided"}
    headers = {"x-apikey": api_key}
    try:
        submit = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=REQUEST_TIMEOUT)
        submit.raise_for_status()
        analysis_id = submit.json()["data"]["id"]
        for _ in range(5):
            result = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=REQUEST_TIMEOUT)
            result.raise_for_status()
            data = result.json()["data"]["attributes"]
            if data.get("status") == "completed":
                stats = data.get("stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                }
            time.sleep(2)
        return {"error": "analysis still pending after timeout"}
    except requests.RequestException as e:
        return {"error": str(e)}


def vt_check_file_hash(file_hash: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No API key provided"}
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(f"{VT_BASE}/files/{file_hash}", headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return {"not_found": True}
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except requests.RequestException as e:
        return {"error": str(e)}


def fetch_content_safely(url: str):
    try:
        resp = requests.get(
            url, timeout=REQUEST_TIMEOUT, stream=True,
            headers={"User-Agent": "Mozilla/5.0 (phishing-scanner)"},
        )
        resp.raise_for_status()
        content_type = resp.headers.get("Content-Type", "unknown")
        chunks, total = [], 0
        for chunk in resp.iter_content(chunk_size=8192):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                print("  [!] File exceeds safety cap, stopping download.")
                break
            chunks.append(chunk)
        return b"".join(chunks), content_type
    except requests.RequestException as e:
        print(f"  [ERROR] Download failed: {e}")
        return None, None


def inspect_one_url(url: str, depth: int, api_key: str, origin_note: str = ""):
    if url in visited:
        return None
    visited.add(url)

    safe_url = url.replace("http", "hxxp")
    indent = "  " * depth
    print(f"\n{indent}=== [depth {depth}] Scanning URL: {safe_url} {origin_note} ===")

    url_verdict = vt_check_url(url, api_key)
    if "error" in url_verdict:
        print(f"{indent}  [URL REPUTATION] Could not check: {url_verdict['error']}")
    else:
        mal, susp = url_verdict.get("malicious", 0), url_verdict.get("suspicious", 0)
        if mal > 0 or susp > 0:
            print(f"{indent}  [URL REPUTATION] FLAGGED — malicious={mal}, suspicious={susp}")
        else:
            print(f"{indent}  [URL REPUTATION] Clean according to VT")

    content, content_type = fetch_content_safely(url)
    if content is None:
        return None

    file_hash = hashlib.sha256(content).hexdigest()
    real_type = identify_real_type(content)
    claimed_ext = Path(url.split("?")[0]).suffix.lower()

    print(f"{indent}  SHA256: {file_hash}")
    print(f"{indent}  Content-Type: {content_type}")
    print(f"{indent}  Claimed extension: {claimed_ext or 'none'}")
    print(f"{indent}  Actual signature: {real_type}")

    mismatch = (claimed_ext in SAFE_DOC_EXTENSIONS and real_type in DANGEROUS_SIGNATURES) or \
               ("pdf" in content_type.lower() and real_type not in ("PDF", "Unknown/raw binary"))

    if mismatch:
        print(f"{indent}  [!!!] MISMATCH DETECTED — claims to be a document but is actually: {real_type}")
    else:
        print(f"{indent}  [OK] Claimed type and actual signature are consistent.")

    hash_verdict = vt_check_file_hash(file_hash, api_key)
    if hash_verdict.get("not_found"):
        print(f"{indent}  [FILE HASH] Not previously seen on VirusTotal.")
    elif "error" in hash_verdict:
        print(f"{indent}  [FILE HASH] Could not check: {hash_verdict['error']}")
    else:
        mal = hash_verdict.get("malicious", 0)
        print(f"{indent}  [FILE HASH] {'FLAGGED by ' + str(mal) + ' engines' if mal else 'Clean according to VT'}")

    print(f"{indent}" + "-" * 50)

    if "html" in content_type.lower() or real_type == "Unknown/raw binary":
        try:
            return content.decode("utf-8", errors="ignore")
        except Exception:
            return None
    return None


def crawl(url: str, depth: int, api_key: str, origin_note: str = ""):
    if depth > MAX_DEPTH:
        return
    html = inspect_one_url(url, depth, api_key, origin_note)
    if html and depth < MAX_DEPTH:
        next_links = extract_links_from_html(html, url)
        for nxt in next_links:
            crawl(nxt, depth + 1, api_key, origin_note="(found on landing page)")


def analyze(links: list[str], api_key: str):
    if not links:
        print("No links found in the email.")
        return
    for url in links:
        crawl(url, depth=1, api_key=api_key, origin_note="(direct from email)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py <VT_API_KEY> <email.html>")
        sys.exit(1)

    VT_API_KEY = sys.argv[1]
    target = sys.argv[2]

    found_links = extract_links(target)
    print(f"Found {len(found_links)} link(s) in {target}")
    analyze(found_links, VT_API_KEY)