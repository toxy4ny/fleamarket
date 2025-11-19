#!/usr/bin/env python3

import os
import re
import json
import math
import time
import datetime
import argparse
import requests
import datetime
from urllib.parse import quote
from typing import Dict, List, Optional

# === DEFAULTS ===
DEFAULT_QUERY = "api_key"
DEFAULT_MAX_RESULTS = 300
DEFAULT_REPO_AGE = 14
DEFAULT_PUSH_AGE = 7
DEFAULT_OUTPUT = "findings.json"
SESSION_FILE = "fleamarket_session.json"

# === ASCII BANNER ===
BANNER = r"""

            ░░░░░░░▄▄▄▄▄░░░░░░░░░░░░▄▄▄▄▄░░░░░░░
            ░░░░▄███████░░░░░░░░░░░░███████▄░░░░
            ░░░▀▀░░░░░██░░░░░░░░░░░░██░░░░░▀▀░░░
            ░░▄▄██▄░░░█░░░░░░░░░░░░░░█░░░▄██▄▄░░
            ░████▀█▄░░█░░▄▄██████▄▄░░█░░▄█▀████░
            ██▀░░░▀█░░▀██████████████▀░░█▀░░░▀██
            ▀░▄▄▄░░▀█▄░██████████████░▄█▀░░▄▄▄░▀
            ░█████▄░░▀████████████████▀░░▄█████░
            ░██▀░░▀█▄▄████████████████▄▄█▀░░▀██░
            ░█▀░░░░░░▀▀██████████████▀▀░░░░░░▀█░
            ░█░░████▄▄▄██████████████▄▄▄████░░█░
            ░░░░███░░░░░░░████████░░░░░░░███░░░░
            ░░░░███░░░░░░██████████░░░░░░███░░░░
            ░░░░░██░░░░░░▀████████▀░░░░░░██░░░░░
            ░░░░░░▀▀░░░░▄██▀▀██▀▀██▄░░░░▀▀░░░░░░
            ░░░░░░░░░░░░███░░░░░░███░░░░░░░░░░░░
            ░░░░░░░░░░░░░▀▀▀░░░░▀▀▀░░░░░░░░░░░░░

▗▄▄▄▖▗▖   ▗▄▄▄▖ ▗▄▖     ▗▖  ▗▖ ▗▄▖ ▗▄▄▖ ▗▖ ▗▖▗▄▄▄▖▗▄▄▄▖
▐▌   ▐▌   ▐▌   ▐▌ ▐▌    ▐▛▚▞▜▌▐▌ ▐▌▐▌ ▐▌▐▌▗▞▘▐▌     █  
▐▛▀▀▘▐▌   ▐▛▀▀▘▐▛▀▜▌    ▐▌  ▐▌▐▛▀▜▌▐▛▀▚▖▐▛▚▖ ▐▛▀▀▘  █  
▐▌   ▐▙▄▄▖▐▙▄▄▖▐▌ ▐▌    ▐▌  ▐▌▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▙▄▄▖  █  
                                                       
         by KL3FT3Z (https://github.com/toxy4ny)                                                 

              The Secret's Hunter for GitHub
           In Focus: Fresh repos, real top leaks. 

"""

# === FALSE POSITIVE & PATTERNS ===
IGNORE_PATH_KEYWORDS = {
    "test", "tests", "example", "examples", "sample", "samples", "demo", "mock", "stub",
    "doc", "docs", "readme", "changelog", "license", ".md", ".txt", "tutorial", "__pycache__"
}

FALSE_POSITIVE_VALUES = {
    "your_api_key", "xxx", "12345", "test", "null", "none", "fake", "dummy",
    "abcdef", "secret", "apikey", "replace_with_real_key", "placeholder", "default"
}

SECRET_PATTERNS = {
    "google_api_key": r'AIza[0-9A-Za-z\_\-]{35}',
    "google_oauth": r'ya29\.[0-9A-Za-z\_\-]{100,}',
    "aws_access_key": r'AKIA[0-9A-Z]{16}',
    "aws_secret_key": r'(?i)aws.*[\'"][A-Za-z0-9/+=]{40}[\'"]',
    "github_token": r'ghp_[0-9A-Za-z]{36}',
    "github_app_token": r'ghs_[0-9A-Za-z]{36}',
    "github_refresh_token": r'ghu_[0-9A-Za-z]{36}',
    "github_fine_grained_token": r'github_pat_[0-9A-Za-z_]{82,}',
    "openai_api_key": r'sk-[0-9a-zA-Z]{48}',
    "anthropic_api_key": r'sk-ant-[0-9a-zA-Z]{48}',
    "gemini_api_key": r'AIza[0-9A-Za-z\_\-]{35}',
    "pinecone_api_key": r'pcsk_[0-9A-Za-z\_\-]{64}',
    "census_api_key": r'[0-9a-f]{40}',
    "slack_token": r'xox[baprs]-[0-9A-Za-z\-]{10,50}',
    "stripe_live_key": r'sk_live_[0-9a-zA-Z]{24}',
    "stripe_test_key": r'sk_test_[0-9a-zA-Z]{24}',
    "twilio_sid": r'AC[0-9a-f]{32}',
    "twilio_token": r'[0-9a-f]{32}',
    "high_entropy_key": r'(["\']?[A-Za-z0-9_]*key[A-Za-z0-9_]*["\']?\s*[:=]\s*["\'])([A-Za-z0-9/+=]{30,})["\']',
}

COMPILED_PATTERNS = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in SECRET_PATTERNS.items()}
repo_metadata_cache = {}

# === SESSION MANAGEMENT ===
def load_session():
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_page": 0, "processed_repos": [], "findings": []}

def save_session(last_page: int, processed_repos: list, findings: list):
    with open(SESSION_FILE, "w") as f:
        json.dump({
            "last_page": last_page,
            "processed_repos": list(set(processed_repos)),
            "findings": findings
        }, f, indent=2)

# === CORE UTILS ===
def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    e = 0.0
    for count in freq.values():
        p = count / len(s)
        e -= p * math.log2(p)
    return e

def is_false_positive(v: str) -> bool:
    v = v.lower().strip("\"'` \t")
    if len(v) < 10: return True
    if v in FALSE_POSITIVE_VALUES: return True
    if any(w in v for w in ["your", "test", "demo", "xxx", "fake", "sample", "example"]): return True
    return entropy(v) < 2.3

def is_ignored_path(p: str) -> bool:
    return any(kw in p.lower() for kw in IGNORE_PATH_KEYWORDS)

def remove_comments(code: str, path: str) -> str:
    lines, cleaned, in_ml = code.splitlines(), [], False
    for line in lines:
        if in_ml:
            if '*/' in line:
                in_ml = False
                rest = line.split('*/', 1)[1]
                if rest.strip(): cleaned.append(rest)
            continue
        if '/*' in line:
            in_ml = True
            before = line.split('/*')[0]
            if before.strip(): cleaned.append(before)
            continue
        if path.endswith(('.py', '.sh', '.bash', '.ps1', '.r', '.rb')):
            line = line.split('#', 1)[0]
        elif path.endswith(('.js', '.ts', '.java', '.c', '.cpp', '.cs', '.go')):
            line = line.split('//', 1)[0]
        if line.strip(): cleaned.append(line)
    return '\n'.join(cleaned)

def extract_secrets(text: str, path: str) -> Dict[str, List[str]]:
    if is_ignored_path(path): return {}
    clean = remove_comments(text, path)
    found = {}
    for name, pat in COMPILED_PATTERNS.items():
        matches = pat.findall(clean)
        if not matches: continue
        vals = []
        for m in matches:
            val = m[1] if isinstance(m, tuple) and len(m) > 1 else (m[0] if isinstance(m, tuple) else m)
            if not is_false_positive(val): vals.append(val)
        if vals: found[name] = list(set(vals))
    return found

def fetch_file(html_url: str) -> Optional[str]:
    raw = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        r = requests.get(raw, timeout=10)
        return r.text if r.status_code == 200 else None
    except: return None

def get_repo_meta(full_name: str) -> Optional[dict]:
    if full_name in repo_metadata_cache: return repo_metadata_cache[full_name]
    url = f"https://api.github.com/repos/{full_name}"
    try:
        r = requests.get(url, headers={"Authorization": f"token {GITHUB_TOKEN}"}, timeout=10)
        if r.status_code == 200:
            d = r.json()
            meta = {"created_at": d.get("created_at"), "pushed_at": d.get("pushed_at"), "stars": d.get("stargazers_count", 0)}
            repo_metadata_cache[full_name] = meta
            return meta
    except: pass
    repo_metadata_cache[full_name] = None
    return None

def is_recent_repo(full_name: str) -> bool:
    meta = get_repo_meta(full_name)
    if not meta or not meta.get("created_at") or not meta.get("pushed_at"):
        return False

    # Парсим даты из GitHub как UTC (они всегда в формате ISO 8601 с 'Z')
    try:
        created_at_str = meta["created_at"]
        pushed_at_str = meta["pushed_at"]

        # Преобразуем "2025-11-10T12:00:00Z" → datetime с UTC tzinfo
        created = datetime.datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        pushed = datetime.datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False

    # Текущее время в UTC (timezone-aware)
    now = datetime.datetime.now(datetime.timezone.utc)

    # Сравниваем — оба объекта timezone-aware
    created_recent = (now - created).days <= MAX_REPO_AGE_DAYS
    pushed_recent = (now - pushed).days <= MAX_LAST_PUSH_DAYS

    return created_recent and pushed_recent

# === MAIN SCANNING LOGIC ===
def fetch_and_process_pages(query: str, start_page: int, max_results: int, output_file: str):
    findings = []
    processed_repos = set()
    session = load_session() if start_page > 0 else {"last_page": start_page, "processed_repos": [], "findings": []}
    if start_page > 0:
        processed_repos = set(session.get("processed_repos", []))
        findings = session.get("findings", [])

    try:
        page = start_page + 1
        total_fetched = 0

        while total_fetched < max_results:
            print(f"🔍 Fetching page {page} of GitHub code search...")
            url = f"https://api.github.com/search/code?q={quote(query)}&per_page=30&page={page}"
            r = requests.get(url, headers={"Authorization": f"token {GITHUB_TOKEN}"})
            
            if r.status_code == 403 and "rate limit" in r.text.lower():
                print("⏳ Rate limit hit. Sleeping 60s...")
                time.sleep(60)
                continue
            if r.status_code != 200:
                print(f"⚠️ API error on page {page}: {r.status_code}")
                break

            data = r.json()
            items = data.get("items", [])
            if not items:
                print("🔚 No more results.")
                break

            new_items = []
            for item in items:
                repo = item["repository"]["full_name"]
                if repo not in processed_repos:
                    new_items.append(item)
                    processed_repos.add(repo)

            for item in new_items:
                repo = item["repository"]["full_name"]
                if not is_recent_repo(repo):
                    continue

                file_path = item["path"]
                html_url = item["html_url"]
                content = fetch_file(html_url)
                if not content: continue

                secrets = extract_secrets(content, file_path)
                if secrets:
                    meta = repo_metadata_cache[repo]
                    finding = {
                        "repo": repo,
                        "file": file_path,
                        "url": html_url,
                        "created_at": meta["created_at"],
                        "pushed_at": meta["pushed_at"],
                        "stars": meta["stars"],
                        "secrets": secrets
                    }
                    findings.append(finding)
                    print(f"  🚨 {repo}/{file_path} → {list(secrets.keys())}")
                else:
                    print(f"  → Clean: {repo}/{file_path}")

            total_fetched += len(items)
            save_session(page, list(processed_repos), findings)
            print(f"  → Page {page} done. Total findings: {len(findings)}")

            if len(items) < 30:
                break
            page += 1
            time.sleep(0.8)

    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user. Progress saved.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    with open(output_file, "w") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    
    return findings

# === CLI ENTRY POINT ===
def main():
    global GITHUB_TOKEN, MAX_REPO_AGE_DAYS, MAX_LAST_PUSH_DAYS

    parser = argparse.ArgumentParser(
        prog="fleamarket",
        description="Ethical scanner for exposed API keys in fresh GitHub repos.",
        epilog="Example: python fleamarket.py --query 'census_api_key' --resume"
    )
    parser.add_argument("--query", type=str, default=DEFAULT_QUERY, help=f"Search query (default: '{DEFAULT_QUERY}')")
    parser.add_argument("--max-results", type=int, default=DEFAULT_MAX_RESULTS, help=f"Max results to fetch (default: {DEFAULT_MAX_RESULTS})")
    parser.add_argument("--repo-age", type=int, default=DEFAULT_REPO_AGE, help=f"Max repo age in days (created_at, default: {DEFAULT_REPO_AGE})")
    parser.add_argument("--push-age", type=int, default=DEFAULT_PUSH_AGE, help=f"Max last push age in days (pushed_at, default: {DEFAULT_PUSH_AGE})")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT, help=f"Output JSON file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--token", type=str, help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--resume", action="store_true", help="Resume from last session (default: start fresh)")
    
    args = parser.parse_args()
    print(BANNER)

    GITHUB_TOKEN = args.token or os.getenv("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        print("❌ Error: GitHub token required. Use --token or set GITHUB_TOKEN env var.")
        exit(1)

    MAX_REPO_AGE_DAYS = args.repo_age
    MAX_LAST_PUSH_DAYS = args.push_age
    OUTPUT_FILE = args.output

    start_page = 0
    if args.resume and os.path.exists(SESSION_FILE):
        session = load_session()
        start_page = session.get("last_page", 0)
        print(f"♻️ Resuming from page {start_page + 1} (last completed: {start_page})")

    print(f"🎯 Target: repos created ≤{MAX_REPO_AGE_DAYS}d AND pushed ≤{MAX_LAST_PUSH_DAYS}d")
    findings = fetch_and_process_pages(
        query=args.query,
        start_page=start_page,
        max_results=min(args.max_results, 1000),
        output_file=OUTPUT_FILE
    )

    print(f"\n✅ Final report: {len(findings)} findings in '{OUTPUT_FILE}'")
    if args.resume:
        print("🧹 To start fresh next time, delete 'fleamarket_session.json'")

if __name__ == "__main__":
    main()