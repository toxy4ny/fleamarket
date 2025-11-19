# Hunting API Keys in the Wild: How I Built FleaMarket to Find (and Help Fix) Real Leaks on GitHub

> **TL;DR**: I built an ethical, open-source scanner called **FleaMarket** that finds exposed API keys in fresh GitHub repos. In a recent scan, it discovered **live Google/Gemini keys** in public `.env` files — and I helped owners secure them **before any abuse occurred**.

---

## 🕵️‍♂️ Why Hunt for Secrets?

API keys in public code are like leaving your house keys under the doormat. Even if you *think* no one will look — **bots do**. Thousands of keys are scraped every hour, leading to:

- Unexpected cloud bills (Stripe, Google Cloud, AWS)
- Data exfiltration
- Account takeovers

While GitHub’s native secret scanning blocks many leaks, **new keys still slip through** — especially in non-standard files like `.env.vercel`, `.env.backup`, or examples.

So I built **FleaMarket**: a lightweight, ethical secret hunter focused on **fresh, high-risk repositories**.

---

## 🛠️ Introducing FleaMarket

**FleaMarket** is a Python-based scanner that:

✅ Searches GitHub Code Search API for potential secrets  
✅ Filters **false positives** (e.g., `"your_key_here"`, test files)  
✅ Ignores stale repositories — only scans repos **created ≤30 days** and **updated ≤7 days**  
✅ Detects 30+ key types: Google, AWS, GitHub, OpenAI, Stripe, Pinecone, Census, and more  
✅ Resumes scans after interruption  
✅ Never exploits or stores keys — **ethics-first design**

> 🔗 GitHub repo (coming soon — but you can build your own!): `github.com/toxy4ny/fleamarket`

---

## 🔍 How It Works

FleaMarket combines **pattern matching**, **entropy analysis**, and **context filtering**:

1. **Search**: Query GitHub for terms like `api_key`, `sk_live_`, `AIza`, etc.
2. **Fetch**: Download file content from search results.
3. **Clean**: Strip comments (Python, JS, Bash, C-style).
4. **Validate**:
   - Is the value **high-entropy**? (Random-looking strings only)
   - Is it **not a placeholder**? (Rejects `"test"`, `"xxx"`, `"your_key"`)
   - Is the file **not in `/test`, `/example`, `README.md`**?
5. **Filter by freshness**: Only analyze repos created recently and recently pushed.
6. **Report**: Save clean findings to `findings.json`.

This avoids noise while catching **real, actionable leaks**.

---

## 🎯 Real Findings (Ethically Disclosed)

In a scan with:
```bash
python fleamarket.py --query "filename:.env AIza" --repo-age 30
```

FleaMarket found **two live Google/Gemini API keys**:

- In `/.env.vercel` → Exposed **Google Maps API key**
- In `/backend/.env.backup` → Exposed **Gemini API key** (`AIzaSy...`)

Both repos were **created within the last 30 days** — meaning keys were likely still active.

### What I Did:
1. **Did not use or test** the keys.
2. Opened **polite, constructive GitHub Issues** explaining the risk.
3. Provided **step-by-step remediation**:
   - Revoke/restrict keys in Google Cloud Console
   - Delete sensitive files
   - Use `.gitignore` and environment management best practices

Both maintainers responded positively — and the keys were secured.

> 🌟 **This is the goal**: not to shame, but to **enable better security through collaboration**.

---

## 🧪 Try It Yourself (Ethically!)

You can build your own version:

1. Get a [GitHub Personal Access Token](https://github.com/settings/tokens) (only `public_repo` scope needed)
2. Use regex patterns for common secrets (e.g., `AIza[0-9A-Za-z\\_\\-]{35}`)
3. Add entropy + context filters
4. Focus on **fresh repos** — they’re more likely to contain **active** leaks
5. **Always disclose responsibly**

> ⚠️ Never scan private repos, self-hosted instances, or non-public data.  
> ⚠️ Never exploit or log actual secrets.  
> ✅ Treat every finding as a chance to **help**, not harm.

---

## 🔮 What’s Next?

FleaMarket is just the beginning. Future ideas:

- Support GitLab, Gist, and public code archives
- Auto-create GitHub Issues via API
- Integrate with GitHub Security Lab workflows
- Publish anonymized trends (e.g., “Most leaked key types this month”)

But the core mission stays the same: **make open-source safer, one responsible disclosure at a time**.

---

## 💬 Final Thought

Finding zero leaks would be ideal.  
But until then — **tools like FleaMarket, built with ethics and care, can turn researchers into allies**.

If you maintain a project: **audit your `.env` files, use secrets managers, and enable GitHub secret scanning**.

If you’re a researcher: **hunt responsibly**.

Together, we keep the ecosystem cleaner — one key at a time.

---

*Have questions? Want the full source code? Let me know in the comments!*  
*Follow me for more on ethical security, red teaming, and offensive tooling.*

---
