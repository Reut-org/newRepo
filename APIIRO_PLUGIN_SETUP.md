# Testing the Apiiro Plugin on Claude — Fresh Windows Machine

This guide gets the **Apiiro security plugin** running on Claude on a Windows
computer where **nothing is installed except the Claude app**.

There are two separate things to install:

1. **The Apiiro plugin** — the `apiiro-*` skills inside Claude Code (this is what
   gives Claude the `/apiiro-setup`, `/apiiro-fast-scan`, etc. commands).
2. **The Apiiro CLI** — the `apiiro` binary the skills call under the hood.

You need both. Do them in order.

---

## Prerequisites

| Need | Why | How |
|------|-----|-----|
| **Claude Code** | Plugins/skills are a Claude Code feature, not the chat app | Open the Claude desktop app → it includes Claude Code. Or install the CLI: `npm i -g @anthropic-ai/claude-code` (needs Node 18+). |
| **Git for Windows** | Provides `git` + Git Bash. The plugin's hooks/status-line scripts are bash, and the CLI scans git repos | Download: https://git-scm.com/download/win |
| **GitHub access to `apiiro/marketplace`** | The plugin marketplace lives there | Sign in to GitHub in the browser; the repo must be accessible to your account |
| **An Apiiro account** | To authenticate the CLI (`apiiro login`) | Your normal Apiiro SSO login |

> **Tip:** On Windows, run the bash-based commands below from **Git Bash**, not
> PowerShell/CMD. The PowerShell equivalents are noted where they differ.

---

## Step 1 — Install the Apiiro plugin in Claude Code

Open Claude Code, then run these slash commands in the prompt:

```
/plugin marketplace add apiiro/marketplace
/plugin install apiiro@apiiro
```

- The first command registers Apiiro's plugin marketplace (GitHub repo
  `apiiro/marketplace`).
- The second installs the `apiiro` plugin from it.

Confirm it worked:

```
/plugin
```

You should see **apiiro** listed as installed, and these skills become available:
`apiiro-setup`, `apiiro-fast-scan`, `apiiro-diff-scan`, `apiiro-risks`,
`apiiro-fix`, `apiiro-guardian`, `apiiro-secure-prompt`, `apiiro-threat-model`.

---

## Step 2 — Install the Apiiro CLI binary

The easiest path on a fresh machine: **let the plugin do it for you.** Just run:

```
/apiiro-setup
```

The setup skill detects your OS and walks through install → login → verify →
feature check. On Windows it will point you to the manual download below.

### Manual install (Windows)

1. Go to: https://github.com/apiiro/marketplace/releases
2. Download the latest **`apiiro-win.exe`**.
3. Rename it to **`apiiro.exe`** and put it in a folder, e.g.
   `C:\Tools\apiiro\apiiro.exe`.
4. Add that folder to your **PATH**:
   - PowerShell (one-time, current user):
     ```powershell
     [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\apiiro", "User")
     ```
   - Then **close and reopen** your terminal (and Claude Code) so PATH refreshes.
5. Verify:
   ```
   apiiro --version
   ```
   You need **version 1.4.2 or newer**. If older, download the latest release again.

---

## Step 3 — Point at STAGING (required) and authenticate

> ⚠️ **By default the CLI connects to production (`app.apiiro.com`). To use
> STAGING you MUST set the staging API URL before logging in.** The staging URL
> is `https://app-staging.apiiro.com`.

Pick **one** of these two ways:

**Option A — environment variable (recommended, persists across commands):**

- PowerShell (current user, persistent):
  ```powershell
  [Environment]::SetEnvironmentVariable("APIIRO_API_URL", "https://app-staging.apiiro.com", "User")
  ```
  Then **close and reopen** the terminal/Claude Code so it takes effect.
- Git Bash (current session only):
  ```bash
  export APIIRO_API_URL=https://app-staging.apiiro.com
  ```

Then:

```
apiiro login
```

**Option B — per-login flag (no env var needed):**

```
apiiro login --api-url https://app-staging.apiiro.com
```

Either way, a browser opens — sign in with your Apiiro account. Then confirm:

```
apiiro auth status
```

Make sure the credentials path/URL reflects staging. If you ever need to switch
environments, run `apiiro logout` first, change the URL, then `apiiro login` again.

---

## Step 4 — Confirm which features are enabled

Different Apiiro environments enable different features. `/apiiro-setup` checks
this automatically, or you can probe manually:

```bash
apiiro fast-scan secrets --file /dev/null   # secrets scanning
apiiro fast-scan oss --file /dev/null        # OSS vulnerability scanning
apiiro guardian query "test"                 # Guardian AI
apiiro threat-model "test"                    # threat modeling
```

If a command says **"not enabled"**, that feature is off for your environment —
contact your Apiiro admin to enable it. Anything else = it's available.

---

## Step 5 — Try it

From inside a git repo, ask Claude things like:

- "Scan this repo for secrets" → triggers **apiiro-fast-scan**
- "Compare main to my branch for security risks" → **apiiro-diff-scan**
- "What security risks does this repo have?" → **apiiro-risks**
- "Is this code secure / what's the attack surface?" → **apiiro-guardian**
- "Threat model this feature: <description>" → **apiiro-threat-model**

Or invoke a skill directly, e.g. `/apiiro-fast-scan`.

---

## Quick reference — copy/paste into Claude on the new machine

If you'd rather just hand this to Claude and let it drive, paste this prompt:

```
I'm on a fresh Windows machine with only the Claude app installed. I want to test
the Apiiro plugin. Please walk me through, one step at a time, confirming each:
1. Install the plugin: /plugin marketplace add apiiro/marketplace then
   /plugin install apiiro@apiiro
2. Run /apiiro-setup to install the Apiiro CLI (Windows: apiiro-win.exe from
   https://github.com/apiiro/marketplace/releases, rename to apiiro.exe, add to PATH),
   then verify apiiro --version is >= 1.4.2.
   IMPORTANT: I need STAGING, not production. Before logging in, set
   APIIRO_API_URL=https://app-staging.apiiro.com (or use
   apiiro login --api-url https://app-staging.apiiro.com), then run apiiro login.
3. Check which Apiiro features are enabled for my environment.
4. Then list the apiiro-* skills I can use.
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `apiiro` not found after install | Reopen the terminal/Claude Code so PATH refreshes; confirm the folder is in PATH |
| `/plugin marketplace add` fails | Make sure you're signed into GitHub and have access to `apiiro/marketplace` |
| Bash scripts/hooks error on Windows | Run from **Git Bash**, not PowerShell/CMD |
| Feature says "not enabled" | That feature isn't provisioned for your environment — ask your Apiiro admin |
| Version too old | Re-download the latest `apiiro-win.exe` from the releases page |
