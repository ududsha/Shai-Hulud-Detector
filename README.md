# Shai-Hulud 2.0 Detector

A security tool to check your globally installed npm packages against the Shai-Hulud 2.0 compromised packages list. This tool helps protect against the ongoing npm supply chain attack campaign.

## What is Shai-Hulud 2.0?

Shai-Hulud 2.0 (also known as "The Second Coming") is a sophisticated npm supply chain attack that compromises packages to steal credentials, GitHub tokens, npm tokens, and sensitive environment variables. The malware creates unauthorized GitHub repositories and deploys malicious GitHub Actions runners.

## Features

- 🔍 Scans all globally installed npm packages (including dependencies)
- 🌐 Fetches latest compromised package lists from multiple sources
- 🎨 Clear, color-coded terminal output
- ⚡ Fast scanning with up to 10 levels of dependency depth
- 📊 Detailed reporting with remediation steps
- 🔄 Supports multiple compromised package list formats

## Installation

Clone this repository:

```bash
git clone https://github.com/ududsha/Shai-Hulud-Detector.git
cd Shai-Hulud-Detector
```

## How to Run

### Method 1: Quick Scan (Recommended)

This is the fastest and easiest way to run the detector:

```bash
# Navigate to the detector directory
cd Shai-Hulud-Detector

# Run the detector with inline package fetching
node detector.js --inline
```

**What happens:**
- The tool automatically fetches your global npm packages
- Retrieves the latest compromised package lists
- Performs the security scan
- Displays results in your terminal

### Method 2: Using Saved Package List

If you want to save your package list for later analysis:

```bash
# Step 1: Navigate to the detector directory
cd Shai-Hulud-Detector

# Step 2: Export your global packages to a file
npm list -g --depth=10 --json > global-packages.json

# Step 3: Run the detector (it will automatically use the saved file)
node detector.js
```

**Benefits of this method:**
- Faster repeated scans (no need to re-fetch packages)
- Useful for offline analysis
- Can be used in CI/CD pipelines

### Method 3: One-Liner from Any Directory

You can run this from anywhere if you add the shebang:

```bash
# Make the script executable (one-time setup)
chmod +x /path/to/Shai-Hulud-Detector/detector.js

# Run from anywhere
/path/to/Shai-Hulud-Detector/detector.js --inline
```

### Running in Different Environments

**macOS/Linux:**
```bash
node detector.js --inline
```

**Windows (Command Prompt):**
```cmd
node detector.js --inline
```

**Windows (PowerShell):**
```powershell
node detector.js --inline
```

## What the Tool Checks

The detector:
1. Fetches the latest compromised packages list from trusted sources
2. Retrieves your globally installed npm packages
3. Scans all dependencies up to 10 levels deep
4. Cross-references against known compromised packages
5. Reports any matches with severity levels

## Data Sources

The tool fetches compromised package lists from:
- [Gensec AI Repository](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector)
- [Tenable Security](https://github.com/tenable/shai-hulud-second-coming-affected-packages)

## If Compromised Packages Are Found

The tool will provide detailed remediation suggestions:

1. **Immediate Actions:**
   - Uninstall all compromised packages
   - Rotate all GitHub and npm tokens
   - Check for unauthorized repositories named "Sha1-Hulud: The Second Coming"
   - Review GitHub Actions for suspicious runners named "SHA1HULUD"

2. **Security Scan:**
   - Look for `.truffler-cache` directory
   - Check for files: `setup_bun.js`, `bun_environment.js`, `actionsSecrets.json`
   - Review `~/.ssh`, `~/.aws`, `~/.config` for unauthorized changes

3. **System Cleanup:**
   - Clear npm cache: `npm cache clean --force`

## Sample Output

### Clean System
```
✓ No compromised packages detected!
Your global npm packages appear to be clean.
```

### Compromised System
```
⚠ CRITICAL: Compromised packages detected!

1. malicious-package@1.0.0
   Severity: CRITICAL
   Path: /usr/local/lib/node_modules/malicious-package
```

## Exit Codes

- `0`: No compromised packages found
- `1`: Compromised packages detected
- `2`: Error during execution

## Requirements

- Node.js (any recent version)
- npm
- Internet connection (to fetch compromised package lists)

## Learn More

- [Wiz Investigation](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Unit 42 Report](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Tenable FAQ](https://www.tenable.com/blog/faq-about-sha1-hulud-2-0-the-second-coming-of-the-npm-supply-chain-campaign)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

## Disclaimer

This tool is provided as-is for security scanning purposes. Always verify results and follow your organization's security policies when handling potential security incidents.

---

**Stay safe and keep your dependencies secure! 🛡️**
