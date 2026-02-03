# Verification (Anti-Impersonation)

This project intentionally avoids common high-risk distribution patterns.

## What we do NOT ship
- No VS Code extension
- No one-line installers (curl|sh)
- No marketplace installers

## If you publish releases
Recommended:
1) Publish SHA256 checksums for release artifacts
2) Provide a clear “official channels” list
3) Encourage users to verify checksums before running

## How to verify SHA256 (examples)
macOS/Linux:
```bash
shasum -a 256 <file>
