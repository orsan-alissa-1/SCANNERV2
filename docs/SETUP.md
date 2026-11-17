# Environment and setup notes

This is an archive of an environment-dependent prototype. The source has been syntax-checked, but no end-to-end execution or scan has been performed for this release. The following inventory explains what would need to be reconstructed; it is not a tested installation procedure.

## Original environment assumptions

- Linux with Python, Nmap available on PATH, and SQLite.
- Python packages listed in `requirements.txt`; versions were not recorded in the supplied ZIP.
- A CVE database at `data/vulnerabilities.db`, containing a `cves` table with `cve_id`, `description`, `cvss_score`, `severity`, `vendor`, `product`, and `version` columns.
- A new `users.db` with a `users` table containing `id`, `username`, `password_hash`, and `role`. Passwords use bcrypt. The supplied application does not initialise this schema or provide a working first-user bootstrap flow.
- A MITRE ATT&CK JSON dataset at the hardcoded path `/root/cti/enterprise-attack/enterprise-attack.json`. The application opens it at import time; it is absent from the submitted ZIP and this archive.
- Ollama listening at `http://localhost:11434`, with the `llama3` model installed, for AI guidance.
- An external HackTricks mirror under `hacktricks-offline/book.hacktricks.wiki` for local reference links. The mirror is not redistributed.

## Reconstruction blockers

1. Restore or configure the MITRE dataset path before importing the application.
2. Provision the CVE schema and data. The original importer targets an NVD JSON 1.1 feed for 2024; its current availability has not been verified. It is not a guaranteed working bootstrap method.
3. Create a fresh user schema and a bcrypt-hashed account through a separate setup process. Existing account data was deliberately excluded.
4. Address the security issues in `KNOWN_LIMITATIONS.md` before serving the application. The original `wsgi.py` enables debugging and listens on all network interfaces.
5. Provision the model and reference content separately if needed. Chart scripts currently load from CDNs and must be made local for full offline operation.

The original `install.sh` is excluded: it upgrades operating-system packages, changes system Python with `--break-system-packages`, installs unrelated PDF tooling, and omits Python packages directly imported by the application. Use an isolated environment for any reconstruction work.

## Excluded resources

Existing user records, CVE database, scan outputs, logs, Python caches, the copied HackTricks site, and the original installer are not part of this public source archive. The source implementation is otherwise preserved byte-for-byte.
