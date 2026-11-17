# Known limitations

These observations come from source inspection, not a completed penetration test.

## Finding accuracy

- CVE matching uses SQL substring matching on service names and simplified version strings, with at most five matches per service. It does not evaluate complete product applicability or affected-version ranges.
- Severity is sorted as text in report queries, rather than by a numeric severity rank.
- The importer retains a single CPE entry per CVE and does not require that entry to be marked vulnerable. This can misrepresent affected products.
- Service-to-MITRE mappings are static reference associations, not observed attack detections.
- Device risk scores are based on open-service counts. Exploitability labels use description keywords, not exploitation validation.
- The AI route samples ten random CVEs rather than supplying verified matches for the scanned host. Its generated commands and guidance require independent review.

## Application security

- Flask uses a fixed placeholder session secret.
- The AI route has no login check.
- Report paths are joined to user-controlled filenames without a containment check, creating path traversal risks.
- AI output is returned as HTML without sanitisation.
- State-changing forms have no implemented CSRF protection, and login has no rate limiting.
- Administrative access depends on the username `admin` rather than the stored role.
- The development entry point enables debug mode and listens on `0.0.0.0`.
- The automatically started static reference server does not explicitly bind to loopback.

## Portability and offline operation

- Importing the app requires an absent MITRE JSON file at an absolute Linux path.
- User-table creation and first-account setup are missing from the distributed code.
- AI functionality requires a separately provisioned Ollama service and model.
- Chart libraries load from CDNs. Full offline operation is not demonstrated by this source alone.
- The CVE updater makes an online request and targets the original JSON 1.1 feed format.
- No dependency lockfile or automated test suite was supplied.

These limitations are retained and documented to represent the capstone faithfully. This repository does not claim they have been fixed.
