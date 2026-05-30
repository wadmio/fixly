# Fixly – Scan Result Validation Notes
**Author:** Riyadh Al-Hoyidy  
**Date:** 2026-05-29  
**Phase:** Phase 2 – OSV/NVD Validation & CVE Matching Checks

---

## Repositories Tested

| Repository | Packages Scanned | Critical | High | Medium | Low | Total Vulns |
|---|---|---|---|---|---|---|
| OWASP/NodeGoat | 36 | 1 | 10 | 5 | 1 | 17 |
| juice-shop/juice-shop | 129 | 2 | 12 | 12 | 0 | 26 |
| wadmio/fixly | 11 | 0 | 7 | 4 | 2 | 13 |

---

## What Is Working Correctly

- **Severity badges** display with correct colour coding: Critical (red), High (orange), Medium (yellow), Low (blue)
- **CVE and GHSA IDs** both appear correctly in the ID column
- **Fix versions** are shown with a → arrow for most vulnerabilities
- **Results are sorted by severity** (Critical first, then High, Medium, Low) — matches expected behaviour
- **Package name and installed version** display correctly on each row
- **Scan timestamp and package count** display correctly at the top of the results page
- **OSV API integration** is confirmed working — all three scans returned accurate, real vulnerability data

---

## Issues Found

### 1. Missing Fix Version (No Fallback Text)
- **Affected:** `marasdb` v0.6.11 in the juice-shop scan
- **Issue:** The Fix column is blank when no safe upgrade version is available in the OSV record
- **Expected behaviour:** Should display "No fix available" or similar instead of an empty cell
- **Impact:** Users may not know whether a fix exists or whether the data simply failed to load

### 2. CVSS Numeric Score Not Displayed
- **Affected:** All scan results
- **Issue:** Only the severity label (e.g. High, Medium) is shown — the numeric CVSS score (e.g. 9.8, 7.5) is not displayed
- **Expected behaviour:** Per Phase 2 plan, severity display should include the CVSS score alongside the label
- **Impact:** Developers cannot assess relative risk between two vulnerabilities with the same severity label

### 3. Fixly Repo Has 13 Active Vulnerabilities
- **Affected:** `wadmio/fixly` — `next` v16.2.3
- **Issue:** All 13 vulnerabilities are in the Next.js dependency. Fix version shown is 15.5.16
- **Recommended action:** Run `npm update next` or pin Next.js to a safe version in package.json

---

## Recommendations for Phase 2

| Priority | Item |
|---|---|
| High | Add fallback text ("No fix available") when Fix version is missing |
| High | Display CVSS numeric score alongside severity badge |
| Medium | Add a tooltip or expandable row showing full CVE description |
| Medium | Group multiple vulnerabilities from the same package into one row |
| Low | Add a "copy CVE ID" button for quick reference |

---

## Validation Method

All scans were run locally using the Fixly web scanner at `localhost:3000`.  
Vulnerability data is sourced from the OSV API (`api.osv.dev/v1`).  
Results were compared visually against known-vulnerable repositories to confirm accuracy.  
No false positives were identified in the tested repositories.
