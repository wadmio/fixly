# Fixly

## Real-Time Dependency Vulnerability Detection and Remediation Engine

Fixly is a cybersecurity tool designed to help developers detect vulnerable third-party dependencies in modern web applications.

Fixly does **not** scan live websites or random web links. Instead, Fixly scans the **GitHub repository used to build a modern web application**, identifies dependency files, and checks those dependencies for known vulnerabilities.

The project focuses on the **Node.js / Next.js ecosystem**, where applications commonly rely on npm packages and nested dependencies.

---

## Project Purpose

Modern web applications often depend on many open-source packages. These packages help developers build faster, but they can also introduce security risks if they are outdated or contain known vulnerabilities.

Fixly helps reduce this risk by scanning project dependency files such as:

- `package.json`
- `package-lock.json`

The tool checks dependency information against trusted vulnerability databases such as:

- OSV
- NVD

Fixly then presents vulnerability results in a clear and developer-friendly format.

---

## What Fixly Is Building

Fixly is planned as a hybrid cybersecurity tool with two main components:

### 1. Web-Based GitHub Repository Scanner

The web scanner allows a user to submit a **public GitHub repository URL**. Fixly then scans the repository, locates supported dependency files, extracts package names and versions, and checks them for known vulnerabilities.

The report may include:

- Affected package name
- Installed package version
- Vulnerability ID
- CVE information when available
- Severity level
- CVSS score when available
- Short vulnerability summary
- Suggested remediation guidance when available

### 2. VS Code Extension Prototype

The VS Code extension is planned to support developers directly inside their coding environment. It will scan local Node.js dependency files and display vulnerability alerts inside the developer workflow.

The extension is intended to support:

- Local dependency scanning
- Manual scan command
- Vulnerability alerts
- Clear severity output
- Basic remediation guidance

---

## Current Project Status

This project is currently in development as part of our capstone project.

Completed so far:

- Original project proposal
- Problem statement
- Literature review
- Initial system architecture
- Node.js / Next.js project scope
- OSV and NVD API research
- Dependency scanning workflow planning
- Small web scanner demo using a GitHub repository
- Demo shown to the professor last semester
- Revised project plan for this semester

In progress:

- Improving the existing web scanner demo
- Strengthening GitHub repository scanning
- Improving dependency file extraction
- Improving dependency parsing
- Connecting scan results to OSV and/or NVD
- Improving vulnerability matching accuracy
- Creating a clearer vulnerability report/dashboard
- Building or improving the VS Code extension prototype
- Adding better documentation and setup instructions

---

## Tech Stack

Planned or used technologies:

- JavaScript / TypeScript
- Node.js
- Next.js or React
- VS Code Extension API
- OSV API
- NVD API
- GitHub API
- Git / GitHub

---

## Project Scope

### Supported in Current Scope

Fixly is focused on:

- Node.js projects
- Next.js projects
- Public GitHub repositories
- `package.json`
- `package-lock.json`
- OSV and/or NVD vulnerability lookups
- Structured vulnerability reports
- Basic VS Code extension prototype

### Not Included in Current Scope

To keep the project realistic, Fixly will not currently support:

- Scanning live deployed websites
- Scanning random website URLs
- Private GitHub repository scanning
- Multi-language package ecosystems
- CI/CD pipeline blocking
- Automatic package updates
- Enterprise authentication
- Full commercial deployment

---

## How Fixly Works

The basic Fixly workflow is:

1. User submits a public GitHub repository URL.
2. Fixly retrieves supported dependency files from the repository.
3. Fixly extracts package names and installed versions.
4. Fixly sends dependency data to OSV and/or NVD.
5. Fixly checks whether installed package versions match known vulnerable versions.
6. Fixly returns a structured vulnerability report.
7. The developer reviews severity, CVE details, and remediation guidance.

---

## Planned Final Deliverables

By the end of the semester, the project will include:

- Revised project plan document
- GitHub repository with clear structure
- Complete README documentation
- Web-based GitHub repository scanner
- VS Code extension prototype
- Vulnerability API integration
- Structured vulnerability report/dashboard
- Final demo and presentation

---

## Team Members

- Jibril Abdi
- Warsame Abdi
- Riyadh Al-Hoyidy

---

## Team Responsibilities

### Jibril Abdi

- Project documentation
- README writing
- Report editing
- Parser documentation support
- Meeting preparation

### Warsame Abdi

- Technical architecture
- Backend scanner logic
- API integration testing
- Repository scanning workflow
- Technical demo walkthrough

### Riyadh Al-Hoyidy

- OSV/NVD API research
- GitHub repository parsing research
- CVE matching validation
- Alert formatting
- Report formatting and UI polish

---

## Risks and Challenges

Potential risks include:

- OSV or NVD API rate limits
- Missing or incomplete vulnerability metadata
- Incorrect dependency parsing
- False positives or missed vulnerabilities
- Unsupported repository structures
- Missing `package.json` or `package-lock.json` files
- VS Code extension complexity
- Time constraints
- Scope creep

To reduce these risks, Fixly is limited to public GitHub repositories and Node.js dependency files for the current version.

---

## Installation

Setup instructions will be updated as development continues.

Planned local setup:

```bash
git clone <repository-url>
cd fixly
npm install
npm run dev
```

---

## Usage

Planned usage for the web scanner:

1. Start the local development server.
2. Open the Fixly web interface.
3. Enter a public GitHub repository URL.
4. Run the scan.
5. Review the vulnerability report.

Planned usage for the VS Code extension:

1. Open a Node.js project in VS Code.
2. Run the Fixly scan command.
3. Review dependency vulnerability alerts.
4. Apply recommended fixes where available.

---

## Project Goal

The goal of Fixly is to help developers secure modern web applications by identifying vulnerable dependencies earlier in the development process.

Fixly is designed to make vulnerability information easier to understand by presenting clear results instead of overwhelming developers with raw technical output.

---

## License

This project is for academic and educational purposes.
