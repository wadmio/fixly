
**Fixly**  
*Real-Time Dependency Vulnerability Detection and Remediation Engine for Modern*  
*Web Applications*  
**INFO32606**  
**Prof. Tanbeer**  
**Warsame Abdi** 991681254 **- Jibril Abdi** 991697497 *- Riyadh Al-Hoyidy* 991640621  
**2026**\*-***02***-\***24**

## **1. Project Overview**

Our group is building Fixly, a cybersecurity tool designed to help developers detect vulnerable third-party dependencies in modern web applications. Fixly focuses on the Node.js / Next.js ecosystem, where developers often rely on many open-source packages from npm. While these packages help speed up development, they can also introduce security risks when they are outdated, indirectly vulnerable, or included through nested dependencies.

The original project proposal defined Fixly as a hybrid vulnerability detection system made up of two main components: a Visual Studio Code extension and a web-based repository scanner. The VS Code extension is intended to scan local dependency files such as package.json and package-lock.json directly inside the developer’s editor. The web platform allows a user to submit a public GitHub repository URL, extract dependency information, check it against known vulnerability sources, and generate a structured vulnerability report. This approach gives Fixly both real-time developer workflow support and broader repository-level scanning.

Fixly uses trusted public vulnerability databases such as OSV and NVD to identify known vulnerabilities, including CVEs, severity levels, CVSS scores, affected package versions, and remediation guidance when available. The system is designed to parse dependency data, compare installed versions against vulnerability records, and present the results in a clear format. This is important because existing tools like npm audit can provide useful information, but the output is often too technical, lengthy, or unclear for newer developers to act on quickly.

The main goal of Fixly is not only to detect vulnerable packages, but to make dependency security easier to understand and easier to act on. Instead of overwhelming users with raw vulnerability output, Fixly will present clear alerts, affected package names, installed versions, vulnerability IDs, severity ratings, short explanations, and recommended fixes when available. This makes the tool especially useful for students, junior developers, and teams building quickly with modern frameworks or AI-assisted coding tools.

## **2. Original Scope From Last Semester**

Last semester, our original scope for Fixly was to build a clear dependency vulnerability scanner that helps secure modern web applications by scanning the GitHub repositories used to build them. A key clarification from our professor was that Fixly should stay straightforward: we are not scanning live website links or random web pages. Instead, Fixly scans a project’s source repository, identifies dependency files, and checks those dependencies for known vulnerabilities.

Our original plan used a hybrid architecture with two main components: a VS Code extension and a web-based GitHub repository scanner. The VS Code extension was meant to scan local files such as package.json and package-lock.json while developers are working. The web scanner was meant to accept a public GitHub repository URL, extract dependency data, and generate a structured vulnerability report.

The technical scope focused on the Node.js / Next.js ecosystem, since these applications commonly rely on npm packages and nested dependencies. Fixly was planned to parse dependency manifests, extract package names and versions, and compare them against trusted vulnerability sources such as OSV and NVD. If a vulnerable package was found, the tool would show details such as the affected package, installed version, vulnerability ID, CVE information, severity level, CVSS score, summary, and possible remediation guidance.

To keep the project realistic, we intentionally excluded multi-language support, private repository scanning, CI/CD blocking, automatic package updates, enterprise authentication, and full commercial deployment. Our main goal was to prove the core workflow: scan a GitHub repository, extract dependency data, check vulnerability databases, match affected versions, and present the results clearly for developers building modern web applications.

## **3. What Was Completed Last Semester**

Last semester, our group completed the main planning, research, and early proof-of-concept work for Fixly. We finalized the original project proposal, defined the problem statement, researched existing dependency security tools, and confirmed that our product should focus on scanning the GitHub repository behind a modern web application, not scanning the live website itself.

We also selected the main technical direction for the project: a hybrid system made up of a VS Code extension and a web-based GitHub repository scanner. The original proposal outlined that Fixly would parse Node.js dependency files such as package.json and package-lock.json, query vulnerability databases such as OSV and NVD, and return vulnerability details including CVEs, CVSS scores, severity levels, and remediation guidance.

The biggest technical accomplishment from last semester was that we created a small working web scanner demo. This demo allowed us to use a GitHub repository as the scan target, extract dependency-related information, and test the basic vulnerability scanning workflow. We showed this early demo to the professor, which helped prove that the project idea was technically possible and gave us a stronger foundation for this semester.

By the end of last semester, we had completed:

* The original Fixly project proposal
* Problem statement and literature review
* Initial system architecture
* Node.js / Next.js scope decision
* OSV and NVD API research
* Dependency parsing workflow planning
* Early web scanner demo using a GitHub repository
* Initial vulnerability report/dashboard direction
* Team role planning and task distribution

Overall, last semester gave us a working foundation. This semester, our focus is to improve the demo, make the scanning logic more reliable, strengthen the GitHub repository workflow, and build the final project into a clean, presentable vulnerability detection tool.

## **4. Feedback Received and How We Addressed It**

Last semester, the main feedback we received was that Fixly needed to be very clear and straightforward in what it scans. Our professor clarified that the product should not be described as a tool that scans random website links or live web pages. Instead, Fixly should be explained as a tool that scans the GitHub repository used to build a modern web application, then checks the project’s dependency files for known vulnerabilities.

We addressed this by tightening the project scope and language. In the revised plan, we now clearly explain that Fixly scans source code repositories, not deployed websites. The web scanner accepts a public GitHub repository URL, looks for dependency manifests such as package.json and package-lock.json, extracts package names and versions, and checks them against vulnerability databases like OSV and NVD.

Another piece of feedback was that the project could become too broad if we tried to build every possible security feature. Our original proposal included both a VS Code extension and a web-based scanner, which is useful but also increases complexity. To address this, we are keeping the project focused on the Node.js / Next.js ecosystem, public GitHub repositories, dependency vulnerability detection, and clear remediation reporting.

We also addressed feedback by improving the project’s practical direction. Since we already created a small web scanner demo last semester, this semester we are not starting from zero. Our focus is to refine that demo, improve vulnerability matching accuracy, strengthen the repository scanning workflow, and make the final output easier for developers to understand. This keeps Fixly realistic, technical, and aligned with the professor’s expectations.

## **5. What Still Needs to Be Completed**

This semester, our group needs to turn the early Fixly web scanner demo into a stronger and more complete final project. Since we already proved the basic GitHub repository scanning workflow last semester, the next step is to improve reliability, accuracy, usability, and documentation.

The main work still left is to strengthen the GitHub repository scanner so it can consistently accept a public GitHub repo URL, locate dependency files such as package.json and package-lock.json, extract package names and versions, and check them against trusted vulnerability sources such as OSV and NVD. This includes improving error handling for repositories that are missing dependency files or have unsupported project structures.

We also still need to improve the vulnerability matching logic. Fixly needs to compare installed package versions against known vulnerable versions and return clear results, including the affected package, installed version, vulnerability ID, severity level, CVSS score when available, and remediation guidance. This connects directly to our original goal of giving developers clear vulnerability information instead of raw technical output.

The remaining work includes:

* Improving the existing web scanner demo
* Finalizing the GitHub repository structure
* Strengthening dependency parsing for Node.js projects, including basic handling of nested and transitive dependencies where feasible
* Improving OSV and/or NVD API integration
* Validating vulnerability matching accuracy
* Creating a cleaner vulnerability report/dashboard
* Adding better error handling and logging
* Building the VS Code extension
* Displaying vulnerability alerts inside VS Code
* Testing Fixly with sample vulnerable repositories
* Updating the README with setup instructions and project usage
* Preparing the final presentation and demo

Overall, the main goal this semester is to move Fixly from a basic proof of concept into a polished, understandable, and technically reliable vulnerability scanning tool for developers building modern web applications.

## **6. Final Deliverables**

By the end of this semester, our group plans to deliver a working and well-documented version of Fixly that clearly demonstrates the full dependency vulnerability scanning workflow. The final product will focus on scanning the GitHub repository behind a modern web application, extracting dependency data, checking for known vulnerabilities, and presenting the results in a clear developer-friendly format.

Our main final deliverables will include:

* Revised Project Plan Document  
A written project plan explaining what Fixly is, what was completed last semester, what feedback we received, what still needs to be completed, and how we plan to finish the project this semester.
* GitHub Repository  
A clean GitHub repository containing the project code, folder structure, documentation, and a clear README file.
* GitHub README  
A README that explains the project purpose, tech stack, setup instructions, usage steps, current status, team roles, risks, and final project scope.
* Web-Based GitHub Repository Scanner  
A working scanner that accepts a public GitHub repository URL, identifies Node.js dependency files, extracts package names and versions, and checks them against vulnerability databases such as OSV and/or NVD.
* VS Code Extension Prototype  
A prototype extension that can scan local Node.js dependency files such as package.json and package-lock.json and display vulnerability results inside the developer workflow.
* Structured Vulnerability Report  
A clear report showing affected package names, installed versions, vulnerability IDs, CVE details when available, severity levels, CVSS scores, short summaries, and remediation guidance.
* Final Demo and Presentation  
A final walkthrough showing how Fixly scans a GitHub repository, detects vulnerable dependencies, and displays results in a readable format for developers.

These deliverables align with our original project scope, which planned Fixly as a hybrid tool combining a VS Code extension with a web-based repository scanning platform for Node.js applications.

|Week|Focus|Key Milestones|Jibril Abdi|Warsame Abdi|Riyadh Al-Hoyidy|
|-|:-:|:-:|:-:|:-:|:-:|
|**Week 1**|**Revised Planning**|**Review previous scope, professor feedback, and rewrite project plan.**|**Project documentation and plan editing**|**Technical scope review and architecture check**|**Review API and scanner requirements**|
|**Week 2**|**GitHub Setup**|**Create/clean GitHub repo. Add README, folders, and basic project structure.**|**README setup and documentation layout**|**Repo structure and environment setup**|**OSV/NVD notes and API research update**|
|**Week 3**|**Demo Review**|**Review web scanner demo from last semester and list needed improvements.**|**Document current demo features**|**Test existing scanner workflow**|**CVE matching validation**|
|**Week 4**|**GitHub Input Flow**|**Improve public GitHub repository URL input and validation.**|**Write usage notes for repo scan flow**|**Build/improve GitHub URL handling**|**Research invalid repo and missing file cases**|
|**Week 5**|**Dependency Extraction**|**Extract package.json and package-lock.json from public repos.**|**Document supported files and limits**|**Implement dependency file retrieval**|**Test extraction                           on sample Node.js repos**|
|**Week 6**|**Dependency Parsing**|**Parse package names and installed versions from dependency files.**|**Explain parser logic in documentation**|**Build/refine parser logic**|**Validate package/version output**|
|**Week 7**|**API Integration**|**Connect parsed dependencies to OSV and/or NVD APIs.**|**Document API request/response flow**|**Implement vulnerability API calls**|**Research CVE, CVSS, severity, and affected version fields**|
|**Week  8**|**Vulnerability Matching**|**Match installed versions against known vulnerable versions.**|**Document matching logic clearly**|**Improve matching logic and reduce false results**|**Validate CVE matching accuracy**|
|**Week    9**|**Report Dashboard**|**Create structured vulnerability report/dashboard.**|**Write clear labels and report descriptions**|**Connect backend scan results to frontend**|**Format severity, CVE, and remediation output**|
|**Week 10**|**VS Code Extension**|**Build basic VS Code extension prototype for local scans.**|**Document extension setup steps**|**Connect extension command to scanner logic**|**Format alert messages and severity display**|
|**Week 11**|**Error Handling**|**Add clear errors for invalid repos, missing files, and failed API calls.**|**Document known limitations**|**Add backend error handling and logging**|**Test failure cases and unsupported repos**|
|**Week 12**|**Testing**|**Test Fixly using vulnerable and clean sample repositories.**|**Record test cases and results**|**Fix scanner and parser bu gs**|**Compare results with OSV/NVD and npm audit where useful**|
|**Week 13**|**Final Documentation**|**Finalize README, screenshots, project plan, and demo script.**|**Final report editing and README polish**|**Prepare technical demo walkthrough**|**Polish dashboard/report output**|
|**Week 14**|**Final Submission**|**Submit final deliverables and present Fixly proof of concept.**|**Submit final documentation**|**Lead technical demo**|**Explain API matching and report results**|

## **7. What risks, challenges, or blockers may affect the project**

Several risks could affect Fixly's development timeline and technical reliability this semester.

**OSV and NVD API Limitations:** Both the OSV and NVD APIs are public and rate-limited. If the team sends too many requests during testing or demo preparation, responses may be throttled or temporarily blocked. This could slow down development and produce inconsistent results during demos. To mitigate this, the team should implement response caching, add retry logic with delays, and avoid bulk API testing without throttling controls in place.

**Version Matching Accuracy:** Accurately comparing installed dependency versions against vulnerable version ranges is one of the more technically difficult parts of Fixly. Package versioning follows semantic versioning rules, but real-world package.json files often use range specifiers such as ^, \~, or \*, which must be interpreted correctly before any comparison can happen. Errors in this logic could produce false positives or missed vulnerabilities, which would undermine the tool's credibility. The team should validate matching logic against known-vulnerable packages and compare results against npm audit where possible.

**GitHub API Rate Limits and Repository Variability:** Fetching dependency files from public GitHub repositories relies on GitHub's API, which enforces hourly rate limits for unauthenticated requests. Beyond rate limits, public repositories vary widely in structure — some may not contain package.json or package-lock.json, may use monorepo structures, or may place dependency files in non-standard directories. The scanner must handle these cases gracefully with clear error messages rather than silent failures.

**VS Code Extension Complexity:** The VS Code extension is a significant technical undertaking that introduces a separate development environment, packaging process, and debugging workflow. Delays in core web scanner work could push extension development late into the semester, leaving insufficient time for testing and refinement. To reduce this risk, the team should begin extension scaffolding early and keep the initial scope minimal — focusing on on-demand scanning rather than complex real-time monitoring.

**Scope Creep:** As the project matures, it may be tempting to add features such as support for additional package ecosystems, private repository authentication, or CI/CD pipeline integration. While these would add value, they risk destabilizing the existing system if introduced too late. Any new feature proposals should be evaluated against the remaining timeline and only considered after core deliverables are stable.

**Team Coordination and Integration:** Because Fixly is a hybrid system with both a frontend and backend component, and because each team member owns different layers of the stack, integration points between the parser, API layer, frontend dashboard, and VS Code extension could become blockers if not tested early and often. The team should plan integration checkpoints at Weeks 9 and 12 specifically to catch mismatches before the final demo.

**Data Quality and False Results:** Vulnerability databases are not always complete or perfectly maintained. Some packages may have records in OSV but not NVD, or vice versa. Relying on a single database could cause Fixly to miss known vulnerabilities. Where feasible, the team should cross-reference both sources and clearly communicate in the UI when a result comes from one source versus both.

