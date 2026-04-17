# Azure Application Gateway SSL Certificate Expiry Notification

**Azure Automation Runbook-Based SSL Certificate Health Monitoring**

**Developed by the DevOps Team @ Movate**

| Role | Name | Contact |
|---|---|---|
| Team Lead | Vignesh Nagachalavelavan | Vignesh.Nagachalavelavan01@movate.com |
| Engineer | Shiv Kumar Verma | ShivKumar.Verma@movate.com |
| DevOps Engineers | Movate DevOps Team | — |

📄 **Full Documentation (PDF):** [ssl-certificate-expiry-notification-documentation.pdf](docs/ssl-certificate-expiry-notification-documentation.pdf)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Business Problem](#2-business-problem)
3. [Solution Overview](#3-solution-overview)
4. [High-Level Architecture (HLD)](#4-high-level-architecture-hld)
5. [Low-Level Design (LLD)](#5-low-level-design-lld)
6. [Key Technical Highlights](#6-key-technical-highlights)
7. [Certificate Status Classification](#7-certificate-status-classification)
8. [Technology Stack](#8-technology-stack)
9. [Code Structure](#9-code-structure)
10. [Configuration](#10-configuration)
11. [Deployment](#11-deployment)
12. [IAM & Security Model](#12-iam--security-model)
13. [Email & Excel Output](#13-email--excel-output)
14. [Advantages](#14-advantages)
15. [Limitations](#15-limitations)
16. [Use Cases](#16-use-cases)
17. [Operational Runbook](#17-operational-runbook)
18. [Final Outcome](#18-final-outcome)

---

## 1. Executive Summary

This solution is an **Azure Automation Python 3 Runbook** that proactively monitors SSL/TLS certificate expiry across all Azure Application Gateways in one or more subscriptions. It runs on a daily schedule, scans every certificate attached to a live TLS listener, and delivers a colour-coded health report — an HTML email plus a full Excel attachment — via **Azure Communication Services (ACS) Email**.

The runbook is entirely **read-only**: it never creates, modifies, or deletes any Azure resource.

### Key Outcomes

| Outcome | Description |
|---|---|
| **Proactive** | Catches certificates before they expire — not after |
| **Multi-Subscription** | Single runbook covers all Application Gateways across the entire Azure estate |
| **Read-Only** | No risk of accidental resource modification; safe to run with Reader-only RBAC |
| **Auditable** | Full Excel report delivered after every run for compliance and governance |

> **Zero-touch monitoring**: once deployed, the runbook runs daily on a schedule with no manual intervention required.

---

## 2. Business Problem

| Challenge | Impact |
|---|---|
| Manual certificate tracking | Human error, missed expiry deadlines |
| No centralised visibility | Poor governance across multiple subscriptions and gateways |
| Expired certificates | Application outages, browser security warnings, broken HTTPS |
| Reactive monitoring | Certificates discovered as expired only after end-user impact |

---

## 3. Solution Overview

An **Azure Automation Python 3 Runbook** executes on a daily schedule to:

1. **Authenticate** to Azure using a Service Principal (`ClientSecretCredential`)
2. **Discover** every Application Gateway across all configured subscriptions
3. **Fetch** full gateway details including `publicCertData` for each SSL certificate
4. **Parse** certificate expiry dates from PKCS#7/DER/PEM encoded certificate data
5. **Classify** each certificate: Expired / Critical / Warning / OK / Unknown
6. **Report** results via a colour-coded HTML email and a full Excel attachment

### Certificate Status Thresholds

| Status | Condition |
|---|---|
| **Expired** | Days remaining < 0 |
| **Critical** | 0 – 7 days remaining |
| **Warning** | 8 – 14 days remaining (configurable) |
| **OK** | > 14 days remaining |
| **Unknown** | Expiry could not be parsed (e.g. Key Vault-backed certificates) |

---

## 4. High-Level Architecture (HLD)

### Component Overview

| Component | Role |
|---|---|
| Azure Automation Account | Hosts and schedules the Python 3 runbook |
| Azure Automation Schedule | Triggers the runbook daily (e.g. 06:00 UTC) |
| Service Principal | Identity used by the runbook to read Application Gateway resources |
| Application Gateways | Target resources — SSL certificate data is read from each gateway |
| Azure Communication Services | Delivers the HTML email and Excel attachment to recipients |

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Azure Subscription(s)                          │
│                                                                             │
│  ┌──────────────────────────┐    ┌──────────────────────────────────────┐  │
│  │  Azure Automation Account │    │      Application Gateways            │  │
│  │  ┌─────────────────────┐ │    │  ┌────────────┐  ┌────────────────┐  │  │
│  │  │  Python 3 Runbook   │─┼────┼─►│  Gateway 1 │  │   Gateway N    │  │  │
│  │  │  (main.py)          │ │    │  │  SSL Certs │  │   SSL Certs    │  │  │
│  │  └─────────────────────┘ │    │  └────────────┘  └────────────────┘  │  │
│  │  ┌─────────────────────┐ │    └──────────────────────────────────────┘  │
│  │  │  Schedule (daily)   │ │                                               │
│  │  └─────────────────────┘ │    ┌──────────────────────────────────────┐  │
│  │  ┌─────────────────────┐ │    │  Azure Communication Services (ACS)  │  │
│  │  │  Variables / Creds  │ │    │  Email                               │  │
│  │  │  - AzureSPCredential│─┼────┼─►  Send HTML + Excel to recipients   │  │
│  │  │  - ACS_CONNECTION.. │ │    └──────────────────────────────────────┘  │
│  │  └─────────────────────┘ │                                               │
│  └──────────────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────────────┘

Authentication Flow:
  Automation Account → ClientSecretCredential (Service Principal)
                    → Azure RBAC: Reader on each subscription
```

---

## 5. Low-Level Design (LLD)

### Execution Flow

```
Trigger → Authenticate → Discover → Parse → Classify → Report → Send
```

### Detailed Phase Breakdown

```
Azure Automation Schedule (daily trigger)
        │
        ▼
┌──────────────────────────────────────────────────┐
│  PHASE 1 — AUTHENTICATE                          │
│  Read AzureSPCredential from Automation Account  │
│  Build ClientSecretCredential                    │
│  Instantiate NetworkManagementClient per sub     │
└──────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────┐
│  PHASE 2 — DISCOVER & SCAN                       │
│  For each subscription in AG_SUBSCRIPTION_IDS:  │
│    list_all() Application Gateways               │
│    get() each gateway (for full publicCertData)  │
│    Filter to certs attached to TLS listeners     │
└──────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────┐
│  PHASE 3 — PARSE & CLASSIFY                      │
│  Attempt 4-stage fallback decode:                │
│    1. PKCS#7 container                           │
│    2. Bare DER certificate                       │
│    3. PEM-in-base64 encoded                      │
│    4. Raw PEM string                             │
│  Classify: Expired / Critical / Warning / OK     │
│  Mark as Unknown if expiry cannot be parsed      │
└──────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────┐
│  PHASE 4 — BUILD REPORTS                         │
│  Excel: all certificates, sorted by days left    │
│  HTML email: top-5 per status + metrics card     │
└──────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────┐
│  PHASE 5 — SEND                                  │
│  Send HTML email + Excel via ACS Email           │
│  DRY_RUN=true → write to disk (local testing)   │
└──────────────────────────────────────────────────┘
```

---

## 6. Key Technical Highlights

### Resilient Certificate Parsing

- Four-stage fallback decode chain handles every certificate format Azure may return
- PKCS#7 container → bare DER → PEM-in-base64 → raw PEM string
- Unknown status clearly flagged for Key Vault-backed certificates

### Listener-Aware Scanning

- Only certificates attached to active TLS listeners are reported
- Orphaned / unused certificates are intentionally skipped to reduce noise

### Read-Only Safety

- Zero write operations against any Azure resource
- Safe to run with minimal RBAC permissions (`Reader` role only)
- `DRY_RUN=true` mode writes output to disk without sending any email

### Dual Output Format

- **HTML email**: at-a-glance metrics card with colour-coded per-status tables
- **Excel attachment**: full 13-column report with auto-filter and row-level colour coding

---

## 7. Certificate Status Classification

| Status | Days Remaining | Row Colour | Description |
|---|---|---|---|
| **Expired** | < 0 | Dark Red | Certificate has already expired |
| **Critical** | 0 – 7 | Orange-Red | Requires immediate attention |
| **Warning** | 8 – 14 | Amber | Action required within threshold |
| **OK** | > 14 | Green | Certificate healthy |
| **Unknown** | N/A | Grey | Expiry cannot be parsed (Key Vault-backed) |

The Warning threshold is configurable via the `AG_ALERT_DAYS` Automation variable (default: `14`).

---

## 8. Technology Stack

| Layer | Technology |
|---|---|
| Compute | Azure Automation Account (Python 3 Runbook) |
| Scheduler | Azure Automation Schedule |
| Authentication | Azure Service Principal (`ClientSecretCredential`) |
| Resource Discovery | Azure Management SDK — `azure-mgmt-network` |
| Certificate Parsing | Python `cryptography` library (PKCS#7, X.509, DER, PEM) |
| Email | Azure Communication Services (ACS) Email |
| Reporting | `openpyxl` (Excel), HTML (inline email template) |
| Language | Python 3.8 (Azure Automation runtime) |

---

## 9. Code Structure

```
ssl-certificate-notifier/
├── main.py                       # Runbook / main script (all logic)
├── requirements.txt              # Python dependencies
├── DOCUMENTATION.md              # Full technical documentation
└── .env                          # Local secrets (never commit — git-ignored)
```

### main.py — Section Breakdown

| Section | Responsibility |
|---|---|
| **Section 1 — Configuration** | Resolves all settings from Automation variables, env vars, or defaults. `DRY_RUN=true` writes outputs to disk. |
| **Section 2 — Certificate Scanning** | Read-only Azure API calls. Lists/gets Application Gateways, parses cert data, builds flat records. |
| **Section 3 — Excel Report** | Builds colour-coded `.xlsx` workbook using `openpyxl`. Rows sorted by days remaining. |
| **Section 4 — HTML Email** | Builds responsive HTML email with per-status tables and metrics card. |
| **Section 5 — ACS Email** | Sends HTML + Excel attachment via `azure-communication-email`. |
| **Section 6 — Entry Point** | `main()` orchestrates sections 1–5. |

---

## 10. Configuration

### Azure Automation Account Assets

Configure these in the Automation Account before running the runbook in production:

| Asset Type | Name | Value |
|---|---|---|
| Credential | `AzureSPCredential` | Username = Client ID, Password = Client Secret |
| Variable (String) | `AZURE_TENANT_ID` | Azure AD tenant ID |
| Variable (String) | `AG_SUBSCRIPTION_IDS` | Comma-separated subscription IDs |
| Variable (String) | `AG_ALERT_DAYS` | Days before expiry for Warning threshold (default: `14`) |
| Variable (String) | `ACS_CONNECTION_STRING` | ACS Email resource connection string |
| Variable (String) | `ACS_SENDER_ADDRESS` | Verified ACS sender address |
| Variable (String) | `AG_NOTIFICATION_TO` | Comma-separated recipient email addresses |

### Local Development (`.env` file)

For local runs, create a `.env` file with the following keys (**never commit real secrets**):

```dotenv
AZURE_CLIENT_ID=<service-principal-client-id>
AZURE_CLIENT_SECRET=<service-principal-client-secret>
AZURE_TENANT_ID=<tenant-id>
AG_SUBSCRIPTION_IDS=<sub-id-1>,<sub-id-2>
AG_ALERT_DAYS=14
DRY_RUN=false
ACS_CONNECTION_STRING=<acs-connection-string>
ACS_SENDER_ADDRESS=DoNotReply@<domain>.azurecomm.net
AG_NOTIFICATION_TO=team@example.com
```

Set `DRY_RUN=true` to skip the ACS call and write the Excel and HTML files to disk locally for inspection.

---

## 11. Deployment

### Prerequisites

1. An Azure Automation Account with Python 3 runbook support
2. A Service Principal with `Reader` role on all target subscriptions
3. An Azure Communication Services resource with a verified sender domain
4. Required Python packages installed in the Automation Account

### Step-by-Step Deployment

#### 1. Install Required Packages in the Automation Account

Upload the following packages to the Automation Account (Python 3 packages):

```
azure-identity
azure-mgmt-network
azure-mgmt-subscription
azure-communication-email
cryptography
openpyxl
```

#### 2. Import the Runbook

Upload `main.py` as a **Python 3** runbook in the Automation Account.

#### 3. Configure Automation Account Assets

Add all variables and credentials listed in the [Configuration](#10-configuration) section.

#### 4. Create a Schedule

Link a daily schedule to the runbook (recommended: 06:00 UTC, before business hours).

#### 5. Test Locally

```bash
pip install -r requirements.txt
DRY_RUN=true python main.py       # writes .xlsx + .html to disk, no email sent
```

#### 6. Run Manually in Automation Account

Trigger the runbook manually from the Azure Portal to validate end-to-end connectivity before relying on the schedule.

---

## 12. IAM & Security Model

### Authentication

| Layer | Identity | Permissions |
|---|---|---|
| Automation Account | Managed Identity / Run As Account | Access to Automation variables and credentials |
| Application Gateway scanning | Service Principal (`AzureSPCredential`) | `Reader` role on each target subscription |
| Email delivery | ACS connection string | Authenticated ACS Email sender |

### Required RBAC

The Service Principal needs **Reader** role on each target subscription (or at minimum on the resource groups containing Application Gateways). No write permissions are required.

### Security Guidelines

- Store all secrets in **Azure Automation encrypted variables / credentials** — never hardcode in the runbook
- The `.env` file is for local development only — add it to `.gitignore` and never commit to source control
- The Service Principal should be scoped to minimum required subscriptions with `Reader` role only

---

## 13. Email & Excel Output

### HTML Email Structure

| Section | Description |
|---|---|
| **Metrics card** | "At a glance" summary — total certs scanned, alert badge counts, report timestamp |
| **Expired table** | Top-5 expired certificates (dark red theme) |
| **Critical table** | Top-5 certificates expiring within 7 days (orange-red theme) |
| **Warning table** | Top-5 certificates expiring within 14 days (amber theme) |
| **Unknown table** | All certificates whose expiry could not be determined |
| **Legend + footer** | Status legend and automated disclaimer |

### Excel Attachment Columns

`Gateway Name` · `Location` · `Resource Group` · `Subscription Name` · `Subscription ID` · `Certificate Name` · `Listeners` · `Subject` · `Issuer` · `Expiry Date (UTC)` · `Days Remaining` · `Status` · `Key Vault Ref`

Each row is colour-coded by status: red (Expired), orange-red (Critical), amber (Warning), green (OK), grey (Unknown).

---

## 14. Advantages

### Proactive Monitoring

- **Daily schedule** — catches certificates before they expire, not after
- **Configurable warning threshold** — adjust lead time to match your renewal process
- **Multi-subscription** — single runbook covers the entire Azure estate from one place

### Safety

- **Read-only** — zero risk of accidental resource modification
- **Minimal RBAC** — `Reader` role only; no elevated permissions required
- **Dry-run mode** — full local testing without any email or Azure API side effects

### Resilience

- **4-stage certificate parsing** — handles all certificate formats Azure may return
- **Listener-aware** — only scans certificates actively attached to TLS listeners
- **Unknown classification** — explicitly handles Key Vault-backed certificates rather than silently failing

### Reporting

- **Dual output** — HTML email for at-a-glance visibility, Excel for audit records
- **Colour-coded** — immediate visual prioritisation by status severity
- **Sorted by urgency** — soonest-expiring certificates always appear first

---

## 15. Limitations

| Limitation | Impact |
|---|---|
| **Key Vault-backed certificates** | Azure does not expose `publicCertData` for Key Vault certs — these appear as "Unknown expiry" and must be monitored separately |
| **No auto-renewal** | Notification only — the runbook does not renew, replace, or rotate any certificate |
| **Python 3.8 runtime** | Must remain compatible with the Azure Automation Python 3.8 runtime; some newer library features may require version pinning |
| **No historical trend** | Each run is independent; there is no built-in storage of past results or trending data |
| **Application Gateway only** | Does not scan certificates on Front Door, API Management, App Service, or other Azure services |
| **ACS Email single-region** | The ACS connection string is tied to a specific ACS resource region |
| **Top-5 per status in email** | HTML email shows only the top-5 most urgent per status; full data is in the Excel attachment |

---

## 16. Use Cases

- **Enterprise SSL governance** — enforce certificate visibility across all Application Gateways in an Azure estate from a single automated runbook
- **Proactive incident prevention** — eliminate SSL-related outages caused by unnoticed certificate expiry
- **Compliance requirements** — supports SOC 2, ISO 27001, and other frameworks requiring certificate lifecycle monitoring and audit evidence
- **Multi-subscription Azure environments** — centralised visibility across dev, staging, and production subscriptions without per-subscription tooling

---

## 17. Operational Runbook

### Trigger the Runbook Manually

Navigate to the Automation Account in the Azure Portal → **Runbooks** → select the runbook → **Start**.

### Test Locally

```bash
pip install -r requirements.txt
DRY_RUN=true python main.py
```

Output files (`ssl_certificate_report_<date>.xlsx` and `email_output.html`) will be written to the current directory.

### Change the Warning Threshold

Update the `AG_ALERT_DAYS` variable in the Automation Account (no runbook redeployment required).

### Add a New Subscription

Add the subscription ID to the `AG_SUBSCRIPTION_IDS` Automation variable (comma-separated) and grant the Service Principal `Reader` role on the new subscription.

### Add or Change Email Recipients

Update the `AG_NOTIFICATION_TO` Automation variable (no runbook redeployment required).

### Check Execution History

Navigate to the Automation Account → **Jobs** to view past executions, output logs, and error details.

---

## 18. Final Outcome

This solution delivers a production-grade, enterprise-ready SSL certificate monitoring system:

| Capability | Detail |
|---|---|
| **Proactive expiry monitoring** | Daily scheduled scan catches expiring certificates before they cause outages |
| **Multi-subscription coverage** | Single runbook covers all Application Gateways across the entire Azure estate |
| **Resilient certificate parsing** | Four-stage fallback chain handles every certificate format Azure returns |
| **Enterprise-grade reporting** | Colour-coded HTML email + full Excel attachment delivered to stakeholders after every run |
| **Read-only safety** | Zero risk of resource modification; minimal RBAC permissions required |
| **Compliance-ready** | Audit trail via daily Excel reports suitable for SOC 2, ISO 27001, and similar frameworks |
