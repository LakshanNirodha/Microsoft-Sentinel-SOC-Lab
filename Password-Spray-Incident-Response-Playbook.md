# Password Spray Attack — Incident Response Playbook

| | |
|---|---|
| **Playbook owner** | Lakshan Nirodha |
| **Environment** | Microsoft Sentinel SOC Lab (SentinelLabRG, Southeast Asia region) |
| **Applies to** | SIEM alerts matching brute-force / password spray patterns against Azure AD sign-ins |
| **MITRE ATT&CK mapping** | T1110.003 (Brute Force: Password Spraying) |
| **Status** | Living document - update after every new incident or lesson learned |
| **Last updated** | August 2026 |

---

## 1. Preparation

*Goal: be ready before an alert ever fires.*

- Custom analytics rule deployed in Sentinel, mapped to MITRE ATT&CK **T1110.003**
- Four KQL queries built and saved in the workspace to detect repeated failed sign-ins across many accounts from the same source
- Roles clarified: as SOC analyst, I am responsible for triage, investigation, and documentation of any alert this rule generates
- Reference: VirusTotal account ready for quick IP/domain reputation checks during investigation

## 2. Detection and Analysis

*Goal: confirm the alert is real, and understand its scale.*

**Steps:**

1. Open the triggered incident in Sentinel (e.g. Incident 482)
2. Run the saved KQL queries against `SigninLogs` to confirm the pattern: many failed logins, across many different user accounts, from a small number of source IPs, in a short time window
3. Check how many accounts are affected - in the real incident this was **57 Melbourne Polytechnic student accounts**
4. Identify the source IP addresses involved
5. Run each source IP through **VirusTotal** to check reputation/threat intelligence (real incident: attacker IPs traced to Colombia, France, and Morocco)
6. Classify the incident: **True Positive** or **False Positive**, based on evidence gathered

> **Real example finding:** confirmed True Positive - a live password spray attack against 57 student accounts, from three IPs with poor VirusTotal reputations.

## 3. Containment

*Goal: stop it from getting worse right now.*

- Identify any accounts among the 57 that show a successful login after repeated failures (these are the highest priority — a successful spray hit)
- Recommend temporary account lockout or forced password reset for any affected/successful accounts
- Recommend blocking the identified malicious source IPs at the firewall/conditional access policy level
- Notify IT/identity team so they can action the lockouts (in a real organization, not just a lab)

## 4. Eradication and Recovery

*Goal: remove the threat completely, restore normal state.*

- Confirm no attacker sessions remain active (check for any active tokens/sessions tied to compromised accounts)
- Force password resets for any accounts with a successful sign-in from a malicious IP
- Re-enable accounts only after reset is confirmed
- Verify MFA is enforced on all affected accounts going forward, since password spray specifically targets accounts without MFA

## 5. Post-Incident Activity

*Goal: document it and learn from it.*

- Document the incident: what happened, how many accounts, which IPs, how it was detected, what was done
- Record the **root cause**: accounts without MFA enforcement being reachable via password spray
- Recommend policy improvement: enforce MFA org-wide, tighten conditional access sign-in risk policies
- Publish sanitized findings for portfolio/learning purposes (already done — see GitHub repo below)

## 6. Coordination

*Goal: report and share properly.*

- Report incident summary to relevant stakeholders (in a real SOC: IT manager, security lead)
- If required by policy/compliance, report to the appropriate authority depending on data affected and jurisdiction
- Share the detection rule and KQL logic with the wider security team so others can reuse it

---

## Reference

- Full technical writeup and KQL queries: [github.com/LakshanNirodha/Microsoft-Sentinel-SOC-Lab](https://github.com/LakshanNirodha/Microsoft-Sentinel-SOC-Lab)
- MITRE ATT&CK technique: [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
