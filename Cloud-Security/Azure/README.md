# Cybersecurity Automation Scripts
## Cloud Security
### Azure

### Azure Entra Privileged Review Automation
This script connects to Microsoft Graph via MSAL and exports:
- Active privileged role assignments (including PIM-activated)
- Eligible role assignments (PIM eligibility)

**Location:** `Cloud-Security/entra_privilege_review.py`

**Usage:**
```bash
pip install msal requests pandas python-dateutil
python Cloud-Security/entra_privilege_review.py

