import json
import logging
import sys
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tabulate import tabulate

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


class CloudIAMAuditor:

  def __init__(self, config_path="config.json"):
    self.config = self._load_config(config_path)
    try:
      self.iam_client = boto3.client("iam")
      self.s3_client = boto3.client("s3")
    except (BotoCoreError, ClientError) as e:
      logger.error(f"Failed to initialize AWS clients: {e}")
      sys.exit(1)

  def _load_config(self, path):
    try:
      with open(path, "r") as f:
        return json.load(f)
    except Exception as e:
      logger.warning(
          f"Could not load config {path}, using default settings. Error: {e}"
      )
      return {"max_password_age_days": 90, "require_mfa": True}

  def audit_iam_users(self):
    logger.info("Initiating Enterprise IAM User & Credential Audit...")
    report = []
    try:
      paginator = self.iam_client.get_paginator("list_users")
      for page in paginator.paginate():
        for user in page["Users"]:
          username = user["UserName"]
          created_date = str(user.get("CreateDate", "Unknown"))
          mfa_enabled = False
          try:
            mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
            if mfa_devices.get("MFADevices"):
              mfa_enabled = True
          except ClientError:
            pass
          is_admin = self._check_admin_privileges(username)
          status = "COMPLIANT"
          risk_level = "LOW"
          if not mfa_enabled:
            status = "MFA Not Enabled"
            risk_level = "HIGH"
          if is_admin:
            risk_level = "CRITICAL"
            status += " | Admin Privileges Detected"
          report.append([
              username,
              created_date,
              "Yes" if mfa_enabled else "No",
              "Yes" if is_admin else "No",
              risk_level,
              status,
          ])
    except ClientError as e:
      logger.error(f"Error listing IAM users: {e}")
    return report

  def _check_admin_privileges(self, username):
    try:
      policies = self.iam_client.list_attached_user_policies(UserName=username)
      for p in policies.get("AttachedPolicies", []):
        if "AdministratorAccess" in p.get("PolicyName", ""):
          return True
    except ClientError:
      pass
    return False

  def run_audit(self):
    print("\n" + "=" * 80)
    print(" ENTERPRISE CLOUD IAM & SECURITY COMPLIANCE AUDITOR ")
    print("=" * 80 + "\n")
    user_audit_results = self.audit_iam_users()
    headers = [
        "Username",
        "Created Date",
        "MFA Active",
        "Admin Access",
        "Risk Level",
        "Audit Findings",
    ]
    print(tabulate(user_audit_results, headers=headers, tablefmt="fancy_grid"))
    print("\n[+] Audit execution completed successfully.\n")


if __name__ == "__main__":
  auditor = CloudIAMAuditor()
  auditor.run_audit()
