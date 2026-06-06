"""
AWS Security Compliance Checker
================================
Automates security compliance checks for AWS accounts.
Checks: S3 public access, IAM MFA enforcement, Security Group open access.

Author: Wilson Wan
"""

import boto3
import json
import datetime
from botocore.exceptions import ClientError, NoCredentialsError


# ============================================================
#  UTILITY HELPERS
# ============================================================

class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════╗
║       AWS Security Compliance Checker            ║
║       v1.0 — Built with boto3                    ║
╚══════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)


def print_section(title):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}{Colors.END}")


def status_icon(is_pass):
    return f"{Colors.GREEN}✅ PASS{Colors.END}" if is_pass else f"{Colors.RED}❌ FAIL{Colors.END}"


# ============================================================
#  CHECK 1 — S3 PUBLIC ACCESS
# ============================================================

def check_s3_public_access():
    """
    Check all S3 buckets for public access risks.

    Checks performed:
    - Public Access Block configuration
    - Bucket ACL grants to 'AllUsers' or 'AuthenticatedUsers'
    - Bucket Policy allowing wildcard (*) principals
    """
    print_section("CHECK 1: S3 Bucket Public Access")

    s3 = boto3.client("s3")
    results = []

    try:
        buckets = s3.list_buckets()["Buckets"]
    except NoCredentialsError:
        print(f"{Colors.RED}  ERROR: AWS credentials not configured.{Colors.END}")
        return []

    if not buckets:
        print(f"  {Colors.YELLOW}No S3 buckets found.{Colors.END}")
        return []

    for bucket in buckets:
        name = bucket["Name"]
        findings = []

        # --- 1a. Check Public Access Block ---
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab["PublicAccessBlockConfiguration"]
            all_blocked = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                findings.append("Public Access Block is NOT fully enabled")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append("No Public Access Block configured")
            else:
                findings.append(f"Could not check Public Access Block: {e}")

        # --- 1b. Check Bucket ACL ---
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri:
                    findings.append("ACL grants access to AllUsers (public)")
                if "AuthenticatedUsers" in uri:
                    findings.append("ACL grants access to AuthenticatedUsers")
        except ClientError:
            pass  # Permission denied — skip gracefully

        # --- 1c. Check Bucket Policy ---
        try:
            policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect = stmt.get("Effect", "")
                if principal == "*" and effect == "Allow":
                    findings.append("Bucket policy allows wildcard (*) principal")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                pass  # Other error — skip gracefully

        is_pass = len(findings) == 0
        results.append({
            "resource": name,
            "check": "S3 Public Access",
            "status": "PASS" if is_pass else "FAIL",
            "findings": findings if findings else ["All public access properly blocked"],
        })

        icon = status_icon(is_pass)
        print(f"\n  Bucket: {Colors.BOLD}{name}{Colors.END}  →  {icon}")
        for f in findings if findings else ["All public access properly blocked"]:
            print(f"    • {f}")

    return results


# ============================================================
#  CHECK 2 — IAM MFA ENFORCEMENT
# ============================================================

def check_iam_mfa():
    """
    Check all IAM users for MFA device enrollment.

    Flags any user with console access but no MFA device attached.
    Also checks the root account MFA status via account summary.
    """
    print_section("CHECK 2: IAM User MFA Status")

    iam = boto3.client("iam")
    results = []

    # --- 2a. Check root account MFA ---
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        root_mfa = summary.get("AccountMFAEnabled", 0)
        is_pass = root_mfa == 1
        results.append({
            "resource": "Root Account",
            "check": "IAM MFA",
            "status": "PASS" if is_pass else "FAIL",
            "findings": ["MFA enabled"] if is_pass else ["ROOT ACCOUNT MFA IS NOT ENABLED — CRITICAL"],
        })
        print(f"\n  {'Root Account':<30} →  {status_icon(is_pass)}")
        if not is_pass:
            print(f"    {Colors.RED}• ROOT ACCOUNT MFA IS NOT ENABLED — CRITICAL{Colors.END}")
    except ClientError as e:
        print(f"  {Colors.YELLOW}Could not check root MFA: {e}{Colors.END}")

    # --- 2b. Check each IAM user ---
    try:
        users = iam.list_users()["Users"]
    except ClientError:
        print(f"  {Colors.RED}ERROR: Cannot list IAM users.{Colors.END}")
        return results

    for user in users:
        username = user["UserName"]

        # Check if user has console access (login profile)
        has_console = False
        try:
            iam.get_login_profile(UserName=username)
            has_console = True
        except ClientError:
            has_console = False

        # Check MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        has_mfa = len(mfa_devices) > 0

        if has_console and not has_mfa:
            status = "FAIL"
            msg = "Console access enabled but NO MFA device"
        elif has_console and has_mfa:
            status = "PASS"
            msg = "Console access with MFA enabled"
        else:
            status = "PASS"
            msg = "Programmatic access only (no console login)"

        is_pass = status == "PASS"
        results.append({
            "resource": username,
            "check": "IAM MFA",
            "status": status,
            "findings": [msg],
        })
        print(f"  {username:<30} →  {status_icon(is_pass)}")
        print(f"    • {msg}")

    return results


# ============================================================
#  CHECK 3 — SECURITY GROUP OPEN ACCESS
# ============================================================

def check_security_groups():
    """
    Check all Security Groups for overly permissive ingress rules.

    Flags rules that allow inbound traffic from 0.0.0.0/0 or ::/0,
    with special attention to high-risk ports (22, 3389, 3306, 5432, 1433, 27017).
    """
    print_section("CHECK 3: Security Group Open Access (0.0.0.0/0)")

    ec2 = boto3.client("ec2")
    results = []

    HIGH_RISK_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
    }

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        print(f"  {Colors.RED}ERROR: {e}{Colors.END}")
        return []

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "N/A")
        vpc_id = sg.get("VpcId", "N/A")
        findings = []

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "N/A")

            open_cidrs = []
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_cidrs.append("0.0.0.0/0")
            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    open_cidrs.append("::/0")

            if not open_cidrs:
                continue

            # All traffic rule (-1 protocol)
            if protocol == "-1":
                findings.append(
                    f"⚠️  ALL TRAFFIC open to {', '.join(open_cidrs)} — CRITICAL"
                )
                continue

            # Check specific port ranges
            for port, svc in HIGH_RISK_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append(
                        f"Port {port} ({svc}) open to {', '.join(open_cidrs)}"
                    )

            # Wide port range warning
            port_range_size = to_port - from_port
            if port_range_size > 100:
                findings.append(
                    f"Wide port range {from_port}-{to_port}/{protocol} "
                    f"open to {', '.join(open_cidrs)}"
                )
            elif not any(from_port <= p <= to_port for p in HIGH_RISK_PORTS):
                findings.append(
                    f"Port {from_port}-{to_port}/{protocol} "
                    f"open to {', '.join(open_cidrs)}"
                )

        is_pass = len(findings) == 0
        results.append({
            "resource": f"{sg_id} ({sg_name})",
            "check": "Security Group Open Access",
            "status": "PASS" if is_pass else "FAIL",
            "findings": findings if findings else ["No unrestricted inbound rules"],
            "vpc_id": vpc_id,
        })

        icon = status_icon(is_pass)
        print(f"\n  SG: {Colors.BOLD}{sg_id}{Colors.END} ({sg_name}) [VPC: {vpc_id}]  →  {icon}")
        for f in findings if findings else ["No unrestricted inbound rules"]:
            marker = Colors.RED if "CRITICAL" in f else ""
            end = Colors.END if marker else ""
            print(f"    {marker}• {f}{end}")

    return results


# ============================================================
#  REPORT GENERATION
# ============================================================

def generate_report(all_results):
    """Generate a summary report and optionally save to JSON."""
    print_section("COMPLIANCE SUMMARY REPORT")

    total = len(all_results)
    passed = sum(1 for r in all_results if r["status"] == "PASS")
    failed = total - passed
    score = (passed / total * 100) if total > 0 else 0

    # Score color
    if score >= 90:
        color = Colors.GREEN
    elif score >= 70:
        color = Colors.YELLOW
    else:
        color = Colors.RED

    print(f"""
  Total Checks:  {total}
  {Colors.GREEN}Passed:        {passed}{Colors.END}
  {Colors.RED}Failed:        {failed}{Colors.END}
  Compliance:    {color}{Colors.BOLD}{score:.1f}%{Colors.END}
    """)

    # List failures
    if failed > 0:
        print(f"  {Colors.RED}{Colors.BOLD}Failed Resources:{Colors.END}")
        for r in all_results:
            if r["status"] == "FAIL":
                print(f"    ✗ [{r['check']}] {r['resource']}")
                for f in r["findings"]:
                    print(f"      → {f}")

    # Save JSON report
    report = {
        "report_date": datetime.datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "compliance_score": round(score, 1),
        },
        "results": all_results,
    }

    filename = f"report_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  {Colors.GREEN}Report saved → {filename}{Colors.END}")

    return report


# ============================================================
#  MAIN
# ============================================================

def main():
    print_banner()

    # Verify AWS credentials
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        acct = identity["Account"]
        arn = identity["Arn"]
        print(f"  {Colors.GREEN}Authenticated{Colors.END}")
        print(f"  Account:  {acct}")
        print(f"  Identity: {arn}\n")
    except NoCredentialsError:
        print(f"\n  {Colors.RED}ERROR: No AWS credentials found.{Colors.END}")
        print("  Configure via: aws configure, env vars, or IAM role.\n")
        return

    # Run all checks
    all_results = []
    all_results.extend(check_s3_public_access())
    all_results.extend(check_iam_mfa())
    all_results.extend(check_security_groups())

    # Generate report
    generate_report(all_results)


if __name__ == "__main__":
    main()