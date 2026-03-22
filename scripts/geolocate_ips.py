#!/usr/bin/env python3
"""
Enhanced IP Geolocation Tool

Uses IPinfo.io API to geolocate IP addresses and provide detailed location
and organizational information. Supports bulk processing from files.

Security Features:
- API token from environment variable
- Input validation
- Rate limiting
- Error handling

Usage:
    python3 geolocate_ips.py                    # Interactive mode
    python3 geolocate_ips.py --file ips.txt     # Process from file
    python3 geolocate_ips.py --ip 8.8.8.8       # Single IP
"""

import requests
import time
import json
import csv
import os
import sys
import argparse
import socket
import re
import subprocess
from pathlib import Path
import ipaddress
from typing import List, Dict, Optional

# Add utils to path
sys.path.append(str(Path(__file__).parent / "utils"))

# Known cloud provider patterns (matched against IPinfo.io Org field)
CLOUD_PROVIDER_PATTERNS = {
    "Amazon": "AWS",
    "AWS": "AWS",
    "Microsoft": "Azure",
    "Azure": "Azure",
    "Google": "GCP",
    "Cloudflare": "Cloudflare",
    "Akamai": "Akamai",
    "Fastly": "Fastly",
    "DigitalOcean": "DigitalOcean",
    "Linode": "Linode/Akamai",
    "OVH": "OVH",
    "Hetzner": "Hetzner",
    "Vultr": "Vultr",
    "Oracle": "Oracle Cloud",
    "Alibaba": "Alibaba Cloud",
}

# Known CDN providers (geo results show edge node, not origin)
CDN_INDICATORS = {"cloudfront", "cloudflare", "akamai", "fastly", "edgecast",
                  "stackpath", "incapsula", "sucuri", "cdn"}

# Common subdomains that may bypass CDN and point to origin
ORIGIN_SUBDOMAINS = [
    "direct", "origin", "origin-www", "mail", "smtp", "mx",
    "ftp", "cpanel", "webmail", "autodiscover", "vpn",
    "api", "dev", "staging", "admin", "portal",
]


class IPGeolocationTool:
    def __init__(self, api_token: Optional[str] = None):
        """Initialize the geolocation tool."""
        # Set up paths first (needed for config file access)
        self.project_root = Path(__file__).parent.parent
        self.output_dir = self.project_root / "output"
        self.input_dir = self.project_root / "input"
        self.data_dir = self.project_root / "data"
        
        # Ensure directories exist
        self.output_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize API settings (after paths are set up)
        self.api_token = api_token or self._get_api_token()
        self.base_url = "https://ipinfo.io"
        self.rate_limit_delay = 1  # seconds between requests
    
    def _get_api_token(self) -> str:
        """Get API token from environment or prompt user."""
        # Try environment variable first
        token = os.getenv('IPINFO_API_TOKEN')
        if token:
            return token
        
        # Try config file
        config_file = self.project_root / "config" / "api_config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    return config.get('ipinfo_api_token', '')
            except Exception:
                pass
        
        # Prompt user
        print("⚠️  No API token found in environment variable IPINFO_API_TOKEN")
        print("💡 You can get a free token at: https://ipinfo.io/signup")
        token = input("Enter your IPinfo.io API token: ").strip()
        
        # Offer to save it
        save = input("Save token to config file? (y/n): ").lower() == 'y'
        if save:
            self._save_api_token(token)
        
        return token
    
    def _save_api_token(self, token: str):
        """Save API token to config file."""
        config_dir = self.project_root / "config"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "api_config.json"
        config = {"ipinfo_api_token": token}
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Token saved to {config_file}")
        print("💡 You can also set the environment variable: export IPINFO_API_TOKEN=your_token")
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def is_domain(self, entry: str) -> bool:
        """Check if an entry looks like a domain name (not an IP)."""
        if self.validate_ip(entry):
            return False
        # Must have at least one dot, no spaces, valid hostname characters
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'
        return bool(re.match(pattern, entry))

    def resolve_domain(self, domain: str, quiet: bool = False) -> List[str]:
        """Resolve a domain name to its IP addresses (A and AAAA records)."""
        try:
            results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            # Extract unique IPs from results
            ips = list(dict.fromkeys(result[4][0] for result in results))
            return ips
        except socket.gaierror as e:
            if not quiet:
                print(f"❌ DNS resolution failed for {domain}: {e}")
            return []
        except socket.timeout:
            if not quiet:
                print(f"❌ DNS resolution timed out for {domain}")
            return []

    def identify_cloud_provider(self, org: str) -> str:
        """Identify cloud provider from the IPinfo.io Org field."""
        if not org or org == "N/A":
            return "N/A"
        org_lower = org.lower()
        for pattern, provider in CLOUD_PROVIDER_PATTERNS.items():
            if pattern.lower() in org_lower:
                return provider
        return "N/A"

    def geolocate_domain(self, domain: str) -> List[Dict]:
        """Resolve a domain and geolocate all its IPs."""
        ips = self.resolve_domain(domain)
        if not ips:
            return [{"Domain": domain, "IP": "N/A", "Input_Type": "domain",
                      "Cloud_Provider": "N/A", "Error": "DNS resolution failed"}]

        print(f"🔍 {domain} resolved to {len(ips)} IP(s): {', '.join(ips)}")

        # Check CNAME chain for CDN indicators
        cname_chain = self._get_cname_chain(domain)

        results = []
        cdn_detected = False
        for i, ip in enumerate(ips):
            result = self.geolocate_ip(ip)
            result["Domain"] = domain
            result["Input_Type"] = "domain"
            result["Cloud_Provider"] = self.identify_cloud_provider(result.get("Org", ""))
            if self._is_cdn_edge(result.get("Org", ""), cname_chain):
                cdn_detected = True
            results.append(result)

            # Rate limiting between lookups (except last)
            if i < len(ips) - 1:
                time.sleep(self.rate_limit_delay)

        # Suggest --deep if CDN detected
        if cdn_detected:
            print(f"\n⚠️  CDN detected for {domain} — these IPs are likely edge nodes near you, not the origin server.")
            print(f"💡 Use --deep for a full investigation: --domain {domain} --deep")

        return results

    def _run_dig(self, domain: str, record_type: str) -> List[str]:
        """Run dig for a specific record type and return parsed answers."""
        try:
            result = subprocess.run(
                ["dig", "+short", domain, record_type],
                capture_output=True, text=True, timeout=10
            )
            lines = [l.strip().rstrip('.') for l in result.stdout.strip().split('\n') if l.strip()]
            return lines
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _get_cname_chain(self, domain: str) -> List[str]:
        """Follow the full CNAME chain for a domain."""
        chain = []
        current = domain
        seen = set()
        for _ in range(10):  # max depth to prevent loops
            cnames = self._run_dig(current, "CNAME")
            if not cnames or current in seen:
                break
            seen.add(current)
            current = cnames[0]
            chain.append(current)
        return chain

    def _parse_spf_ips(self, txt_records: List[str]) -> List[str]:
        """Extract IP addresses and ranges from SPF TXT records."""
        ips = []
        for record in txt_records:
            if 'v=spf1' not in record.lower():
                continue
            # Find ip4: and ip6: directives
            for match in re.finditer(r'ip[46]:([^\s]+)', record, re.IGNORECASE):
                ip_val = match.group(1)
                # Strip CIDR notation to get base IP for geolocation
                base_ip = ip_val.split('/')[0]
                if self.validate_ip(base_ip):
                    ips.append(base_ip)
            # Find include: directives (note them but don't recurse)
            for match in re.finditer(r'include:([^\s]+)', record, re.IGNORECASE):
                ips.append(f"(SPF include: {match.group(1)})")
        return ips

    def _is_cdn_edge(self, org: str, cname_chain: List[str]) -> bool:
        """Check if the result is likely a CDN edge node."""
        # Check org field
        if org:
            org_lower = org.lower()
            for indicator in CDN_INDICATORS:
                if indicator in org_lower:
                    return True
        # Check CNAME chain for CDN patterns
        for cname in cname_chain:
            cname_lower = cname.lower()
            for indicator in CDN_INDICATORS:
                if indicator in cname_lower:
                    return True
        return False

    def deep_investigate_domain(self, domain: str) -> Dict:
        """
        Deep DNS investigation to find origin infrastructure behind CDN.

        Returns a report dict with:
        - CNAME chain (reveals CDN setup)
        - MX records (mail servers often on origin)
        - SPF/TXT IPs (reveal real server IPs)
        - Origin subdomain probes (direct., origin., mail., etc.)
        - Geolocation of all discovered origin IPs
        """
        print(f"\n{'='*60}")
        print(f"🔬 Deep investigation: {domain}")
        print(f"{'='*60}")

        report = {
            "domain": domain,
            "cname_chain": [],
            "cdn_detected": False,
            "cdn_provider": "N/A",
            "mx_records": [],
            "spf_ips": [],
            "origin_subdomains": [],
            "origin_ips": [],  # IPs believed to be actual origin
            "all_results": [],  # Full geo results for all discovered IPs
        }

        # 1. CNAME chain
        print(f"\n📋 CNAME Chain:")
        chain = self._get_cname_chain(domain)
        report["cname_chain"] = chain
        if chain:
            for i, cname in enumerate(chain):
                prefix = "  └─" if i == len(chain) - 1 else "  ├─"
                print(f"{prefix} {cname}")
            if self._is_cdn_edge("", chain):
                cdn_name = "Unknown CDN"
                for cname in chain:
                    for indicator in CDN_INDICATORS:
                        if indicator in cname.lower():
                            cdn_name = indicator.title()
                            break
                report["cdn_detected"] = True
                report["cdn_provider"] = cdn_name
                print(f"  ⚠️  CDN detected: {cdn_name} — A record IPs are edge nodes, NOT origin")
        else:
            print(f"  (no CNAME — domain resolves directly)")

        # 2. A record IPs (standard resolution)
        print(f"\n📍 A Record IPs (what DNS returns):")
        a_ips = self.resolve_domain(domain)
        for ip in a_ips:
            result = self.geolocate_ip(ip)
            result["Domain"] = domain
            result["Input_Type"] = "A-record"
            result["Cloud_Provider"] = self.identify_cloud_provider(result.get("Org", ""))
            is_cdn = self._is_cdn_edge(result.get("Org", ""), chain)
            result["Is_CDN_Edge"] = "Yes" if is_cdn else "No"
            report["all_results"].append(result)

            cdn_warn = " ⚠️ CDN edge" if is_cdn else ""
            cloud = result.get('Cloud_Provider', 'N/A')
            cloud_tag = f" [{cloud}]" if cloud != "N/A" else ""
            print(f"  {ip}: {result.get('City', '?')}, {result.get('Country', '?')} ({result.get('Org', '?')}){cloud_tag}{cdn_warn}")
            time.sleep(self.rate_limit_delay)

        # 3. MX records
        print(f"\n📧 MX Records (mail servers — often on origin infra):")
        mx_records = self._run_dig(domain, "MX")
        if mx_records:
            for mx in mx_records:
                # MX records have priority prefix like "10 mail.example.com"
                parts = mx.split()
                mx_host = parts[-1] if parts else mx
                report["mx_records"].append(mx_host)
                print(f"  {mx}")

                # Resolve and geolocate MX host
                mx_ips = self.resolve_domain(mx_host)
                for ip in mx_ips[:2]:  # Limit to first 2 IPs per MX
                    result = self.geolocate_ip(ip)
                    result["Domain"] = f"{domain} (MX: {mx_host})"
                    result["Input_Type"] = "MX-record"
                    result["Cloud_Provider"] = self.identify_cloud_provider(result.get("Org", ""))
                    result["Is_CDN_Edge"] = "No"
                    report["all_results"].append(result)

                    cloud = result.get('Cloud_Provider', 'N/A')
                    cloud_tag = f" [{cloud}]" if cloud != "N/A" else ""
                    print(f"    → {ip}: {result.get('City', '?')}, {result.get('Country', '?')} ({result.get('Org', '?')}){cloud_tag}")

                    if not self._is_cdn_edge(result.get("Org", ""), []):
                        report["origin_ips"].append(ip)
                    time.sleep(self.rate_limit_delay)
        else:
            print(f"  (no MX records)")

        # 4. SPF/TXT records
        print(f"\n📝 SPF Record (reveals allowed sending IPs):")
        txt_records = self._run_dig(domain, "TXT")
        spf_ips = self._parse_spf_ips(txt_records)
        report["spf_ips"] = spf_ips
        if spf_ips:
            for entry in spf_ips:
                if entry.startswith("(SPF include:"):
                    print(f"  {entry}")
                elif self.validate_ip(entry):
                    result = self.geolocate_ip(entry)
                    result["Domain"] = f"{domain} (SPF)"
                    result["Input_Type"] = "SPF-record"
                    result["Cloud_Provider"] = self.identify_cloud_provider(result.get("Org", ""))
                    result["Is_CDN_Edge"] = "No"
                    report["all_results"].append(result)
                    report["origin_ips"].append(entry)

                    cloud = result.get('Cloud_Provider', 'N/A')
                    cloud_tag = f" [{cloud}]" if cloud != "N/A" else ""
                    print(f"  {entry}: {result.get('City', '?')}, {result.get('Country', '?')} ({result.get('Org', '?')}){cloud_tag}")
                    time.sleep(self.rate_limit_delay)
        else:
            print(f"  (no SPF record found)")

        # 5. Origin subdomain probing
        print(f"\n🔎 Origin Subdomain Probes:")
        found_any = False
        for sub in ORIGIN_SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            sub_ips = self.resolve_domain(subdomain, quiet=True)
            if sub_ips:
                # Only report if IPs differ from the main A records
                unique_ips = [ip for ip in sub_ips if ip not in a_ips]
                if unique_ips:
                    found_any = True
                    report["origin_subdomains"].append({"subdomain": subdomain, "ips": unique_ips})
                    for ip in unique_ips[:2]:  # Limit per subdomain
                        result = self.geolocate_ip(ip)
                        result["Domain"] = f"{domain} (sub: {sub})"
                        result["Input_Type"] = "origin-probe"
                        result["Cloud_Provider"] = self.identify_cloud_provider(result.get("Org", ""))
                        result["Is_CDN_Edge"] = "No"
                        report["all_results"].append(result)
                        report["origin_ips"].append(ip)

                        cloud = result.get('Cloud_Provider', 'N/A')
                        cloud_tag = f" [{cloud}]" if cloud != "N/A" else ""
                        print(f"  ✅ {subdomain} → {ip}: {result.get('City', '?')}, {result.get('Country', '?')} ({result.get('Org', '?')}){cloud_tag}")
                        time.sleep(self.rate_limit_delay)
        if not found_any:
            print(f"  (no unique origin IPs found via subdomain probes)")

        # 6. Summary
        print(f"\n{'='*60}")
        print(f"📊 Deep Investigation Summary: {domain}")
        print(f"{'='*60}")
        if report["cdn_detected"]:
            print(f"  CDN: {report['cdn_provider']} (A record IPs are edge nodes)")
        else:
            print(f"  CDN: Not detected")

        unique_origins = list(dict.fromkeys(report["origin_ips"]))
        if unique_origins:
            print(f"  Likely origin IPs: {', '.join(unique_origins)}")
        else:
            print(f"  Origin IPs: Could not determine (all IPs may be CDN edges)")
        print(f"  Total IPs discovered: {len(report['all_results'])}")
        print()

        return report

    def geolocate_ip(self, ip: str) -> Dict:
        """Geolocate a single IP address."""
        if not self.validate_ip(ip):
            # Keep invalid IPs in output with original data
            return {"IP": ip}

        url = f"{self.base_url}/{ip}/json"
        params = {"token": self.api_token} if self.api_token else {}

        try:
            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()

                # Check if this is an error response
                if "error" in data:
                    return {"IP": ip, "Error": f"API Error: {data['error']['message']}"}

                return {
                    "IP": ip,
                    "City": data.get("city", "N/A"),
                    "Region": data.get("region", "N/A"),
                    "Country": data.get("country", "N/A"),
                    "Country_Name": data.get("country_name", "N/A"),
                    "Org": data.get("org", "N/A"),
                    "Location": data.get("loc", "N/A"),
                    "Timezone": data.get("timezone", "N/A"),
                    "Postal": data.get("postal", "N/A"),
                    "ASN": data.get("asn", {}).get("asn", "N/A") if isinstance(data.get("asn"), dict) else "N/A",
                    "ISP": data.get("asn", {}).get("name", "N/A") if isinstance(data.get("asn"), dict) else data.get("org", "N/A")
                }
            elif response.status_code == 429:
                return {"IP": ip, "Error": "Rate limit exceeded - try again later"}
            elif response.status_code == 401:
                return {"IP": ip, "Error": "Invalid API token"}
            else:
                return {"IP": ip, "Error": f"HTTP {response.status_code}"}

        except requests.exceptions.Timeout:
            return {"IP": ip, "Error": "Request timeout"}
        except requests.exceptions.RequestException as e:
            return {"IP": ip, "Error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"IP": ip, "Error": f"Unexpected error: {str(e)}"}
    
    def process_ip_list(self, entries: List[str], show_progress: bool = True) -> List[Dict]:
        """Process a list of IP addresses and/or domain names (auto-detected)."""
        results = []
        total = len(entries)

        if show_progress:
            print(f"🌍 Processing {total} entries...\n")

        for i, entry in enumerate(entries, 1):
            entry_stripped = entry.strip()

            if self.validate_ip(entry_stripped):
                # IP address path
                if show_progress:
                    print(f"[{i}/{total}] Processing IP: {entry_stripped}...")

                result = self.geolocate_ip(entry_stripped)
                result["Domain"] = "N/A"
                result["Input_Type"] = "ip"
                result["Cloud_Provider"] = self.identify_cloud_provider(result.get("Org", ""))
                results.append(result)

                if "Error" in result:
                    print(f"❌ {entry_stripped}: {result['Error']}")
                else:
                    cloud = result['Cloud_Provider']
                    cloud_tag = f" [{cloud}]" if cloud != "N/A" else ""
                    print(f"✅ {entry_stripped}: {result['City']}, {result['Region']}, {result['Country']} ({result['Org']}){cloud_tag}")

            elif self.is_domain(entry_stripped):
                # Domain name path
                if show_progress:
                    print(f"[{i}/{total}] Resolving domain: {entry_stripped}...")

                domain_results = self.geolocate_domain(entry_stripped)
                results.extend(domain_results)

                for r in domain_results:
                    if "Error" in r:
                        print(f"❌ {entry_stripped} → {r.get('IP', 'N/A')}: {r['Error']}")
                    else:
                        cloud = r.get('Cloud_Provider', 'N/A')
                        cloud_tag = f" [{cloud}]" if cloud != "N/A" else ""
                        print(f"✅ {entry_stripped} → {r['IP']}: {r['City']}, {r['Region']}, {r['Country']} ({r['Org']}){cloud_tag}")

            else:
                # Invalid entry — keep in output
                print(f"⚠️  {entry_stripped}: Not a valid IP or domain - kept in output")
                results.append({"IP": entry_stripped, "Domain": "N/A", "Input_Type": "unknown"})

            # Rate limiting between entries (except last)
            if i < total:
                time.sleep(self.rate_limit_delay)

        return results
    
    def load_ips_from_file(self, filepath: str) -> List[str]:
        """Load IP addresses from a text file (one per line)."""
        file_path = Path(filepath)

        # Try relative to input directory if not absolute
        if not file_path.is_absolute():
            file_path = self.input_dir / filepath

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        # Keep all entries (including invalid IPs) to maintain order
        return ips
    
    def save_results_csv(self, results: List[Dict], filename: str = None) -> str:
        """Save results to CSV file."""
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"ip_geolocation_{timestamp}.csv"

        # Support absolute paths
        candidate = Path(filename)
        if candidate.is_absolute():
            output_path = candidate.with_suffix('.csv')
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            if not filename.endswith('.csv'):
                filename = f"{filename}.csv"
            output_path = self.output_dir / filename
        
        if results:
            # Get all possible keys from results
            all_keys = set()
            for result in results:
                all_keys.update(result.keys())
            
            fieldnames = ["Domain", "IP", "Input_Type", "Cloud_Provider", "Is_CDN_Edge", "City", "Region", "Country", "Country_Name", "Org", "ISP", "ASN", "Location", "Timezone", "Postal", "Error"]
            # Add any additional keys we might have missed
            fieldnames.extend([key for key in all_keys if key not in fieldnames])
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        
        return str(output_path)
    
    def save_results_json(self, results: List[Dict], filename: str = None) -> str:
        """Save results to JSON file."""
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"ip_geolocation_{timestamp}.json"

        # Support absolute paths
        candidate = Path(filename)
        if candidate.is_absolute():
            output_path = candidate.with_suffix('.json')
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            if not filename.endswith('.json'):
                filename = f"{filename}.json"
            output_path = self.output_dir / filename
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def interactive_mode(self):
        """Interactive mode for entering IPs or domains manually."""
        print("🌍 IP & Domain Geolocation Tool - Interactive Mode")
        print("=" * 50)
        print("Enter IP addresses or domain names (press Enter twice to finish):")

        entries = []
        while True:
            entry = input("IP or domain: ").strip()
            if not entry:
                break

            if self.validate_ip(entry):
                entries.append(entry)
                print(f"✅ Added IP: {entry}")
            elif self.is_domain(entry):
                entries.append(entry)
                print(f"✅ Added domain: {entry}")
            else:
                print(f"❌ Not a valid IP or domain: {entry}")

        if not entries:
            print("No valid entries provided.")
            return []

        return self.process_ip_list(entries)

def main():
    """Main function with command line interface."""
    parser = argparse.ArgumentParser(description="IP & Domain Geolocation Tool using IPinfo.io API")
    parser.add_argument("--ip", help="Single IP address to geolocate")
    parser.add_argument("--domain", help="Single domain name to resolve and geolocate")
    parser.add_argument("--file", help="File containing IPs and/or domains (one per line, auto-detected)")
    parser.add_argument("--output", help="Output path or filename (absolute path or relative to output/; default: auto-generated)")
    parser.add_argument("--format", choices=["csv", "json", "both"], default="csv", 
                       help="Output format (default: csv)")
    parser.add_argument("--deep", action="store_true",
                       help="Deep investigation: trace CNAME chain, MX, SPF, origin subdomains (use with --domain)")
    parser.add_argument("--token", help="IPinfo.io API token (overrides env var)")
    
    args = parser.parse_args()
    
    # Initialize tool
    try:
        tool = IPGeolocationTool(api_token=args.token)
    except Exception as e:
        print(f"❌ Error initializing tool: {e}")
        sys.exit(1)
    
    # Determine IPs to process
    results = []
    
    if args.ip:
        # Single IP mode
        print(f"🌍 Geolocating single IP: {args.ip}")
        result = tool.geolocate_ip(args.ip)
        result["Domain"] = "N/A"
        result["Input_Type"] = "ip"
        result["Cloud_Provider"] = tool.identify_cloud_provider(result.get("Org", ""))
        results = [result]

    elif args.domain:
        if args.deep:
            # Deep investigation mode
            report = tool.deep_investigate_domain(args.domain)
            results = report["all_results"]
        else:
            # Standard domain mode
            print(f"🌍 Resolving and geolocating domain: {args.domain}")
            results = tool.geolocate_domain(args.domain)

    elif args.file:
        # File mode (auto-detects IPs vs domains)
        try:
            entries = tool.load_ips_from_file(args.file)
            if not entries:
                print("❌ No entries found in file.")
                sys.exit(1)
            results = tool.process_ip_list(entries)
        except FileNotFoundError as e:
            print(f"❌ {e}")
            sys.exit(1)

    else:
        # Interactive mode
        results = tool.interactive_mode()
    
    # Save results
    if results:
        print(f"\n📊 Processing complete! {len(results)} results.")
        
        # Count successes and errors
        successes = len([r for r in results if "Error" not in r])
        errors = len([r for r in results if "Error" in r])
        print(f"✅ Successful: {successes}")
        if errors > 0:
            print(f"❌ Errors: {errors}")
        
        # Save output
        if args.format in ["csv", "both"]:
            csv_path = tool.save_results_csv(results, args.output)
            print(f"💾 CSV saved: {csv_path}")
        
        if args.format in ["json", "both"]:
            json_path = tool.save_results_json(results, args.output)
            print(f"💾 JSON saved: {json_path}")
    
    else:
        print("No results to save.")

if __name__ == "__main__":
    main()