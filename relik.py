__author__ = 'R'

'''
******************************************************
Vulnerability Report Automation Script with AI Enhancement
******************************************************

Description: Processes security assessment reports and enhances vulnerability 
data with AI-driven analysis. Efficiently deduplicates vulnerabilities across
multiple files and runs AI enhancement only once per unique vulnerability.

Usage:  python nessus_report_automation.py --company "Your Company" --report-id 123

Environment Variables Required (via .env file):
  - GEMINI_API_KEYS: Comma-separated Gemini API keys for rotation
  - GHOSTWRITER_API_KEY: Ghostwriter API key
  - GHOSTWRITER_URL: Ghostwriter instance URL

Requirements:  pip install lxml google-genai tldextract requests python-dotenv

'''

from lxml import etree
import os
import datetime
import csv
import sys
import argparse
import re
import time
import json
import threading
import signal
from urllib.parse import urlparse
import requests
from time import sleep
import urllib3

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    print("Warning: python-dotenv not installed. Install with: pip install python-dotenv")

# Import Google Generative AI (New SDK)
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("Warning: google-genai not installed. Install with: pip install google-genai")

# Import tldextract for domain extraction
try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False
    print("Warning: tldextract not installed. Install with: pip install tldextract")

B = "\033[1;34m"
E = "\033[1;m"
G = "\033[1;32m"
R = "\033[1;31m"
Y = "\033[1;33m"

# Global variables
gemini_clients = []  # List of Gemini clients with different API keys
current_gemini_index = 0  # Current active Gemini client index
gemini_enabled = False
gemini_processing = False
gemini_spinner = None
company_name = "Security Assessment Team"
request_count = 0
last_request_time = time.time()
RATE_LIMIT_RPM = 15
RATE_LIMIT_WAIT = 65

# Ghostwriter integration
ghostwriter_client = None
ghostwriter_enabled = False

# Simple spinner animation
spinner_chars = ['|', '/', '-', '\\']
spinner_index = 0

def spinner_task():
    """Display a spinning cursor while processing."""
    global gemini_processing, spinner_index
    while gemini_processing:
        print(f"\r{Y}AI is processing{spinner_chars[spinner_index]}{E}", end="", flush=True)
        spinner_index = (spinner_index + 1) % len(spinner_chars)
        time.sleep(0.1)

def start_spinner():
    """Start the spinner in a separate thread."""
    global gemini_processing, gemini_spinner
    gemini_processing = True
    gemini_spinner = threading.Thread(target=spinner_task)
    gemini_spinner.daemon = True
    gemini_spinner.start()

def stop_spinner():
    """Stop the spinner thread."""
    global gemini_processing
    gemini_processing = False
    if gemini_spinner:
        gemini_spinner.join(timeout=0.5)
    print("\r" + " " * 50 + "\r", end="", flush=True)

def handle_sigint(signum, frame):
    """Handle Ctrl+C gracefully."""
    global gemini_processing
    if gemini_processing:
        print(f"\n{R}Warning: Processing interrupted by user.{E}")
        gemini_processing = False
    sys.exit(1)

signal.signal(signal.SIGINT, handle_sigint)

def rate_limit_manager():
    """Manage rate limiting to avoid quota exceeded errors."""
    global request_count, last_request_time
    
    current_time = time.time()
    time_elapsed = current_time - last_request_time
    
    if time_elapsed >= 60:
        request_count = 0
        last_request_time = current_time
    
    if request_count >= RATE_LIMIT_RPM:
        wait_time = RATE_LIMIT_WAIT - time_elapsed
        if wait_time > 0:
            print(f"\n{Y}⏳ Rate limit reached. Waiting {int(wait_time)} seconds...{E}")
            time.sleep(wait_time)
            request_count = 0
            last_request_time = time.time()
    
    request_count += 1

# Ghostwriter Client Class
class GhostwriterClient:
    def __init__(self, ghostwriter_url, ghostwriter_api_key, verify_ssl=True):
        self.ghostwriter_url = ghostwriter_url
        self.ghostwriter_api_key = ghostwriter_api_key
        self.verify_ssl = verify_ssl
        self.headers = {
            "Authorization": f"Bearer {self.ghostwriter_api_key}",
            "Content-Type": "application/json"
        }
    
    def insert_finding(self, finding_data):
        """Insert a single finding into Ghostwriter."""
        url = f"{self.ghostwriter_url}/v1/graphql"
        query = """
        mutation InsertFindings($findings: [reportedFinding_insert_input!]!) {
            insert_reportedFinding(objects: $findings) {
                returning {
                    id
                    title
                    cvssScore
                    position
                }
            }
        }
        """
        variables = {"findings": [finding_data]}
        payload = {"query": query, "variables": variables}
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, verify=self.verify_ssl)
            sleep(1)  # Respect Ghostwriter rate limiting
            response.raise_for_status()
            response_data = response.json()
            
            if response.status_code == 200 and "errors" not in response_data:
                print(f"{G}✓ {finding_data['title']} inserted into Ghostwriter{E}")
                return response_data
            else:
                print(f"{R}✗ Failed to insert {finding_data['title']}: {response_data}{E}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"{R}✗ Ghostwriter API error: {e}{E}")
            return None

def extract_domain_from_url(url):
    """Extract readable domain name from URL."""
    try:
        if TLDEXTRACT_AVAILABLE:
            extracted = tldextract.extract(url)
            if extracted.domain:
                if extracted.suffix:
                    return f"{extracted.domain}.{extracted.suffix}"
                return extracted.domain
        
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        
        netloc = netloc.split(':')[0]
        
        return netloc if netloc else url
    except:
        return url

def validate_api_key(api_key):
    """Validate the API key format."""
    if not api_key:
        return False, "API key is empty"
    
    if not isinstance(api_key, str):
        return False, "API key must be a string"
    
    if not api_key.startswith("AIza"):
        return False, "API key format appears invalid (should start with 'AIza')"
    
    if len(api_key) != 39:
        return False, f"API key length appears invalid (expected 39 characters, got {len(api_key)})"
    
    return True, "API key format is valid"

def get_current_gemini_client():
    """Get the current active Gemini client."""
    global current_gemini_index, gemini_clients
    if gemini_clients and current_gemini_index < len(gemini_clients):
        return gemini_clients[current_gemini_index]
    return None

def rotate_gemini_key():
    """Rotate to the next available Gemini API key."""
    global current_gemini_index, gemini_clients
    
    if len(gemini_clients) <= 1:
        print(f"{R}No additional API keys available for rotation.{E}")
        return False
    
    current_gemini_index = (current_gemini_index + 1) % len(gemini_clients)
    print(f"{Y}⚠ Rotating to API key #{current_gemini_index + 1} of {len(gemini_clients)}{E}")
    return True

def initialize_gemini(api_keys_string, disable_ai):
    """Initialize Gemini clients with multiple API keys."""
    global gemini_clients, gemini_enabled, current_gemini_index
    
    if disable_ai:
        print(f"{Y}AI enhancement disabled by user (--disable-ai flag){E}")
        return False
    
    if not GEMINI_AVAILABLE:
        print(f"{R}Error: google-genai not installed.{E}")
        print(f"{Y}Install with: pip install google-genai{E}")
        return False
    
    if not api_keys_string:
        print(f"{Y}Warning: No GEMINI_API_KEYS found. Running without AI enhancement.{E}")
        return False
    
    # Split comma-separated API keys
    api_keys = [key.strip() for key in api_keys_string.split(',') if key.strip()]
    
    if not api_keys:
        print(f"{Y}Warning: No valid API keys found. Running without AI enhancement.{E}")
        return False
    
    print(f"{G}Initializing AI enhancement with {len(api_keys)} API key(s)...{E}")
    
    # Initialize clients for each API key
    valid_clients = 0
    for i, api_key in enumerate(api_keys):
        is_valid, message = validate_api_key(api_key)
        if not is_valid:
            print(f"{Y}⚠ Skipping API key #{i+1}: {message}{E}")
            continue
        
        try:
            client = genai.Client(api_key=api_key)
            
            # Test the client
            response = client.models.generate_content(
                model='gemini-flash-latest',
                contents='Test'
            )
            
            if response and response.text:
                gemini_clients.append(client)
                valid_clients += 1
                print(f"{G}✓ API key #{i+1} validated successfully{E}")
            else:
                print(f"{Y}⚠ API key #{i+1} returned empty response{E}")
                
        except Exception as e:
            print(f"{Y}⚠ API key #{i+1} validation failed: {str(e)}{E}")
            continue
    
    if valid_clients > 0:
        gemini_enabled = True
        current_gemini_index = 0
        print(f"{G}✓ AI enhancement ENABLED with {valid_clients} active key(s){E}")
        return True
    else:
        print(f"{R}Error: No valid API keys could be initialized{E}")
        return False

def initialize_ghostwriter(ghostwriter_url, ghostwriter_api_key, verify_ssl):
    """Initialize Ghostwriter client."""
    global ghostwriter_client, ghostwriter_enabled
    
    if not ghostwriter_url or not ghostwriter_api_key:
        print(f"{Y}Warning: Ghostwriter credentials not found. Skipping Ghostwriter integration.{E}")
        return False
    
    print(f"{G}Initializing Ghostwriter integration...{E}")
    
    try:
        ghostwriter_client = GhostwriterClient(ghostwriter_url, ghostwriter_api_key, verify_ssl)
        ghostwriter_enabled = True
        print(f"{G}✓ Ghostwriter integration enabled{E}")
        print(f"{G}✓ Connected to: {ghostwriter_url}{E}")
        if not verify_ssl:
            print(f"{Y}⚠ SSL verification disabled for Ghostwriter{E}")
        return True
    except Exception as e:
        print(f"{R}Error initializing Ghostwriter: {str(e)}{E}")
        return False

def enhance_vulnerability_with_ai(vulnerability, severity, description, cvss_score, plugin_output, company, exploit_info=None):
    """Enhance vulnerability data using AI with automatic key rotation on quota exhaustion."""
    global gemini_enabled
    
    if not gemini_enabled:
        impact = f"This {severity.lower()} severity vulnerability could compromise system security."
        description_enhanced = f"During the security assessment conducted by {company}, this vulnerability was identified. {description[:200]}"
        return vulnerability, description_enhanced, impact
    
    rate_limit_manager()
    start_spinner()
    
    max_rotation_attempts = len(gemini_clients)
    rotation_attempt = 0
    
    # Extract exploit information
    exploit_available = exploit_info.get('exploit_available', 'false') if exploit_info else 'false'
    exploit_code_maturity = exploit_info.get('exploit_code_maturity', '') if exploit_info else ''
    exploitability_ease = exploit_info.get('exploitability_ease', '') if exploit_info else ''
    
    try:
        desc_truncated = description[:1500] if description else "No description available"
        plugin_truncated = plugin_output[:800] if plugin_output else ""
        
        # Build exploit context for prompt
        exploit_context = ""
        if exploit_available or exploit_code_maturity or exploitability_ease:
            exploit_context = f"""
EXPLOIT INFORMATION (Use EXACTLY these terms):
- Exploit Available: {exploit_available}
- Exploit Code Maturity: {exploit_code_maturity if exploit_code_maturity else 'Not specified'}
- Exploitability Ease: {exploitability_ease if exploitability_ease else 'Not specified'}
"""
        
        prompt = f"""You are a cybersecurity expert writing PURELY TECHNICAL vulnerability assessments for {company}.

CRITICAL RULES:
1. DO NOT HALLUCINATE or add information not provided
2. Use EXACT exploit terminology from the data provided below
3. Impact must be PURELY TECHNICAL (no business/organizational impact)
4. Start description with: "During the security assessment conducted by {company}..."
5. Be factual and precise - cite only what is in the data

VULNERABILITY DATA:
Name: {vulnerability}
Severity: {severity}
CVSS Score: {cvss_score}
Description: {desc_truncated}
Evidence: {plugin_truncated}
{exploit_context}

Write a TECHNICAL vulnerability assessment:
- Description: Professional summary starting with required phrase
- Impact: PURELY TECHNICAL consequences (system compromise, data exposure, privilege escalation, service disruption, etc.)
- If exploit info provided, mention it using EXACT terms from the data
- Focus on technical attack vectors and system-level consequences
- DO NOT mention business impact, financial losses, reputation, or organizational effects

Respond in JSON:
{{
  "vulnerability_name": "concise technical name (max 100 chars)",
  "description": "starts with 'During the security assessment conducted by {company}...' - technical details only (max 400 words)",
  "impact": "PURELY TECHNICAL impact - system-level consequences, attack potential, technical risks (150-200 words)"
}}"""
        
        while rotation_attempt < max_rotation_attempts:
            gemini_client = get_current_gemini_client()
            
            if not gemini_client:
                break
            
            for attempt in range(3):
                try:
                    response = gemini_client.models.generate_content(
                        model='gemini-flash-latest',
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            temperature=0.2,  # Lower temperature for more factual output
                            top_p=0.8,
                            max_output_tokens=2048
                        )
                    )
                    
                    if response and response.text:
                        json_match = re.search(r'\{.*\}', response.text.strip(), re.DOTALL)
                        if json_match:
                            enhanced_data = json.loads(json_match.group(0))
                            
                            if all(k in enhanced_data for k in ['vulnerability_name', 'description', 'impact']):
                                stop_spinner()
                                desc = enhanced_data['description']
                                if not desc.startswith("During the security assessment"):
                                    desc = f"During the security assessment conducted by {company}, {desc}"
                                
                                return enhanced_data['vulnerability_name'], desc, enhanced_data['impact']
                    
                    break
                    
                except Exception as e:
                    error_str = str(e).lower()
                    
                    # Check for quota/rate limit errors
                    if "quota" in error_str or "429" in error_str or "resource_exhausted" in error_str:
                        stop_spinner()
                        print(f"\n{Y}⚠ API key #{current_gemini_index + 1} quota exhausted{E}")
                        
                        # Try rotating to next key
                        if rotate_gemini_key():
                            rotation_attempt += 1
                            print(f"{Y}Retrying with new API key...{E}")
                            start_spinner()
                            break  # Break inner loop to retry with new key
                        else:
                            # No more keys available
                            stop_spinner()
                            desc_fallback = f"During the security assessment conducted by {company}, this {severity.lower()} severity vulnerability was identified. {description[:300]}"
                            
                            # Build technical impact with exploit info
                            impact_fallback = f"This {severity.lower()} severity vulnerability could allow an attacker to compromise system security."
                            if exploit_available == "true":
                                impact_fallback += f" Exploit availability: {exploit_available}."
                            if exploitability_ease:
                                impact_fallback += f" Exploitability: {exploitability_ease}."
                            if not exploitability_ease and not exploit_available == "true":
                                impact_fallback += " This could lead to unauthorized access, privilege escalation, or denial of service conditions."
                            
                            return vulnerability, desc_fallback, impact_fallback
                    
                    # For other errors, retry with exponential backoff
                    if attempt < 2:
                        time.sleep(2 ** attempt)
                        continue
                    else:
                        break
            
            # If we got here without returning, it means we should try next key
            if rotation_attempt < max_rotation_attempts - 1:
                continue
            else:
                break
        
        stop_spinner()
        desc_fallback = f"During the security assessment conducted by {company}, this {severity.lower()} severity vulnerability was identified. {description[:300]}"
        
        # Build technical impact with exploit info
        impact_fallback = f"This {severity.lower()} severity vulnerability presents a technical security risk to affected systems."
        if exploit_available == "true":
            impact_fallback += f" Public exploits are available (Exploit Available: {exploit_available})."
        if exploit_code_maturity:
            impact_fallback += f" Exploit maturity level: {exploit_code_maturity}."
        if exploitability_ease:
            impact_fallback += f" {exploitability_ease}."
        impact_fallback += " Successful exploitation could lead to system compromise, unauthorized access, data exposure, or service disruption depending on the vulnerability type and attack vector."
        
        return vulnerability, desc_fallback, impact_fallback
        
    except Exception as e:
        stop_spinner()
        desc_fallback = f"During the security assessment conducted by {company}, this vulnerability was identified. {description[:300]}"
        impact_fallback = f"This {severity.lower()} severity vulnerability requires technical remediation to prevent potential system compromise."
        return vulnerability, desc_fallback, impact_fallback

def banner():
    if sys.platform == 'win32':
        os.system('cls')
    else:
        os.system('clear') 
    ban = r"""
    ██████╗ ██████╗ ██╗     ██╗██╗  ██╗
    ██╔══██╗╚════██╗██║     ██║██║ ██╔╝
    ██████╔╝ █████╔╝██║     ██║█████╔╝ 
    ██╔══██╗ ╚═══██╗██║     ██║██╔═██╗ 
    ██║  ██║██████╔╝███████╗██║██║  ██╗
    ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝
    
    Vulnerability Report Automation with AI & Ghostwriter
    """
    print(B + ban + E)

def extract_references(report_item):
    """Extract all references with resolved domains."""
    references = []
    
    cve_list = []
    for cve in report_item.xpath("cve"):
        if cve.text:
            cve_list.append(f"CVE-{cve.text.strip()}")
    
    if cve_list:
        references.append(f"{', '.join(cve_list)} (nvd.nist.gov)")
    
    bid_list = []
    for bid in report_item.xpath("bid"):
        if bid.text:
            bid_list.append(bid.text.strip())
    
    if bid_list:
        references.append(f"{', '.join([f'BID-{b}' for b in bid_list])} (securityfocus.com)")
    
    for xref in report_item.xpath("xref"):
        if xref.text:
            xref_text = xref.text.strip()
            # Check if it's a Nessus plugin reference
            if xref_text.startswith("Nessus Plugin ID"):
                plugin_id = xref_text.split()[-1]
                references.append(f"Nessus Plugin ID {plugin_id}: https://www.tenable.com/plugins/nessus/{plugin_id}")
            else:
                references.append(xref_text)
    
    for see_also in report_item.xpath("see_also"):
        if see_also.text:
            for link in see_also.text.strip().split('\n'):
                link = link.strip()
                if link and (link.startswith('http://') or link.startswith('https://')):
                    # Resolve nessus.org redirect links
                    if 'nessus.org/u?' in link:
                        try:
                            response = requests.head(link, allow_redirects=True, timeout=5)
                            resolved_url = response.url
                            domain = extract_domain_from_url(resolved_url)
                            references.append(f"{domain}: {resolved_url}")
                        except:
                            # If resolution fails, use original link
                            domain = extract_domain_from_url(link)
                            references.append(f"{domain}: {link}")
                    else:
                        domain = extract_domain_from_url(link)
                        references.append(f"{domain}: {link}")
    
    return "\n".join(references) if references else "No external references available"

def format_html_for_ghostwriter(text, format_type="paragraph"):
    """
    Format text with HTML for Ghostwriter.
    
    Args:
        text: The text to format
        format_type: "paragraph", "bullet", "code"
    
    Returns:
        HTML formatted string
    """
    if not text:
        return ""
    
    if format_type == "bullet":
        # Split by newlines or common delimiters and create bullet list
        items = []
        for line in text.split('\n'):
            line = line.strip()
            if line:
                items.append(f"<li>{line}</li>")
        return f"<ul>{''.join(items)}</ul>" if items else text
    
    elif format_type == "code":
        return f"<pre><code>{text}</code></pre>"
    
    else:  # paragraph
        # Replace newlines with <br> and wrap in <p>
        formatted = text.replace('\n\n', '</p><p>').replace('\n', '<br>')
        return f"<p>{formatted}</p>"

def ip_data(nt):
    """Extract affected hosts and their vulnerability mappings."""
    _ip_map = {}
    
    for _re in nt.xpath("Report"):
        for _rh in _re.xpath("ReportHost"):
            _ip = ""
            for _hp in _rh.xpath("HostProperties"):
                for _t in _hp.xpath("tag"):
                    if _t.attrib.get("name") == "host-ip":
                        _ip = _t.text
            
            for _ri in _rh.xpath("ReportItem"):
                sev = _ri.attrib.get("severity")
                if sev == "0":
                    continue
                
                _key = str(_ri.attrib.get("pluginID")).strip()
                _pro = str(_ri.attrib.get("protocol")).strip()
                _por = str(_ri.attrib.get("port")).strip()
                
                _data = [_key, f"({_pro}/{_por})"]
                
                if _ip in _ip_map:
                    _ip_map[_ip].append(_data)
                else:
                    _ip_map[_ip] = [_data]
    
    return _ip_map

def vuln_data(nt):
    """Extract vulnerability details from the report including exploit information."""
    _vuln_map = {}
    _severe = ['None', 'Low', 'Medium', 'High', 'Critical']
    
    for _re in nt.xpath("Report"):
        for _rh in _re.xpath("ReportHost"):
            for _ri in _rh.xpath("ReportItem"):
                sev = _ri.attrib.get("severity")
                if sev == "0":
                    continue
                
                _risk = _severe[int(sev)]
                _pid = str(_ri.attrib.get("pluginID")).strip()
                _pn = str(_ri.attrib.get("pluginName")).strip()
                
                _des = ""
                for _d in _ri.xpath("description"):
                    if _d.text:
                        _des = str(_d.text).strip().replace('\n', ' ')
                
                _cvss = ""
                for _ in _ri.xpath("cvss3_base_score"):
                    if _.text:
                        _cvss = str(_.text).strip()
                if not _cvss:
                    for _ in _ri.xpath("cvss_base_score"):
                        if _.text:
                            _cvss = str(_.text).strip()
                
                _cvssv = ""
                for _ in _ri.xpath("cvss3_vector"):
                    if _.text:
                        _cvssv = str(_.text).strip()
                if not _cvssv:
                    for _ in _ri.xpath("cvss_vector"):
                        if _.text:
                            _cvssv = str(_.text).strip()
                
                _rec = ""
                for _ in _ri.xpath("solution"):
                    if _.text:
                        _rec = str(_.text).strip().replace('\n', ' ')
                
                if not _rec:
                    _rec = "Consult with the vendor for remediation guidance."
                
                _plugin_output = ""
                for _ in _ri.xpath("plugin_output"):
                    if _.text:
                        _plugin_output = str(_.text).strip()[:1000]
                
                _ref = extract_references(_ri)
                
                # Extract exploit information
                _exploit_available = "false"
                for _ in _ri.xpath("exploit_available"):
                    if _.text:
                        _exploit_available = str(_.text).strip()
                
                _exploit_code_maturity = ""
                for _ in _ri.xpath("exploit_code_maturity"):
                    if _.text:
                        _exploit_code_maturity = str(_.text).strip()
                
                _exploitability_ease = ""
                for _ in _ri.xpath("exploitability_ease"):
                    if _.text:
                        _exploitability_ease = str(_.text).strip()
                
                _vuln_map[_pid] = {
                    'name': _pn,
                    'severity': _risk,
                    'description': _des,
                    'cvss': _cvss if _cvss else '0.0',
                    'cvss_vector': _cvssv if _cvssv else 'N/A',
                    'solution': _rec,
                    'references': _ref,
                    'plugin_output': _plugin_output if _plugin_output else "No evidence available",
                    'exploit_available': _exploit_available,
                    'exploit_code_maturity': _exploit_code_maturity,
                    'exploitability_ease': _exploitability_ease
                }
    
    return _vuln_map

def dist_map(ip_map):
    """Distribute ports per IP per vulnerability."""
    fin = {}
    for ip in ip_map:
        m = {}
        for data in ip_map[ip]:
            plugin_id = data[0]
            port_info = data[1]
            if plugin_id in m:
                m[plugin_id] = m[plugin_id] + " " + port_info
            else:
                m[plugin_id] = port_info
        fin[ip] = m
    return fin

def write_instance_csv(data, instance_file):
    """Write instance-level data to separate CSV."""
    file_exists = os.path.isfile(instance_file)
    
    with open(instance_file, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        if not file_exists:
            writer.writerow([
                "Source File",
                "IP Address",
                "Protocol",
                "Port",
                "Plugin ID",
                "Vulnerability",
                "Severity",
                "CVSS Score",
                "Description",
                "Recommendation"
            ])
        
        writer.writerow(data)

def parse_all_nessus_files(files):
    """Parse all Nessus files and collect vulnerability data."""
    print(f"{G}Phase 1: Parsing all Nessus files...{E}\n")
    
    all_vulnerabilities = {}  # Key: plugin_id, Value: vuln data with hosts list
    file_mapping = {}  # Key: plugin_id, Value: list of (source_file, ip, ports)
    
    for file_index, filename in enumerate(files):
        try:
            print(f"{G}[{file_index+1}/{len(files)}] Parsing: {filename}{E}")
            nt = etree.parse(filename)
            source_file = os.path.splitext(filename)[0]
            
            ip_map = ip_data(nt)
            vuln_map = vuln_data(nt)
            
            # Add plugin_id to vuln_map
            for _re in nt.xpath("Report"):
                for _rh in _re.xpath("ReportHost"):
                    for _ri in _rh.xpath("ReportItem"):
                        _pid = str(_ri.attrib.get("pluginID")).strip()
                        if _pid in vuln_map:
                            vuln_map[_pid]['plugin_id'] = _pid
            
            dist = dist_map(ip_map)
            
            # Collect vulnerabilities and their instances
            for ip in dist:
                for plugin_id in dist[ip]:
                    if plugin_id in vuln_map:
                        # Store unique vulnerability data
                        if plugin_id not in all_vulnerabilities:
                            all_vulnerabilities[plugin_id] = vuln_map[plugin_id].copy()
                            file_mapping[plugin_id] = []
                        
                        # Store instance mapping (file, ip, ports)
                        file_mapping[plugin_id].append({
                            'source_file': source_file,
                            'ip': ip,
                            'ports': dist[ip][plugin_id]
                        })
            
            print(f"{G}✓ Parsed {filename}{E}")
            
        except Exception as e:
            print(f"{R}✗ Error parsing {filename}: {str(e)}{E}")
            continue
    
    return all_vulnerabilities, file_mapping

def enhance_vulnerabilities_batch(vulnerabilities, company):
    """Enhance all unique vulnerabilities with AI in batch."""
    print(f"\n{G}Phase 2: AI Enhancement ({len(vulnerabilities)} unique vulnerabilities)...{E}\n")
    
    enhanced_vulns = {}
    total = len(vulnerabilities)
    processed = 0
    
    for plugin_id, vuln_data in vulnerabilities.items():
        processed += 1
        vuln_name_short = vuln_data['name'][:60] + "..." if len(vuln_data['name']) > 60 else vuln_data['name']
        print(f"{B}[{processed}/{total}] {vuln_name_short}{E}")
        
        # Prepare exploit information
        exploit_info = {
            'exploit_available': vuln_data.get('exploit_available', 'false'),
            'exploit_code_maturity': vuln_data.get('exploit_code_maturity', ''),
            'exploitability_ease': vuln_data.get('exploitability_ease', '')
        }
        
        # Enhance with AI
        enhanced_name, enhanced_desc, impact = enhance_vulnerability_with_ai(
            vuln_data['name'],
            vuln_data['severity'],
            vuln_data['description'],
            vuln_data['cvss'],
            vuln_data['plugin_output'],
            company,
            exploit_info
        )
        
        # Store enhanced data
        enhanced_vulns[plugin_id] = {
            'original': vuln_data,
            'enhanced_name': enhanced_name,
            'enhanced_description': enhanced_desc,
            'enhanced_impact': impact
        }
    
    print(f"\n{G}✓ AI enhancement complete for {len(enhanced_vulns)} vulnerabilities{E}\n")
    return enhanced_vulns

def severity_to_number(severity):
    """Convert severity string to number for Ghostwriter (1-5 scale)."""
    severity_map = {
        'Critical': 5,
        'High': 4,
        'Medium': 3,
        'Low': 2,
        'Informational': 1
    }
    return severity_map.get(severity, 3)

def build_affected_entities_format(affected_hosts):
    """Build affected entities list in HTML bullet format for Ghostwriter."""
    # Parse affected hosts string: "192.168.1.1 (tcp/443) (tcp/80) | 192.168.1.2 (tcp/22)"
    entities = []
    
    for entry in affected_hosts.split('|'):
        entry = entry.strip()
        if entry:
            parts = entry.split()
            if parts:
                ip = parts[0]
                # Parse ports like (tcp/443) (tcp/80)
                for p in parts[1:]:
                    match = re.match(r'\((\w+)/(\d+)\)', p)
                    if match:
                        protocol = match.group(1)
                        port = match.group(2)
                        entities.append(f"<li>{ip} ({protocol}/{port})</li>")
    
    return f"<ul>{''.join(entities)}</ul>" if entities else "<p>No affected hosts</p>"

def create_ghostwriter_finding(vuln_data, report_id, position):
    """Create a Ghostwriter finding object with correct field names and HTML formatting."""
    
    # Format references as HTML bullet list
    references_list = vuln_data['references'].split('\n')
    references_html = "<ul>"
    for ref in references_list:
        if ref.strip():
            # Check if reference contains a URL
            if 'http://' in ref or 'https://' in ref:
                parts = ref.split(': ', 1)
                if len(parts) == 2:
                    domain, url = parts
                    references_html += f"<li><a href='{url}'>{domain}</a></li>"
                else:
                    references_html += f"<li>{ref}</li>"
            else:
                references_html += f"<li>{ref}</li>"
    references_html += "</ul>"
    
    return {
        "reportId": report_id,
        "findingTypeId": 1,
        "title": vuln_data['vulnerability'],
        "description": format_html_for_ghostwriter(vuln_data['description'], "paragraph"),
        "impact": format_html_for_ghostwriter(vuln_data['impact'], "paragraph"),
        "mitigation": format_html_for_ghostwriter(vuln_data['recommendation'], "paragraph"),
        "replication_steps": format_html_for_ghostwriter(vuln_data['evidence'], "code"),
        "affectedEntities": build_affected_entities_format(vuln_data['affected_hosts']),
        "references": references_html,
        "severityId": severity_to_number(vuln_data['severity']),
        "cvssScore": float(vuln_data['cvss']),
        "cvssVector": vuln_data['cvss_vector'],
        "position": position
    }

def write_reports(enhanced_vulns, file_mapping, company, instance_file, timestamp):
    """Write CSV reports and prepare Ghostwriter data."""
    print(f"{G}Phase 3: Generating reports...{E}\n")
    
    # Prepare consolidated data
    consolidated_data = []
    
    for plugin_id, enhanced_data in enhanced_vulns.items():
        vuln = enhanced_data['original']
        instances = file_mapping.get(plugin_id, [])
        
        if not instances:
            continue
        
        # Aggregate all affected hosts
        all_hosts = []
        for instance in instances:
            all_hosts.append(f"{instance['ip']} {instance['ports']}")
        
        affected_hosts = " | ".join(all_hosts)
        
        # Prepare row data
        row_data = {
            'cvss': vuln['cvss'],
            'severity': vuln['severity'],
            'vulnerability': enhanced_data['enhanced_name'],
            'description': enhanced_data['enhanced_description'],
            'impact': enhanced_data['enhanced_impact'],
            'cvss_vector': vuln['cvss_vector'],
            'evidence': vuln['plugin_output'],
            'affected_hosts': affected_hosts,
            'recommendation': vuln['solution'],
            'references': vuln['references']
        }
        
        consolidated_data.append(row_data)
        
        # Write instance-level data
        for instance in instances:
            port_entries = instance['ports'].split()
            for port_entry in port_entries:
                match = re.match(r'\((\w+)/(\d+)\)', port_entry)
                if match:
                    protocol = match.group(1)
                    port = match.group(2)
                    
                    instance_data = [
                        instance['source_file'],
                        instance['ip'],
                        protocol,
                        port,
                        plugin_id,
                        enhanced_data['enhanced_name'],
                        vuln['severity'],
                        vuln['cvss'],
                        enhanced_data['enhanced_description'][:200] + "..." if len(enhanced_data['enhanced_description']) > 200 else enhanced_data['enhanced_description'],
                        vuln['solution'][:200] + "..." if len(vuln['solution']) > 200 else vuln['solution']
                    ]
                    write_instance_csv(instance_data, instance_file)
    
    # Sort by CVSS score
    sorted_vulns = sorted(
        consolidated_data,
        key=lambda x: float(x['cvss']) if x['cvss'].replace('.','').replace('-','').isdigit() else 0.0,
        reverse=True
    )
    
    # Write consolidated CSV
    final_file = f"Security_Assessment_Report_{timestamp}.csv"
    for i, vuln_data in enumerate(sorted_vulns, 1):
        vuln_data['sr_no'] = i
        write_csv_consolidated(vuln_data, final_file)
    
    print(f"{G}✓ Consolidated report: {final_file}{E}")
    print(f"{G}✓ Instance report: {instance_file}{E}")
    return sorted_vulns, final_file

def write_csv_consolidated(data, outf):
    """Write consolidated vulnerability data to CSV."""
    file_exists = os.path.isfile(outf)
    
    with open(outf, mode='a' if file_exists else 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        if not file_exists:
            writer.writerow([
                "Sr. No",
                "CVSS Score",
                "Severity",
                "Vulnerability",
                "Description",
                "Impact",
                "CVSS Vector",
                "Evidence / Replication Steps",
                "Affected Hosts",
                "Recommendation",
                "References"
            ])
        
        writer.writerow([
            data['sr_no'],
            data['cvss'],
            data['severity'],
            data['vulnerability'],
            data['description'],
            data['impact'],
            data['cvss_vector'],
            data['evidence'],
            data['affected_hosts'],
            data['recommendation'],
            data['references']
        ])

def push_to_ghostwriter(sorted_vulns, report_id):
    """Push findings to Ghostwriter."""
    if not ghostwriter_enabled or not report_id:
        return
    
    print(f"\n{G}Phase 4: Pushing {len(sorted_vulns)} findings to Ghostwriter...{E}\n")
    
    for position, vuln_data in enumerate(sorted_vulns, 1):
        finding = create_ghostwriter_finding(vuln_data, report_id, position)
        ghostwriter_client.insert_finding(finding)
    
    print(f"{G}✓ All findings pushed to Ghostwriter{E}")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Process security assessment reports with AI enhancement and Ghostwriter integration.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables (.env file):
  GEMINI_API_KEYS       Comma-separated Gemini API keys
  GHOSTWRITER_API_KEY   Ghostwriter API key
  GHOSTWRITER_URL       Ghostwriter instance URL

Examples:
  # Create .env file first
  python nessus_report_automation.py --company "CyberSec Solutions" --report-id 123
  python nessus_report_automation.py --company "CyberSec Solutions" --disable-ai
  python nessus_report_automation.py --company "CyberSec Solutions" --report-id 123 --insecure
        """
    )
    parser.add_argument('--company', type=str, required=True, 
                       help='Company name that performed the assessment')
    parser.add_argument('--report-id', type=int, required=False,
                       help='Ghostwriter report ID (required for Ghostwriter integration)')
    parser.add_argument('--disable-ai', action='store_true',
                       help='Disable AI enhancement (use original vulnerability data)')
    parser.add_argument('--insecure', action='store_true',
                       help='Disable SSL certificate verification for Ghostwriter')
    return parser.parse_args()

def main():
    global company_name
    
    args = parse_arguments()
    company_name = args.company
    
    # Disable SSL warnings if insecure flag is set
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    banner()
    
    print(f"{B}Security Assessment by: {company_name}{E}\n")
    
    # Get API keys from environment
    gemini_keys = os.getenv('GEMINI_API_KEYS')
    ghostwriter_key = os.getenv('GHOSTWRITER_API_KEY')
    ghostwriter_url = os.getenv('GHOSTWRITER_URL')
    
    # Initialize Gemini with multiple keys
    if gemini_keys and not args.disable_ai:
        if initialize_gemini(gemini_keys, args.disable_ai):
            print(f"{G}✓ AI enhancement ENABLED{E}\n")
    else:
        if args.disable_ai:
            print(f"{Y}⚠ AI enhancement disabled by user{E}\n")
        else:
            print(f"{Y}⚠ GEMINI_API_KEYS not set. Running without AI enhancement{E}\n")
    
    # Initialize Ghostwriter
    if ghostwriter_key and ghostwriter_url:
        if args.report_id:
            verify_ssl = not args.insecure
            initialize_ghostwriter(ghostwriter_url, ghostwriter_key, verify_ssl)
        else:
            print(f"{Y}⚠ --report-id not provided. Skipping Ghostwriter integration{E}\n")
    else:
        print(f"{Y}⚠ Ghostwriter credentials not set. Skipping Ghostwriter integration{E}\n")
    
    # Find report files
    files = [f for f in os.listdir('.') if f.endswith('.nessus')]
    if not files:
        print(f"{R}Error: No .nessus files found{E}")
        return
    
    print(f"{G}Found {len(files)} report file(s){E}\n")
    
    # Create timestamp for output files
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    instance_file = f"Security_Assessment_Instances_{timestamp}.csv"
    
    # PHASE 1: Parse all Nessus files
    all_vulnerabilities, file_mapping = parse_all_nessus_files(files)
    
    if not all_vulnerabilities:
        print(f"{R}Error: No vulnerabilities found in reports{E}")
        return
    
    total_instances = sum(len(instances) for instances in file_mapping.values())
    print(f"\n{G}✓ Total unique vulnerabilities: {len(all_vulnerabilities)}{E}")
    print(f"{G}✓ Total vulnerability instances: {total_instances}{E}")
    
    # PHASE 2: AI Enhancement (once per unique vulnerability)
    enhanced_vulns = enhance_vulnerabilities_batch(all_vulnerabilities, company_name)
    
    # PHASE 3: Write reports
    sorted_vulns, final_file = write_reports(enhanced_vulns, file_mapping, company_name, instance_file, timestamp)
    
    # PHASE 4: Push to Ghostwriter
    if args.report_id:
        push_to_ghostwriter(sorted_vulns, args.report_id)
    
    print(f"\n{G}{'='*60}{E}")
    print(f"{G}Report Generation Complete!{E}")
    print(f"{G}{'='*60}{E}")
    print(f"{G}✓ Consolidated report: {final_file}{E}")
    print(f"{G}✓ Instance report: {instance_file}{E}")
    print(f"{G}✓ Unique vulnerabilities: {len(all_vulnerabilities)}{E}")
    print(f"{G}✓ Total instances: {total_instances}{E}")
    print(f"{G}✓ AI calls made: {len(enhanced_vulns)}{E}")
    print(f"{G}✓ Assessment by: {company_name}{E}")
    
    if ghostwriter_enabled and args.report_id:
        print(f"{G}✓ Pushed to Ghostwriter (Report ID: {args.report_id}){E}\n")
    else:
        print()

if __name__ == "__main__":
    main()
