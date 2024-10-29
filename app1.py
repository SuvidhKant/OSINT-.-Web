from flask import Flask, render_template, request
import socket
import ssl
import whois
import dns.resolver
import OpenSSL
import os
import requests
from censys.search import CensysHosts
from dotenv import load_dotenv
from bs4 import BeautifulSoup


# Load the .env file
load_dotenv()

app = Flask(__name__)

# Retrieve the API keys from the environment variables
api_key = os.getenv('API_KEY')
virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
censys_api_id = os.getenv('CENSYS_API_ID')
censys_api_secret = os.getenv('CENSYS_API_SECRET')

# Initialize Censys Hosts
censys_hosts = CensysHosts(censys_api_id, censys_api_secret)

@app.route('/')
def index():
    return render_template('index.html')

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error retrieving IP address: {e}"

def get_ssl_info(domain):
    try:
        conn = ssl.create_connection((domain, 443), timeout=5)
        context = ssl.create_default_context()
        sock = context.wrap_socket(conn, server_hostname=domain)
        certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        issuer = x509.get_issuer()
        subject = x509.get_subject()
        ssl_info = {
            'Issuer': dict(issuer.get_components()),
            'Subject': dict(subject.get_components()),
            'Serial Number': x509.get_serial_number(),
            'Version': x509.get_version(),
            'Not Before': x509.get_notBefore().decode('utf-8'),
            'Not After': x509.get_notAfter().decode('utf-8'),
        }
        return ssl_info
    except Exception as e:
        return f"Error retrieving SSL certificate: {e}"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return "\n".join(w.text.split('\n')[:11])
    except Exception as e:
        return f"Error retrieving WHOIS information: {e}"

def get_dns_info(domain):
    records = {}
    try:
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            records[record_type] = [rdata.to_text() for rdata in answers]
        return records
    except Exception as e:
        return f"Error retrieving DNS records: {e}"

def get_censys_info(ip):
    try:
        # Query Censys for the specified IP
        host_info = censys_hosts.view(ip)
        
        # Extract location data, using .get() to avoid KeyErrors
        location_data = {
            "city": host_info.get("location", {}).get("city", "N/A"),
            "country": host_info.get("location", {}).get("country", "N/A"),
            "region": host_info.get("location", {}).get("region", "N/A"),
            "timezone": host_info.get("location", {}).get("timezone", "N/A"),
            "languages": host_info.get("location", {}).get("languages", "N/A"),
            "currency": host_info.get("location", {}).get("currency", "N/A"),
        }
        return location_data  # Ensure this returns the dictionary
    except Exception as e:
        return f"Error retrieving Censys information: {e}"


def get_subdomains_from_virustotal(api_key, domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('data', [])
            subdomain_list = [subdomain['id'] for subdomain in subdomains]
            return subdomain_list
        else:
            return f"Error: Unable to fetch subdomains. Status code {response.status_code}"
    except Exception as e:
        return str(e)

def get_virustotal_info(domain):
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': virustotal_api_key, 'domain': domain}
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            vt_data = response.json()
            # Extracting some relevant parts of the response
            return {
                "positives": vt_data.get('positives', 0),  # Default to 0 if not available
                "total": vt_data.get('total', 0),  # Default to 0 if not available
                "categories": vt_data.get('categories', 'Unknown'),  # Default to 'Unknown'
                "reputation": vt_data.get('reputation', 'Unknown')  # Default to 'Unknown'
            }
        else:
            return {
                "positives": "N/A",
                "total": "N/A",
                "categories": "N/A",
                "reputation": "N/A",
                "error": f"Error retrieving VirusTotal information: {response.status_code}"
            }
    except Exception as e:
        return {
            "positives": "N/A",
            "total": "N/A",
            "categories": "N/A",
            "reputation": "N/A",
            "error": f"Error retrieving VirusTotal information: {e}"
        }

def get_headers(domain):
    try:
        # Make a GET request to the domain to retrieve headers
        response = requests.get(f'http://{domain}', timeout=5)
        return response.headers  # This will return a dictionary of headers
    except requests.RequestException as e:
        return f"Error retrieving headers: {e}"
    
def check_server_status(domain):
    try:
        # Send a request to the domain
        response = requests.get(f'http://{domain}', timeout=5)
        status_code = response.status_code
        response_time = response.elapsed.total_seconds() * 1000  # Convert to milliseconds
        is_up = True  # If no exception is raised, the server is online
        headers = {key: value for key, value in response.headers.items()}  # Capture headers

        # Extract server info
        server_info = {
            "server": headers.get("Server", "N/A"),
            "powered_by": headers.get("X-Powered-By", "N/A"),
            "content_security_policy": headers.get("Content-Security-Policy", "N/A"),
        }
        
        # Check HTTP security headers
        http_security = check_http_security_headers(headers)
        
    except requests.exceptions.RequestException as e:
        # If there was an error, set status values accordingly
        status_code = "N/A"
        response_time = "N/A"
        is_up = False
        headers = {}  # No headers if there's an error
        server_info = {
            "server": "N/A",
            "powered_by": "N/A",
            "content_security_policy": "N/A",
        }
        http_security = {key: "N/A" for key in ["Content Security Policy", "Strict Transport Security", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]}

    return {
        "is_up": is_up,
        "status_code": status_code,
        "response_time": response_time,
        "headers": headers,
        "server_info": server_info,  # Include server info in the returned dictionary
        "http_security": http_security  # Include HTTP security info
    }


def check_http_security_headers(headers):
    """ Check for important HTTP security headers and their status. """
    security_headers = {
        "Content Security Policy": headers.get("Content-Security-Policy", "No"),
        "Strict Transport Security": headers.get("Strict-Transport-Security", "No"),
        "X-Content-Type-Options": headers.get("X-Content-Type-Options", "No"),
        "X-Frame-Options": headers.get("X-Frame-Options", "No"),
        "X-XSS-Protection": headers.get("X-XSS-Protection", "No"),
    }

    # Transform presence into Yes/No
    for key in security_headers:
        security_headers[key] = "✅ Yes" if security_headers[key] != "No" else "❌ No"

    return security_headers

def get_dns_servers(domain):
    try:
        # Use a DNS resolver to get DNS servers
        resolver = dns.resolver.Resolver()
        dns_servers = resolver.nameservers  # This will give you the configured DNS servers
        
        dns_info = []
        for server in dns_servers:
            # Check for DoH support (a simplistic check; in reality, this may require sending a DoH query)
            # Here we're just mocking the response for simplicity
            # You might implement an actual check here depending on your requirements.
            # For example, using requests to check a known DoH endpoint:
            do_responds = False  # Assume DoH is not supported by default
            
            # Add server info
            dns_info.append({
                "ip_address": str(server),
                "doh_support": do_responds  # Adjust this based on your checks
            })

        return dns_info
    except Exception as e:
        return f"Error retrieving DNS server information: {e}"

def check_security_features(domain):
    security_info = {
        "security_txt": "No",  # Placeholder for security.txt check
        "firewall": "No",  # Placeholder for firewall detection
        "dnssec": {
            "dnskey": "No",  # Placeholder for DNSKEY presence
            "ds": "No",  # Placeholder for DS presence
            "rrsig": "No"  # Placeholder for RRSIG presence
        },
        "hsts": "No",  # Placeholder for HSTS check
        "phishing_status": "No Phishing Found",  # Placeholder for phishing status
        "malware_status": "N/A",  # Placeholder for malware status
        "tls_cipher_suites": [
            "ECDHE-RSA-AES128-GCM-SHA256", 
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES128-SHA", 
            "ECDHE-RSA-AES256-GCM-SHA384", 
            "ECDHE-RSA-AES256-SHA384", 
            "ECDHE-RSA-AES256-SHA"
        ],
        "tls_security_issues": {
            "ca_authorization": "No",  # Placeholder for CA authorization status
            "mozilla_grading": "93",  # Placeholder for Mozilla grading
            "symantec_distrust": "Yes",  # Placeholder for Symantec distrust check
            "certificate_rank": "166",  # Placeholder for certificate rank
            "mozilla_evaluation_level": "Intermediate"  # Placeholder for evaluation level
        },
        "compatibility_issues": [
            "Fix cipher ordering, use recommended intermediate ciphersuite",
            "Consider adding ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305"
        ],
        "intermediate_issues": [
            "Consider enabling OCSP stapling",
            "Increase priority of ECDHE-RSA-AES256-GCM-SHA384 over ECDHE-RSA-AES128-SHA"
        ],
        "modern_issues": [
            "Remove ciphersuites ECDHE-RSA-AES128-SHA, ECDHE-RSA-AES256-SHA",
            "Use a certificate of type ecdsa, not RSA"
        ]
    }

    # Here you would add the logic to actually check for each of these features.
    # This might involve making requests to check for the security.txt file,
    # querying the DNS records to check for DNSSEC, etc.

    return security_info

def check_redirects(domain):
    try:
        response = requests.get(f'http://{domain}', allow_redirects=True, timeout=5)
        return {
            "followed_redirects": len(response.history),
            "final_url": response.url
        }
    except Exception as e:
        return {
            "followed_redirects": 0,
            "final_url": "Error occurred"
        }
def check_crawl_rules(domain):
    try:
        response = requests.get(f"http://{domain}/robots.txt", timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return "No robots.txt file found."
    except Exception as e:
        return f"Error fetching robots.txt: {e}"

def get_linked_pages(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        internal_links = []
        external_links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            if domain in href or href.startswith('/'):
                internal_links.append(href)
            else:
                external_links.append(href)

        return {
            "internal_links": internal_links,
            "external_links": external_links,
            "internal_count": len(internal_links),
            "external_count": len(external_links)
        }
    except Exception as e:
        return {
            "internal_links": [],
            "external_links": [],
            "internal_count": 0,
            "external_count": 0,
            "error": str(e)
        }

def calculate_carbon_footprint(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        page_size_bytes = len(response.content)  # Size of the HTML page in bytes

        # Simplified formula for estimating energy and carbon footprint (values in grams and kWh)
        co2_per_kb = 0.2  # Approximate CO2 emission per KB
        energy_per_kb = 0.001  # Energy usage per KB in kWh

        page_size_kb = page_size_bytes / 1024
        co2_emitted = co2_per_kb * page_size_kb
        energy_usage = energy_per_kb * page_size_kb

        return {
            "html_initial_size": f"{page_size_kb:.2f} KB",
            "co2_initial_load": f"{co2_emitted:.2f} grams",
            "energy_usage": f"{energy_usage:.2f} kWh",
            "co2_emitted": f"{co2_emitted:.2f} grams"
        }
    except Exception as e:
        return {
            "html_initial_size": "N/A",
            "co2_initial_load": "N/A",
            "energy_usage": "N/A",
            "co2_emitted": "N/A",
            "error": str(e)
        }

def find_subdomains(domain):
    subdomains = []
    wordlist = [
    "www", "mail", "ftp", "test", "blog", "dev", "api", "shop", "staging", "admin", 
    "login", "webmail", "forum", "news", "dashboard", "beta", "portal", "secure", 
    "store", "support", "status", "mx", "ns1", "ns2", "smtp", "imap", "pop", "chat", 
    "docs", "static", "img", "cdn", "files", "download", "media", "upload", "video", 
    "payments", "gateway", "app", "server", "db", "data", "cache", "backend", 
    "frontend", "api2", "old", "new", "backup", "dev1", "test1", "qa", "stage", 
    "uat", "demo", "prod", "production", "help", "jobs", "career", "signup", 
    "register", "auth", "sso", "assets", "sitemap", "robots", "feed", "proxy", 
    "billing", "invoice", "client", "customer", "partners", "partner", "user", 
    "users", "account", "accounts", "affiliate", "affiliates", "cms", "crm", 
    "erp", "devops", "monitor", "api-dev", "dns", "autodiscover", "calendar", 
    "events", "tickets", "ticket", "meet", "conference", "stats", "analytics", 
    "graph", "metrics", "ci", "git", "gitlab", "bitbucket", "svn", "pki", "ssl", 
    "cloud", "vps", "domain", "redirect", "redirector", "docs", "web", "home", 
    "office", "crm", "devtools", "tools", "monitoring", "search", "explore", 
    "review", "book", "library", "image", "gallery", "cdn", "video", "music", 
    "podcast", "radio", "storefront", "ecommerce", "shop", "market", "service", 
    "ads", "ad", "news", "login", "logout", "signup", "register", "cart", "checkout", 
    "booking", "reservation", "meeting", "health", "forum", "community", "groups", 
    "team", "teams", "vpn", "tunnel", "proxy", "translate", "files", "manager", 
    "upload", "download", "static", "dynamic"
]


    for subdomain in wordlist:
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(full_domain, 'A')  # Check if the subdomain has an A record
            subdomains.append(full_domain)
        except dns.resolver.NXDOMAIN:
            # No such domain, skip it
            pass
        except dns.resolver.NoAnswer:
            # The server doesn't provide an answer, skip it
            pass
        except Exception as e:
            print(f"Error checking {full_domain}: {e}")
            pass

    return subdomains

@app.route('/check', methods=['POST'])
def check_website():
    domain_input = request.form['domain']
    domain = domain_input.strip().replace('http://', '').replace('https://', '').split('/')[0]

    ip_address = get_ip(domain)
    ssl_info = get_ssl_info(domain)
    whois_info = get_whois_info(domain)
    dns_info = get_dns_info(domain)
    censys_info = get_censys_info(ip_address)  # Use Censys instead of Shodan
    virustotal_info = get_virustotal_info(domain)
    headers_info = get_headers(domain)  # Get the headers for the domain
    server_status = check_server_status(domain)
    dns_servers_info = get_dns_servers(domain)
    security_info = check_security_features(domain)
    redirects = check_redirects(domain)
    linked_pages = get_linked_pages(domain)
    crawl_rules = check_crawl_rules(domain)
    carbon_footprint = calculate_carbon_footprint(domain)
    subdomains = find_subdomains(domain)


    if isinstance(ssl_info, dict):
        ssl_info_formatted = "\n".join([f"{key}: {value}" for key, value in ssl_info.items()])
    else:
        ssl_info_formatted = ssl_info

    # Check if Censys data is valid
    if isinstance(censys_info, dict):
        # Pass the censys_info dictionary to the template
        censys_info_formatted = censys_info  # No need to format it into a string here
    else:
        # Otherwise, it's an error message
        censys_info_formatted = censys_info

    return render_template(
        'result.html',
        domain=domain,
        ip=ip_address,
        ssl_info=ssl_info_formatted,
        whois_info=whois_info,
        dns_info=dns_info,
        censys_info=censys_info_formatted,
        virustotal_info=virustotal_info,
        headers_info=headers_info,
        server_status=server_status,
        dns_servers_info=dns_servers_info,
        security_info=security_info,
        redirects=redirects,
        linked_pages=linked_pages,
        crawl_rules=crawl_rules,
        carbon_footprint=carbon_footprint,
        subdomains=subdomains
    )

if __name__ == '__main__':
    app.run(debug=True)
