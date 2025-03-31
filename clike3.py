#!/usr/bin/env python3
"""
CLIKE - Command Line URL Penetration Testing Tool
A colorful command-line URL penetration testing tool with ASCII art logo, 
timestamps, and comprehensive help functionality.

Compatible with Termux and other Android environments.
"""

import argparse
import csv
import datetime
import dns.resolver
import json
import os
import re
import requests
import socket
import sys
import time
import urllib.parse
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple, Union, Optional, Any
# trafilatura is optional and not used in this version

# Initialize colorama
init(autoreset=True)

# ASCII Art Logo
LOGO = f"""
{Fore.YELLOW}
 _______  __       __  __   __  _______ 
|       ||  |     |  ||  | |  ||       |
|       ||  |     |  ||  |_|  ||    ___|
|       ||  |     |  ||       ||   |___ 
|      _||  |     |  ||       ||    ___|
|     |_ |  |_____| || ||_|| ||   |___ 
|_______||_________||_|   |_||_______|
                             
{Fore.RED}|\\\\{Fore.YELLOW}__{Fore.RED}\\{Fore.YELLOW}____{Fore.RED}==={Fore.YELLOW}> {Fore.RED}[{Fore.YELLOW} URL PENETRATION TESTER {Fore.RED}]
{Style.RESET_ALL}
"""

# Global variables
USER_AGENT = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 15  # Increased timeout for mobile networks
LITE_MODE = False
THREAT_SCORES = {}  # For tracking threat scores during a scan
THREAT_DETAILS = {}  # For storing details about threat scores
DISABLE_LITE_MODE = False  # Flag to disable lite mode for Termux


def get_timestamp() -> str:
    """Return a formatted timestamp [HOUR, MINUTE, SECOND]"""
    now = datetime.datetime.now()
    return f"{Fore.CYAN}[{now.hour}, {now.minute}, {now.second}]{Style.RESET_ALL}"


def print_info(msg: str, prefix: str = "INFO") -> None:
    """Print info message with timestamp"""
    print(f"{get_timestamp()} {Fore.GREEN}[{prefix}]{Style.RESET_ALL} {msg}")


def print_warning(msg: str, prefix: str = "WARNING") -> None:
    """Print warning message with timestamp"""
    print(f"{get_timestamp()} {Fore.YELLOW}[{prefix}]{Style.RESET_ALL} {msg}")


def print_error(msg: str, prefix: str = "ERROR") -> None:
    """Print error message with timestamp"""
    print(f"{get_timestamp()} {Fore.RED}[{prefix}]{Style.RESET_ALL} {msg}")


def print_result(title: str, result: Union[str, dict, list]) -> None:
    """Print results in a formatted way"""
    print(f"\n{Fore.YELLOW}===== {title} ====={Style.RESET_ALL}")
    
    if isinstance(result, (dict, list)):
        try:
            formatted_result = json.dumps(result, indent=2)
            print(f"{Fore.WHITE}{formatted_result}{Style.RESET_ALL}\n")
        except:
            print(f"{Fore.WHITE}{result}{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.WHITE}{result}{Style.RESET_ALL}\n")


def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def normalize_url(url: str) -> str:
    """Normalize URL by ensuring it starts with http:// or https://"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def fetch_url(url: str) -> Tuple[Optional[requests.Response], Optional[str]]:
    """Fetch URL and return response object and error message if any"""
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        response.raise_for_status()
        return response, None
    except requests.exceptions.RequestException as e:
        return None, str(e)


def check_url(url: str) -> Optional[requests.Response]:
    """Check if URL is valid and accessible, return response if successful"""
    if not is_valid_url(url):
        print_error(f"Invalid URL format: {url}")
        return None

    print_info(f"Checking URL: {url}")
    response, error = fetch_url(url)
    
    if error:
        print_error(f"Failed to access URL: {error}")
        return None
    
    print_info(f"Successfully connected to {url}")
    return response


def get_page_title(soup: BeautifulSoup) -> str:
    """Get the title of the page"""
    title = soup.title.string if soup.title else "No title found"
    return title


def get_dns_info(domain: str) -> Dict:
    """Get DNS information for the domain"""
    dns_info = {
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": []
    }
    
    try:
        # Get A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            dns_info["A"] = [record.to_text() for record in a_records]
        except:
            pass
        
        # Get MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_info["MX"] = [record.to_text() for record in mx_records]
        except:
            pass
        
        # Get NS records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_info["NS"] = [record.to_text() for record in ns_records]
        except:
            pass
        
        # Get TXT records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            dns_info["TXT"] = [record.to_text() for record in txt_records]
        except:
            pass
            
        # Try to get IP address
        try:
            ip = socket.gethostbyname(domain)
            dns_info["IP"] = ip
        except:
            dns_info["IP"] = "Could not resolve IP"
            
    except Exception as e:
        print_error(f"Error getting DNS info: {str(e)}")
    
    return dns_info


def check_url_redirects(url: str) -> List[Dict]:
    """Check for URL redirects"""
    redirects = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        
        for resp in response.history:
            redirects.append({
                "status_code": resp.status_code,
                "url": resp.url,
                "location": resp.headers.get('Location', 'N/A')
            })
            
        # Add final destination
        redirects.append({
            "status_code": response.status_code,
            "url": response.url,
            "location": "Final destination"
        })
        
    except Exception as e:
        print_error(f"Error checking redirects: {str(e)}")
    
    return redirects


def extract_forms(soup: BeautifulSoup) -> List[Dict]:
    """Extract forms from the page"""
    forms_data = []
    
    forms = soup.find_all('form')
    for i, form in enumerate(forms):
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        
        inputs = []
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', '')
            input_name = input_tag.get('name', '')
            input_value = input_tag.get('value', '')
            
            inputs.append({
                'type': input_type,
                'name': input_name,
                'value': input_value if input_type not in ('password', 'hidden') else '[PROTECTED]'
            })
        
        forms_data.append({
            'id': i + 1,
            'action': action,
            'method': method,
            'inputs': inputs
        })
    
    return forms_data


def get_network_info(url: str) -> Dict:
    """Get network information about the URL"""
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    
    try:
        response, error = fetch_url(url)
        if error:
            return {"error": error}
        
        network_info = {
            "domain": domain,
            "ip": socket.gethostbyname(domain),
            "port": parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
            "protocol": parsed_url.scheme,
            "response_time": response.elapsed.total_seconds(),
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
        
        return network_info
    except Exception as e:
        return {"error": str(e)}


def extract_meta_tags(soup: BeautifulSoup) -> List[Dict]:
    """Extract meta tags from the page"""
    meta_tags = []
    
    for meta in soup.find_all('meta'):
        meta_data = {}
        
        # Extract common attributes
        for attr in ['name', 'property', 'content', 'charset', 'http-equiv']:
            if meta.get(attr):
                meta_data[attr] = meta.get(attr)
                
        if meta_data:
            meta_tags.append(meta_data)
    
    return meta_tags


def get_cookies(response: requests.Response) -> Dict:
    """Get cookies from the response"""
    cookies = {}
    
    for cookie in response.cookies:
        cookies[cookie.name] = {
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "expires": cookie.expires,
            "secure": cookie.secure,
            "http_only": cookie.has_nonstandard_attr('HttpOnly')
        }
    
    return cookies


def check_https_security(url: str, response: requests.Response) -> Dict:
    """Check HTTPS security"""
    parsed_url = urllib.parse.urlparse(url)
    security_info = {
        "is_https": parsed_url.scheme == 'https',
        "hsts": 'Strict-Transport-Security' in response.headers,
        "content_security_policy": 'Content-Security-Policy' in response.headers,
        "x_content_type_options": 'X-Content-Type-Options' in response.headers,
        "x_frame_options": 'X-Frame-Options' in response.headers,
        "x_xss_protection": 'X-XSS-Protection' in response.headers
    }
    
    return security_info


def count_images(soup: BeautifulSoup) -> int:
    """Count images on the page"""
    return len(soup.find_all('img'))


def extract_links(soup: BeautifulSoup, base_url: str) -> Dict:
    """Extract links from the page"""
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc
    
    all_links = soup.find_all('a', href=True)
    
    internal_links = []
    external_links = []
    
    for link in all_links:
        href = link['href']
        
        # Skip empty, javascript, and anchor links
        if not href or href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
            continue
            
        # Handle relative URLs
        if not href.startswith(('http://', 'https://')):
            # Convert relative URL to absolute
            href = urllib.parse.urljoin(base_url, href)
        
        parsed_href = urllib.parse.urlparse(href)
        
        # Check if internal or external
        if parsed_href.netloc == base_domain or not parsed_href.netloc:
            internal_links.append(href)
        else:
            external_links.append(href)
    
    return {
        "total": len(all_links),
        "internal": internal_links,
        "external": external_links
    }


def check_url_availability(url_list: List[str]) -> Dict:
    """Check availability of multiple URLs"""
    results = {}
    
    def check_single_url(url):
        try:
            response = requests.head(url, headers=HEADERS, timeout=TIMEOUT)
            return url, {
                "status_code": response.status_code,
                "available": 200 <= response.status_code < 400
            }
        except:
            return url, {
                "status_code": 0,
                "available": False
            }
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        for url, result in executor.map(check_single_url, url_list):
            results[url] = result
    
    return results


def count_words(soup: BeautifulSoup) -> int:
    """Count words on the page"""
    text = soup.get_text(separator=' ', strip=True)
    words = re.findall(r'\w+', text)
    return len(words)


def extract_js_tags(soup: BeautifulSoup) -> List[str]:
    """Extract JavaScript tags from the page"""
    js_tags = []
    
    # External scripts
    for script in soup.find_all('script', src=True):
        js_tags.append(script['src'])
    
    # Count inline scripts
    inline_scripts = len(soup.find_all('script', src=False))
    if inline_scripts > 0:
        js_tags.append(f"{inline_scripts} inline script(s)")
    
    return js_tags


def extract_css_resources(soup: BeautifulSoup) -> List[str]:
    """Extract CSS resources from the page"""
    css_resources = []
    
    # External stylesheets
    for link in soup.find_all('link', rel="stylesheet"):
        if link.get('href'):
            css_resources.append(link['href'])
    
    # Style tags
    style_tags = len(soup.find_all('style'))
    if style_tags > 0:
        css_resources.append(f"{style_tags} inline style tag(s)")
    
    # Inline styles
    inline_styles = len(soup.find_all(style=True))
    if inline_styles > 0:
        css_resources.append(f"{inline_styles} element(s) with inline style")
    
    return css_resources


def check_sitemap(domain: str) -> Dict:
    """Check for sitemap.xml"""
    sitemap_info = {
        "exists": False,
        "url_count": 0,
        "sitemap_url": f"http://{domain}/sitemap.xml"
    }
    
    try:
        response, error = fetch_url(sitemap_info["sitemap_url"])
        
        if error or response.status_code != 200:
            # Try HTTPS if HTTP fails
            sitemap_info["sitemap_url"] = f"https://{domain}/sitemap.xml"
            response, error = fetch_url(sitemap_info["sitemap_url"])
            
        if not error and response.status_code == 200:
            sitemap_info["exists"] = True
            # Count URLs in sitemap
            sitemap_content = response.text
            urls = re.findall(r'<loc>(.*?)</loc>', sitemap_content)
            sitemap_info["url_count"] = len(urls)
            
    except Exception as e:
        sitemap_info["error"] = str(e)
    
    return sitemap_info


def check_robots_txt(domain: str) -> Dict:
    """Check for robots.txt"""
    robots_info = {
        "exists": False,
        "robots_url": f"http://{domain}/robots.txt",
        "content": ""
    }
    
    try:
        response, error = fetch_url(robots_info["robots_url"])
        
        if error or response.status_code != 200:
            # Try HTTPS if HTTP fails
            robots_info["robots_url"] = f"https://{domain}/robots.txt"
            response, error = fetch_url(robots_info["robots_url"])
            
        if not error and response.status_code == 200:
            robots_info["exists"] = True
            robots_info["content"] = response.text
            
    except Exception as e:
        robots_info["error"] = str(e)
    
    return robots_info


def count_videos(soup: BeautifulSoup) -> int:
    """Count videos on the page"""
    video_count = 0
    
    # Count video tags
    video_count += len(soup.find_all('video'))
    
    # Count YouTube iframes
    youtube_iframes = soup.find_all('iframe', src=lambda s: s and ('youtube.com' in s or 'youtu.be' in s))
    video_count += len(youtube_iframes)
    
    # Count Vimeo iframes
    vimeo_iframes = soup.find_all('iframe', src=lambda s: s and 'vimeo.com' in s)
    video_count += len(vimeo_iframes)
    
    return video_count


def check_broken_links(links: List[str]) -> Dict:
    """Check for broken links"""
    results = {}
    
    if LITE_MODE and not DISABLE_LITE_MODE:
        # In lite mode, limit to 10 links
        links = links[:10]
        print_warning("Lite mode enabled, checking only first 10 links")
    
    def check_link(link):
        try:
            response = requests.head(link, headers=HEADERS, timeout=TIMEOUT)
            return link, {
                "status_code": response.status_code,
                "broken": response.status_code >= 400
            }
        except:
            return link, {
                "status_code": 0,
                "broken": True
            }
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        for link, result in executor.map(check_link, links):
            results[link] = result
    
    return results


def check_mobile_support(soup: BeautifulSoup) -> Dict:
    """Check for mobile support"""
    mobile_support = {
        "viewport": False,
        "media_queries": False,
        "responsive_meta": False
    }
    
    # Check viewport meta tag
    viewport = soup.find('meta', attrs={'name': 'viewport'})
    if viewport:
        mobile_support["viewport"] = True
        mobile_support["viewport_content"] = viewport.get('content', '')
    
    # Check for media queries in style tags
    for style in soup.find_all('style'):
        if style.string and '@media' in style.string:
            mobile_support["media_queries"] = True
            break
    
    # Check for mobile-specific meta tags
    mobile_meta = soup.find('meta', attrs={'name': 'mobile-web-app-capable'})
    apple_meta = soup.find('meta', attrs={'name': 'apple-mobile-web-app-capable'})
    if mobile_meta or apple_meta:
        mobile_support["responsive_meta"] = True
    
    return mobile_support


def extract_header_tags(soup: BeautifulSoup) -> Dict:
    """Extract header tags (h1-h6) from the page"""
    headers = {}
    
    for i in range(1, 7):
        tag = f'h{i}'
        headers[tag] = []
        
        for header in soup.find_all(tag):
            text = header.get_text(strip=True)
            if text:
                headers[tag].append(text)
    
    return headers


def get_page_language(soup: BeautifulSoup) -> str:
    """Get the language of the page"""
    html_tag = soup.find('html')
    
    if html_tag and html_tag.get('lang'):
        return html_tag.get('lang')
    
    # Try to find language meta tag
    lang_meta = soup.find('meta', attrs={'http-equiv': 'content-language'})
    if lang_meta and lang_meta.get('content'):
        return lang_meta.get('content')
    
    return "Not specified"


def export_text_content(url: str) -> str:
    """
    Export main text content from the URL
    
    This function extracts the main content of a website in a clean, readable format
    that's easier to process than raw HTML. The extraction removes navigation elements,
    ads, and other non-content areas of the page.
    """
    try:
        # Use BeautifulSoup for content extraction
        response, error = fetch_url(url)
        if error:
            return f"Error fetching URL: {error}"
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove script and style elements and navigational elements
            for element in soup(["script", "style", "header", "footer", "nav", "aside", "iframe"]):
                element.extract()
            
            # Get text
            text = soup.get_text(separator='\n')
            
            # Break into lines and remove leading/trailing space
            lines = (line.strip() for line in text.splitlines())
            # Break multi-headlines into a line each
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            # Drop blank lines
            text = '\n'.join(chunk for chunk in chunks if chunk)
            
            # If text is too long, truncate it
            if len(text) > 5000 and LITE_MODE:
                text = text[:5000] + "...\n[Text truncated due to size. Enable full mode for complete content]"
            
            return text
        except Exception as inner_e:
            return f"Error extracting with BeautifulSoup: {str(inner_e)}"
    except Exception as e:
        return f"Error extracting text: {str(e)}"


def check_sql_leak(soup: BeautifulSoup) -> Dict:
    """Check for potential SQL error leaks"""
    sql_errors = {
        "found": False,
        "potential_leaks": []
    }
    
    # Common SQL error patterns
    error_patterns = [
        r'SQL syntax.*?MySQL',
        r'Warning.*?mysql_',
        r'valid MySQL result',
        r'MySqlClient\.',
        r'ORA-[0-9]{5}',
        r'Oracle error',
        r'SQL Server.*?Error',
        r'Microsoft SQL Server',
        r'PostgreSQL.*?ERROR',
        r'Driver.*? SQL[\-\_\ ]*Server',
        r'ODBC SQL Server Driver',
        r'SQLite/JDBCDriver',
        r'SQLException',
        r'Syntax error.*?in query expression',
        r'DB2 SQL error'
    ]
    
    text = soup.get_text()
    
    for pattern in error_patterns:
        matches = re.findall(pattern, text)
        if matches:
            sql_errors["found"] = True
            for match in matches:
                sql_errors["potential_leaks"].append(match)
    
    return sql_errors


def extract_inputs(soup: BeautifulSoup) -> List[Dict]:
    """Extract input fields from the page"""
    inputs = []
    
    for input_tag in soup.find_all('input'):
        input_data = {
            "type": input_tag.get('type', 'text'),
            "name": input_tag.get('name', ''),
            "id": input_tag.get('id', ''),
            "required": 'required' in input_tag.attrs,
            "placeholder": input_tag.get('placeholder', '')
        }
        inputs.append(input_data)
    
    return inputs


def extract_buttons(soup: BeautifulSoup) -> List[Dict]:
    """Extract buttons from the page"""
    buttons = []
    
    # Find button elements
    for button in soup.find_all('button'):
        button_data = {
            "type": button.get('type', ''),
            "text": button.get_text(strip=True),
            "id": button.get('id', ''),
            "class": button.get('class', '')
        }
        buttons.append(button_data)
    
    # Find input buttons
    for input_button in soup.find_all('input', type=lambda t: t in ['button', 'submit', 'reset']):
        button_data = {
            "type": input_button.get('type', ''),
            "value": input_button.get('value', ''),
            "id": input_button.get('id', ''),
            "class": input_button.get('class', '')
        }
        buttons.append(button_data)
    
    return buttons


def extract_tables(soup: BeautifulSoup) -> List[Dict]:
    """Extract tables from the page"""
    tables = []
    
    for i, table in enumerate(soup.find_all('table')):
        table_data = {
            "id": table.get('id', f'table_{i+1}'),
            "rows": len(table.find_all('tr')),
            "headers": []
        }
        
        # Extract headers
        headers = table.find_all('th')
        for header in headers:
            table_data["headers"].append(header.get_text(strip=True))
        
        tables.append(table_data)
    
    return tables


def extract_iframes(soup: BeautifulSoup) -> List[Dict]:
    """Extract iframes from the page"""
    iframes = []
    
    for iframe in soup.find_all('iframe'):
        iframe_data = {
            "src": iframe.get('src', ''),
            "id": iframe.get('id', ''),
            "name": iframe.get('name', ''),
            "width": iframe.get('width', ''),
            "height": iframe.get('height', '')
        }
        iframes.append(iframe_data)
    
    return iframes


def extract_assets(soup: BeautifulSoup, base_url: str) -> Dict:
    """Extract assets from the page"""
    assets = {
        "images": [],
        "scripts": [],
        "stylesheets": [],
        "fonts": [],
        "videos": [],
        "audios": []
    }
    
    # Extract images
    for img in soup.find_all('img'):
        if img.get('src'):
            assets["images"].append(urllib.parse.urljoin(base_url, img['src']))
    
    # Extract scripts
    for script in soup.find_all('script', src=True):
        assets["scripts"].append(urllib.parse.urljoin(base_url, script['src']))
    
    # Extract stylesheets
    for link in soup.find_all('link', rel="stylesheet"):
        if link.get('href'):
            assets["stylesheets"].append(urllib.parse.urljoin(base_url, link['href']))
    
    # Extract fonts
    for link in soup.find_all('link', rel=lambda r: r and 'font' in r):
        if link.get('href'):
            assets["fonts"].append(urllib.parse.urljoin(base_url, link['href']))
    
    # Extract videos
    for video in soup.find_all('video'):
        if video.get('src'):
            assets["videos"].append(urllib.parse.urljoin(base_url, video['src']))
        for source in video.find_all('source'):
            if source.get('src'):
                assets["videos"].append(urllib.parse.urljoin(base_url, source['src']))
    
    # Extract audios
    for audio in soup.find_all('audio'):
        if audio.get('src'):
            assets["audios"].append(urllib.parse.urljoin(base_url, audio['src']))
        for source in audio.find_all('source'):
            if source.get('src'):
                assets["audios"].append(urllib.parse.urljoin(base_url, source['src']))
    
    return assets


def extract_keywords(soup: BeautifulSoup) -> List[str]:
    """Extract keywords from meta tags"""
    keywords = []
    
    # Try to get meta keywords
    meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
    if meta_keywords and meta_keywords.get('content'):
        keywords = [k.strip() for k in meta_keywords.get('content').split(',')]
    
    return keywords


def calculate_threat_score(check_name: str, data: Any) -> int:
    """
    Calculate threat score for a specific check
    Returns an integer score from 0-100 (0: no threat, 100: maximum threat)
    """
    score = 0
    
    # Score is set based on check type and result
    if check_name == "security":
        # HTTPS security check
        if isinstance(data, dict):
            if not data.get("is_https", False):
                score += 30  # Not using HTTPS is a significant risk
            if not data.get("hsts", False):
                score += 10  # No HSTS header
            if not data.get("content_security_policy", False):
                score += 10  # No Content Security Policy
            if not data.get("x_content_type_options", False):
                score += 5   # No X-Content-Type-Options header
            if not data.get("x_frame_options", False):
                score += 5   # No X-Frame-Options header
            if not data.get("x_xss_protection", False):
                score += 5   # No X-XSS-Protection header
    
    elif check_name == "mixed_content":
        # Mixed content check
        if isinstance(data, dict) and data.get("has_mixed_content", False):
            score += 40  # Mixed content is a significant security risk
    
    elif check_name == "cookie_sec":
        # Cookie security check
        if isinstance(data, dict):
            cookies_without_secure = data.get("cookies_without_secure", 0)
            cookies_without_httponly = data.get("cookies_without_httponly", 0)
            cookies_without_samesite = data.get("cookies_without_samesite", 0)
            
            score += cookies_without_secure * 10  # 10 points per insecure cookie
            score += cookies_without_httponly * 8  # 8 points per cookie without HttpOnly
            score += cookies_without_samesite * 5  # 5 points per cookie without SameSite
    
    elif check_name == "clickjacking":
        # Clickjacking protection check
        if isinstance(data, dict) and not data.get("protected", False):
            score += 25  # No clickjacking protection
    
    elif check_name == "csp":
        # Content Security Policy check
        if isinstance(data, dict):
            if not data.get("has_csp", False):
                score += 20  # No CSP header
            if data.get("has_unsafe_inline", False):
                score += 10  # Has unsafe-inline directive
            if data.get("has_unsafe_eval", False):
                score += 10  # Has unsafe-eval directive
    
    elif check_name == "iframe_security":
        # Iframe security check
        if isinstance(data, dict):
            insecure_iframes = len(data.get("insecure_iframes", []))
            score += insecure_iframes * 15  # 15 points per insecure iframe
    
    elif check_name == "ssl":
        # SSL/TLS certificate check
        if isinstance(data, dict):
            if not data.get("valid", True):
                score += 40  # Invalid SSL certificate
            if data.get("expired", False):
                score += 40  # Expired SSL certificate
            if data.get("self_signed", False):
                score += 20  # Self-signed certificate
            if data.get("weak_signature", False):
                score += 15  # Weak signature algorithm
    
    elif check_name == "vulns":
        # Vulnerability check
        if isinstance(data, dict):
            vuln_count = len(data.get("vulnerabilities", []))
            score += vuln_count * 20  # 20 points per detected vulnerability
    
    elif check_name == "passwords":
        # Password form security
        if isinstance(data, dict):
            insecure_forms = data.get("insecure_password_forms", 0)
            score += insecure_forms * 30  # 30 points per insecure password form
    
    elif check_name == "deserialize":
        # Insecure deserialization
        if isinstance(data, dict) and data.get("potentially_vulnerable", False):
            score += 35  # Potentially vulnerable to insecure deserialization
    
    elif check_name == "leaks":
        # Information leaks
        if isinstance(data, dict):
            sensitive_info = len(data.get("sensitive_info", []))
            score += sensitive_info * 15  # 15 points per leaked sensitive info
    
    elif check_name == "sec_headers":
        # Security headers
        if isinstance(data, dict):
            missing_headers = data.get("missing_headers", [])
            score += len(missing_headers) * 5  # 5 points per missing security header
    
    # Cap the score at 100
    return min(score, 100)


def get_threat_category(score: int) -> Tuple[str, str]:
    """Return human-readable threat category and color based on score"""
    if score < 20:
        return "Low Risk", Fore.GREEN
    elif score < 40:
        return "Moderate Risk", Fore.CYAN
    elif score < 60:
        return "Medium Risk", Fore.YELLOW
    elif score < 80:
        return "High Risk", Fore.YELLOW + Style.BRIGHT
    else:
        return "Critical Risk", Fore.RED + Style.BRIGHT


def print_threat_score(domain: str, score: int, details: Dict = None) -> None:
    """Print the threat score with a colorful indicator"""
    category, color = get_threat_category(score)
    
    # Create a visual bar for the threat level
    bar_length = 50
    filled_length = int(round(bar_length * score / 100))
    bar = ('█' * filled_length) + ('░' * (bar_length - filled_length))
    
    # Choose color gradient based on score
    if score < 20:
        bar_color = Fore.GREEN
    elif score < 40:
        bar_color = Fore.CYAN
    elif score < 60:
        bar_color = Fore.YELLOW
    elif score < 80:
        bar_color = Fore.YELLOW + Style.BRIGHT
    else:
        bar_color = Fore.RED + Style.BRIGHT
    
    print("\n" + "=" * 70)
    print(f"{Fore.WHITE}{Style.BRIGHT}SECURITY THREAT ASSESSMENT: {domain}{Style.RESET_ALL}")
    print("=" * 70)
    print(f"{color}Threat Score: {score}/100 - {category}{Style.RESET_ALL}")
    print(f"{bar_color}{bar}{Style.RESET_ALL}")
    print(f"{score}%")
    
    # Print details of what contributed to the score
    if details and len(details) > 0:
        print("\nRisk Factors:")
        for check, info in details.items():
            if info["score"] > 0:
                cat, detail_color = get_threat_category(info["score"])
                print(f" {detail_color}• {check}: {info['score']} points - {info['reason']}{Style.RESET_ALL}")
    
    print("=" * 70 + "\n")


def calculate_overall_threat_score(url: str) -> Tuple[int, Dict]:
    """Calculate the overall threat score for a URL based on all checks"""
    global THREAT_SCORES, THREAT_DETAILS
    
    if url not in THREAT_SCORES:
        return 0, {}
    
    # Get all check scores for this URL
    scores = THREAT_SCORES[url]
    details = THREAT_DETAILS[url]
    
    if not scores:
        return 0, {}
    
    # Calculate a weighted average of all scores
    # More critical checks get higher weights
    weights = {
        "security": 1.2,
        "ssl": 1.5,
        "vulns": 1.5,
        "csp": 1.2,
        "clickjacking": 1.0,
        "mixed_content": 1.2,
        "passwords": 1.3,
        "iframe_security": 0.8,
        "cookie_sec": 1.0,
        "deserialize": 1.0,
        "leaks": 1.1,
        "sec_headers": 0.9
    }
    
    total_score = 0
    total_weight = 0
    
    for check, score in scores.items():
        weight = weights.get(check, 1.0)
        total_score += score * weight
        total_weight += weight
    
    # Avoid division by zero
    if total_weight == 0:
        return 0, details
    
    # Calculate the weighted average score
    overall_score = int(round(total_score / total_weight))
    
    # Cap score at 100
    return min(overall_score, 100), details


def run_all_checks(url: str, soup: BeautifulSoup, response: requests.Response) -> None:
    """Run all available checks"""
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    
    print_info("Running all checks, this may take some time...")
    
    # Title check
    title = get_page_title(soup)
    print_result("Page Title", title)
    
    # DNS info
    dns_info = get_dns_info(domain)
    print_result("DNS Information", dns_info)
    
    # Redirects
    redirects = check_url_redirects(url)
    print_result("URL Redirects", redirects)
    
    # Forms
    forms = extract_forms(soup)
    print_result("Forms", forms)
    
    # Network info
    network_info = get_network_info(url)
    print_result("Network Information", network_info)
    
    # Meta tags
    meta_tags = extract_meta_tags(soup)
    print_result("Meta Tags", meta_tags)
    
    # Cookies
    cookies = get_cookies(response)
    print_result("Cookies", cookies)
    
    # HTTPS security
    security = check_https_security(url, response)
    print_result("HTTPS Security", security)
    
    # Images count
    images_count = count_images(soup)
    print_result("Images Count", images_count)
    
    # Links analysis
    links = extract_links(soup, url)
    print_result("Links Analysis", {
        "Total Links": len(links["internal"]) + len(links["external"]),
        "Internal Links": len(links["internal"]),
        "External Links": len(links["external"])
    })
    
    # Word count
    words = count_words(soup)
    print_result("Word Count", words)
    
    # JavaScript tags
    js_tags = extract_js_tags(soup)
    print_result("JavaScript Tags", js_tags)
    
    # CSS resources
    css_resources = extract_css_resources(soup)
    print_result("CSS Resources", css_resources)
    
    # Sitemap check
    sitemap = check_sitemap(domain)
    print_result("Sitemap Check", sitemap)
    
    # Robots.txt check
    robots = check_robots_txt(domain)
    print_result("Robots.txt Check", robots)
    
    # Videos count
    videos_count = count_videos(soup)
    print_result("Videos Count", videos_count)
    
    # Mobile support
    mobile = check_mobile_support(soup)
    print_result("Mobile Support", mobile)
    
    # Header tags
    headers = extract_header_tags(soup)
    print_result("Header Tags", headers)
    
    # Page language
    language = get_page_language(soup)
    print_result("Page Language", language)
    
    # SQL leak check
    sql_leak = check_sql_leak(soup)
    print_result("SQL Leak Check", sql_leak)
    
    # CORS policy check
    cors_policy = check_cors_policy(response)
    print_result("CORS Policy", cors_policy)
    
    # Content Security Policy check
    csp_policy = check_csp_policy(response)
    print_result("Content Security Policy", csp_policy)
    
    # Feature Policy check
    feature_policy = check_feature_policy(response)
    print_result("Feature/Permissions Policy", feature_policy)
    
    # Sensitive files check
    sensitive_files = check_for_sensitive_files(domain)
    print_result("Sensitive Files Check", sensitive_files)
    
    # Common subdomains check
    subdomains = check_subdomains(domain, False)
    print_result("Common Subdomains", subdomains)
    
    # WAF detection
    waf = check_waf_presence(url)
    print_result("WAF Detection", waf)
    
    # Security headers check
    security_headers = check_security_headers(response)
    print_result("Security Headers", security_headers)
    
    # Information leaks check
    leaks = check_for_leaks(soup, response)
    print_result("Information Leaks", leaks)
    
    # Open ports check (common only)
    if not LITE_MODE:
        ports = check_open_ports(domain, True)
        print_result("Open Ports (Common)", ports)
    
    # SSL/TLS information
    ssl_info = check_ssl_info(domain)
    print_result("SSL/TLS Information", ssl_info)
    
    # HTTP methods check
    methods = check_http_methods(url)
    print_result("HTTP Methods", methods)
    
    # Cookie security check
    cookie_security = check_cookie_security(response)
    print_result("Cookie Security", cookie_security)
    
    # Caching headers check
    cache_headers = check_caching_headers(response)
    print_result("Caching Headers", cache_headers)
    
    # Server information
    server_info = extract_server_info(response)
    print_result("Server Information", server_info)
    
    # Vulnerability checks
    vulnerabilities = check_for_vulns(url, soup)
    print_result("Vulnerability Checks", vulnerabilities)
    
    # Clickjacking protection check
    clickjacking = check_for_clickjacking(response)
    print_result("Clickjacking Protection", clickjacking)
    
    # File upload forms analysis
    upload_forms = check_file_upload_forms(soup)
    print_result("File Upload Forms", upload_forms)
    
    # Password forms analysis
    password_forms = check_password_forms(soup)
    print_result("Password Forms", password_forms)
    
    # API endpoints detection
    api_endpoints = check_api_endpoints(soup, url)
    print_result("API Endpoints", api_endpoints)
    
    # Server performance check
    performance = check_server_status(url)
    print_result("Server Performance", performance)
    
    # Email protection check
    email_protection = check_email_protection(soup)
    print_result("Email Protection", email_protection)
    
    # Form honeypots check
    honeypots = check_for_honeypots(soup)
    print_result("Form Honeypots", honeypots)
    
    # Iframe security check
    iframe_security = check_iframe_security(soup)
    print_result("Iframe Security", iframe_security)
    
    # Third-party resources analysis
    third_party = check_third_party_resources(soup, url)
    print_result("Third-Party Resources", third_party)
    
    # Content types analysis
    content_types = check_content_types(response)
    print_result("Content Types", content_types)
    
    # Mixed content check
    mixed_content = check_mixed_content(soup, url)
    print_result("Mixed Content Check", mixed_content)
    
    # Insecure deserialization check
    deserialization = check_insecure_deserialization(soup)
    print_result("Insecure Deserialization Check", deserialization)


def process_url(url: str, args) -> None:
    """Process a single URL with the given arguments"""
    results = {}  # Store results for format_results option
    global THREAT_SCORES, THREAT_DETAILS
    
    # Initialize threat scores and details for this URL
    THREAT_SCORES[url] = {}
    THREAT_DETAILS[url] = {}
    
    # Normalize URL
    url = normalize_url(url)
    
    # Check URL and get response
    response = check_url(url)
    if not response:
        return
    
    # Parse HTML with BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Run all checks if requested
    if args.all:
        run_all_checks(url, soup, response)
        
        # Calculate and display the overall threat score
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        score, details = calculate_overall_threat_score(url)
        print_threat_score(domain, score, details)
        return
    
    # Individual checks based on arguments
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    
    if args.title:
        title = get_page_title(soup)
        print_result("Page Title", title)
    
    if args.dns:
        dns_info = get_dns_info(domain)
        print_result("DNS Information", dns_info)
    
    if args.redirects:
        redirects = check_url_redirects(url)
        print_result("URL Redirects", redirects)
    
    if args.forms:
        forms = extract_forms(soup)
        print_result("Forms", forms)
    
    if args.network:
        network_info = get_network_info(url)
        print_result("Network Information", network_info)
    
    if args.meta:
        meta_tags = extract_meta_tags(soup)
        print_result("Meta Tags", meta_tags)
    
    if args.cookies:
        cookies = get_cookies(response)
        print_result("Cookies", cookies)
    
    if args.security:
        security_info = check_https_security(url, response)
        print_result("HTTPS Security", security_info)
    
    if args.images:
        image_count = count_images(soup)
        print_result("Images Count", image_count)
    
    if args.links:
        links_info = extract_links(soup, url)
        print_result("Links Analysis", {
            "Total Links": len(links_info["internal"]) + len(links_info["external"]),
            "Internal Links": len(links_info["internal"]),
            "External Links": len(links_info["external"])
        })
    
    if args.external:
        links_info = extract_links(soup, url)
        print_result("External Links", links_info["external"])
    
    if args.available:
        links_info = extract_links(soup, url)
        all_links = links_info["internal"] + links_info["external"]
        availability = check_url_availability(all_links[:10])  # Limit to 10 links
        print_result("URL Availability", availability)
    
    if args.words:
        word_count = count_words(soup)
        print_result("Word Count", word_count)
    
    if args.js:
        js_tags = extract_js_tags(soup)
        print_result("JavaScript Tags", js_tags)
    
    if args.css:
        css_resources = extract_css_resources(soup)
        print_result("CSS Resources", css_resources)
    
    if args.sitemap:
        sitemap = check_sitemap(domain)
        print_result("Sitemap Check", sitemap)
    
    if args.robots:
        robots = check_robots_txt(domain)
        print_result("Robots.txt Check", robots)
    
    if args.videos:
        video_count = count_videos(soup)
        print_result("Videos Count", video_count)
    
    if args.broken:
        links_info = extract_links(soup, url)
        all_links = links_info["internal"] + links_info["external"]
        broken_links = check_broken_links(all_links)
        print_result("Broken Links", broken_links)
    
    if args.mobile:
        mobile_support = check_mobile_support(soup)
        print_result("Mobile Support", mobile_support)
    
    if args.headers:
        header_tags = extract_header_tags(soup)
        print_result("Header Tags", header_tags)
    
    if args.lang:
        language = get_page_language(soup)
        print_result("Page Language", language)
    
    if args.export:
        text_content = export_text_content(url)
        print_result("Text Content", text_content)
    
    if args.sql:
        sql_leak = check_sql_leak(soup)
        print_result("SQL Leak Check", sql_leak)
        
    # New additional checks
    if args.cors:
        cors_policy = check_cors_policy(response)
        print_result("CORS Policy", cors_policy)
        
    if args.csp:
        csp_policy = check_csp_policy(response)
        print_result("Content Security Policy", csp_policy)
        
    if args.feature_policy:
        feature_policy = check_feature_policy(response)
        print_result("Feature/Permissions Policy", feature_policy)
        
    if args.sensitive_files:
        sensitive_files = check_for_sensitive_files(domain)
        print_result("Sensitive Files Check", sensitive_files)
        
    if args.subdomains:
        use_wordlist = args.subdomain_wordlist if hasattr(args, 'subdomain_wordlist') else False
        subdomains = check_subdomains(domain, use_wordlist)
        print_result("Subdomains Check", subdomains)
        
    if args.waf:
        waf = check_waf_presence(url)
        print_result("WAF Detection", waf)
        
    if args.sec_headers:
        security_headers = check_security_headers(response)
        print_result("Security Headers", security_headers)
        
    if args.leaks:
        leaks = check_for_leaks(soup, response)
        print_result("Information Leaks", leaks)
        
    if args.ports:
        ports = check_open_ports(domain, True)  # Common ports only
        print_result("Open Ports (Common)", ports)
        
    if args.ports_all:
        ports = check_open_ports(domain, False)  # Extended scan
        print_result("Open Ports (All)", ports)
        
    if args.ssl:
        ssl_info = check_ssl_info(domain)
        print_result("SSL/TLS Information", ssl_info)
        
    if args.methods:
        methods = check_http_methods(url)
        print_result("HTTP Methods", methods)
        
    if args.cookie_sec:
        cookie_security = check_cookie_security(response)
        print_result("Cookie Security", cookie_security)
        
    if args.cache:
        cache_headers = check_caching_headers(response)
        print_result("Caching Headers", cache_headers)
        
    if args.server_info:
        server_info = extract_server_info(response)
        print_result("Server Information", server_info)
        
    if args.vulns:
        vulnerabilities = check_for_vulns(url, soup)
        print_result("Vulnerability Checks", vulnerabilities)
        
    if args.clickjacking:
        clickjacking = check_for_clickjacking(response)
        print_result("Clickjacking Protection", clickjacking)
        
    if args.uploads:
        upload_forms = check_file_upload_forms(soup)
        print_result("File Upload Forms", upload_forms)
        
    if args.passwords:
        password_forms = check_password_forms(soup)
        print_result("Password Forms", password_forms)
        
    if args.api:
        api_endpoints = check_api_endpoints(soup, url)
        print_result("API Endpoints", api_endpoints)
        
    if args.perf:
        performance = check_server_status(url)
        print_result("Server Performance", performance)
        
    if args.email_protection:
        email_protection = check_email_protection(soup)
        print_result("Email Protection", email_protection)
        
    if args.honeypots:
        honeypots = check_for_honeypots(soup)
        print_result("Form Honeypots", honeypots)
        
    if args.iframe_security:
        iframe_security = check_iframe_security(soup)
        print_result("Iframe Security", iframe_security)
        
    if args.third_party:
        third_party = check_third_party_resources(soup, url)
        print_result("Third-Party Resources", third_party)
        
    if args.content_type:
        content_types = check_content_types(response)
        print_result("Content Types", content_types)
        
    if args.mixed_content:
        mixed_content = check_mixed_content(soup, url)
        print_result("Mixed Content Check", mixed_content)
        
    if args.deserialize:
        deserialization = check_insecure_deserialization(soup)
        print_result("Insecure Deserialization Check", deserialization)
        
    # New functions in clike2.py
    if hasattr(args, 'sql_search') and args.sql_search:
        output_type = args.output if hasattr(args, 'output') else 'p'
        sql_files = search_sql_files(url, output_type)
        results["sql_files"] = sql_files
        # Output is handled within the function
    
    if hasattr(args, 'view_file') and args.view_file:
        file_content = view_sensitive_file_content(url, args.view_file)
        results["sensitive_file_content"] = {
            "path": args.view_file,
            "content": file_content
        }
        print_info(f"Viewing content of file: {args.view_file}")
        print(file_content)
    
    # Format results if requested
    if hasattr(args, 'format_results') and args.format_results and results:
        include_timestamp = args.timestamp if hasattr(args, 'timestamp') else True
        formatted_results = format_results(results, include_timestamp)
        print("\n" + formatted_results)


def print_help() -> None:
    """Print help message with all available options"""
    print(LOGO)
    help_text = f"""
{Fore.YELLOW}CLIKE URL Penetration Testing Tool{Style.RESET_ALL}

{Fore.GREEN}USAGE:{Style.RESET_ALL}
    python clike.py -u <url> [options]
    python clike.py --batch <file> [options]
    python clike.py -i [options]

{Fore.GREEN}BASIC OPTIONS:{Style.RESET_ALL}
    -u, --url         URL of website to analyze
    -b, --batch       Process multiple URLs from a file (one URL per line)
    -i, --interactive Interactive mode - enter URLs manually
    -h, --help        Display this help message
    --lite            Low resource mode (limits certain operations)
    --disable-lite    Disable lite mode for Termux (consume more resources)
    -all, --all       Run all checks

{Fore.GREEN}EXPORT OPTIONS:{Style.RESET_ALL}
    -e, --export-results  Export results to a file
    --format              Format to export results (json, csv, txt)
    -o, --output-file     Name of the output file
    --webhook             Send results to a webhook URL (Discord, Slack, etc.)

{Fore.GREEN}ANALYSIS OPTIONS:{Style.RESET_ALL}
    -d, --dns         DNS information
    -r, --redirects   URL redirects
    -f, --forms       Forms on page
    -n, --network     Network information
    -m, --meta        Meta tags
    -c, --cookies     Cookies
    -s, --security    HTTPS security
    -t, --title       Page title
    -img, --images    Count images
    -l, --links       Links analysis
    -x, --external    External links
    -v, --available   URL availability
    -w, --words       Word count
    -j, --js          JavaScript tags
    --css             CSS resources
    --sm, --sitemap   Sitemap check
    --robots          Robots.txt check
    --vid, --videos   Count videos
    --broken          Check for broken links
    --mobile          Mobile support check
    --h1              Header tags
    --lang            Page language
    --export          Export text content
    --sql             SQL leak check
    
{Fore.GREEN}ADVANCED SECURITY CHECKS:{Style.RESET_ALL}
    --cors            Check CORS policy
    --csp             Check Content Security Policy
    --feature-policy  Check Feature Policy headers
    --sensitive-files Check for sensitive files
    --subdomains      Check common subdomains
    --subdomain-wordlist Use extended wordlist for subdomain check
    --waf             Check for WAF presence
    --sec-headers     Check security headers
    --leaks           Check for information leaks
    --ports           Check open ports (common only)
    --ports-all       Check open ports (extended scan)
    --ssl             Check SSL/TLS certificate info
    --methods         Check HTTP methods
    --cookie-sec      Check cookie security
    --cache           Check caching headers
    --server-info     Extract server information
    --vulns           Check for common vulnerabilities
    --clickjacking    Check clickjacking protection
    --uploads         Analyze file upload forms
    --passwords       Analyze password forms
    --api             Identify potential API endpoints
    --perf            Check server performance
    --email-protection Check email address protection
    --honeypots       Check for form honeypots
    --iframe-security Check iframe security
    --third-party     Analyze third-party resources
    --content-type    Analyze content types
    --mixed-content   Check for mixed content
    --deserialize     Check for insecure deserialization

{Fore.GREEN}EXTRACTION OPTIONS:{Style.RESET_ALL}
    --headers         Get HTTP headers
    --links           Get all links
    --external        Get external links
    --internal        Get internal links
    --assets          Get assets (images, scripts, etc.)
    --scripts         Get scripts
    --forms           Get forms
    --inputs          Get input fields
    --buttons         Get buttons
    --tables          Get tables
    --iframes         Get iframes
    --meta            Get meta tags
    --title           Get title
    --content         Get content
    --keywords        Get keywords

{Fore.GREEN}EXAMPLES:{Style.RESET_ALL}
    python clike.py -u example.com -d -t -img
    python clike.py -u https://example.com --all
    python clike.py -u example.com --lite -l -broken
    python clike.py -b url_list.txt -t -img -w
    python clike.py -i -d -s -t
    python clike.py -u example.com -d -t -e --format json -o results.json
    python clike.py -b url_list.txt --all -e --format csv -o batch_results.csv
    
    # Security Testing Examples
    python clike.py -u example.com --ssl --sec-headers --cors --csp
    python clike.py -u example.com --waf --vulns --leaks
    python clike.py -u example.com --passwords --uploads --api --deserialize
    python clike.py -u example.com --all --sensitive-files --subdomains
    python clike.py -u example.com --iframe-security --third-party --mixed-content
    python clike.py -u example.com -e --format json --sec-headers --cookie-sec -o security_report.json
    python clike.py -u example.com --webhook https://webhook.site/YOUR-UUID  # Send results to webhook
    python clike.py -u example.com --ssl --sec-headers --webhook https://discord.com/api/webhooks/YOUR-WEBHOOK-URL
    
{Fore.GREEN}REAL-TIME THREAT SCORE:{Style.RESET_ALL}
    The tool includes a comprehensive security threat scoring system that:
    - Calculates risk scores for individual security checks
    - Generates an overall threat score from 0-100
    - Categorizes threats as Low/Moderate/Medium/High/Critical Risk
    - Provides visual indicators with a color-coded threat bar
    - Details specific security issues that contributed to the score
    
    # Real-time Threat Score Examples
    python clike.py -u example.com --all  # Includes complete Threat Score assessment
    python clike.py -u example.com --security --ssl --clickjacking --mixed-content  # Security-focused scan with Threat Score

{Fore.GREEN}NEW FUNCTIONS:{Style.RESET_ALL}
    The tool includes several new powerful features:
    
    1. SQL File Search:
       Search for exposed SQL files with output options:
       python clike.py -u example.com --sql-search -op p  # Print results to console (p = print)
       python clike.py -u example.com --sql-search -op w  # Send to webhook (w = webhook)
       python clike.py -u example.com --sql-search -op f  # Export to CSV file (f = file)
    
    2. View Sensitive File Content:
       View the content of discovered sensitive files:
       python clike.py -u example.com --view-file /wp-config.php
       python clike.py -u example.com --view-file /.env
    
    3. Format Results:
       Format and display scan results in a clean, structured format:
       python clike.py -u example.com --ssl --sec-headers --format-results
       python clike.py -u example.com --all --format-results --timestamp
    
    4. Disable Lite Mode for Termux:
       Use more resources on Termux when needed:
       python clike.py -u example.com --disable-lite --ssl --waf

{Fore.GREEN}TERMUX USAGE:{Style.RESET_ALL}
    Lite mode will be enabled automatically when running on Termux
    Try the following examples optimized for mobile:
    
    python clike.py -u example.com -t -d         # Basic info only
    python clike.py -i -t -meta                  # Interactive mode with minimal checks
    python clike.py -b sites.txt -t --lite       # Process multiple URLs with minimal checks
    python clike.py -u example.com --sec-headers --cors --csp  # Basic security check
    python clike.py -u example.com --lite --ssl --waf          # Lightweight security test
"""
    print(help_text)


def process_url_with_results(url: str, args) -> Dict[str, Any]:
    """
    Process URL with all specified checks and return results as a dictionary
    
    This version is similar to process_url but instead of just displaying results,
    it collects them in a dictionary to be returned for export
    """
    global THREAT_SCORES, THREAT_DETAILS
    
    # Initialize threat scores and details for this URL
    THREAT_SCORES[url] = {}
    THREAT_DETAILS[url] = {}
    
    url = normalize_url(url)
    results = {}
    
    # Check URL and get response
    response = check_url(url)
    if not response:
        return {"error": "Failed to connect to URL"}
    
    # Parse HTML
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print_error(f"Error parsing HTML: {str(e)}")
        return {"error": f"Error parsing HTML: {str(e)}"}
    
    # Get domain
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    
    # Perform checks based on arguments
    if args.title or args.all:
        title = get_page_title(soup)
        results["title"] = title
        print_result("Page Title", title)
    
    if args.dns or args.all:
        dns_info = get_dns_info(domain)
        results["dns_info"] = dns_info
        print_result("DNS Information", dns_info)
    
    if args.redirects or args.all:
        redirects = check_url_redirects(url)
        results["redirects"] = redirects
        print_result("URL Redirects", redirects)
    
    if args.forms or args.all:
        forms = extract_forms(soup)
        results["forms"] = forms
        print_result("Forms", forms)
    
    if args.network or args.all:
        network_info = get_network_info(url)
        results["network_info"] = network_info
        print_result("Network Information", network_info)
    
    if args.meta or args.all:
        meta_tags = extract_meta_tags(soup)
        results["meta_tags"] = meta_tags
        print_result("Meta Tags", meta_tags)
    
    if args.cookies or args.all:
        cookies = get_cookies(response)
        results["cookies"] = cookies
        print_result("Cookies", cookies)
    
    if args.security or args.all:
        security_info = check_https_security(url, response)
        results["security_info"] = security_info
        print_result("HTTPS Security", security_info)
    
    if args.images or args.all:
        image_count = count_images(soup)
        results["image_count"] = image_count
        print_result("Image Count", image_count)
    
    if args.links or args.all:
        links = extract_links(soup, url)
        results["links"] = links
        print_result("Links", links)
    
    if args.external or args.all:
        links = extract_links(soup, url)
        results["external_links"] = links["external"]
        print_result("External Links", links["external"])
    
    if args.words or args.all:
        word_count = count_words(soup)
        results["word_count"] = word_count
        print_result("Word Count", word_count)
    
    if args.js or args.all:
        js_tags = extract_js_tags(soup)
        results["js_tags"] = js_tags
        print_result("JavaScript Tags", js_tags)
    
    if args.css or args.all:
        css_resources = extract_css_resources(soup)
        results["css_resources"] = css_resources
        print_result("CSS Resources", css_resources)
    
    if args.sitemap or args.all:
        sitemap_info = check_sitemap(domain)
        results["sitemap_info"] = sitemap_info
        print_result("Sitemap Check", sitemap_info)
    
    if args.robots or args.all:
        robots_info = check_robots_txt(domain)
        results["robots_info"] = robots_info
        print_result("Robots.txt Check", robots_info)
    
    if args.videos or args.all:
        video_count = count_videos(soup)
        results["video_count"] = video_count
        print_result("Video Count", video_count)
    
    if args.broken or args.all:
        links_data = extract_links(soup, url)
        all_links = links_data["internal"] + links_data["external"]
        broken_links = check_broken_links(all_links)
        results["broken_links"] = broken_links
        print_result("Broken Links Check", broken_links)
    
    if args.mobile or args.all:
        mobile_support = check_mobile_support(soup)
        results["mobile_support"] = mobile_support
        print_result("Mobile Support", mobile_support)
    
    if args.h1 or args.all:
        headers = extract_header_tags(soup)
        results["headers"] = headers
        print_result("Header Tags", headers)
    
    if args.lang or args.all:
        language = get_page_language(soup)
        results["language"] = language
        print_result("Page Language", language)
    
    if args.export or args.all:
        text_content = export_text_content(url)
        results["text_content"] = text_content
        print_result("Text Content", text_content[:500] + "..." if len(text_content) > 500 else text_content)
    
    if args.sql or args.all:
        sql_leaks = check_sql_leak(soup)
        results["sql_leaks"] = sql_leaks
        print_result("SQL Leak Check", sql_leaks)
    
    if args.headers or args.all:
        headers = dict(response.headers)
        results["http_headers"] = headers
        print_result("HTTP Headers", headers)
    
    if args.internal or args.all:
        links_data = extract_links(soup, url)
        results["internal_links"] = links_data["internal"]
        print_result("Internal Links", links_data["internal"])
    
    if args.assets or args.all:
        assets = extract_assets(soup, url)
        results["assets"] = assets
        print_result("Assets", assets)
    
    if args.scripts or args.all:
        scripts = [script['src'] for script in soup.find_all('script', src=True)]
        results["scripts"] = scripts
        print_result("Scripts", scripts)
    
    if args.inputs or args.all:
        inputs = extract_inputs(soup)
        results["inputs"] = inputs
        print_result("Input Fields", inputs)
    
    if args.buttons or args.all:
        buttons = extract_buttons(soup)
        results["buttons"] = buttons
        print_result("Buttons", buttons)
    
    if args.tables or args.all:
        tables = extract_tables(soup)
        results["tables"] = tables
        print_result("Tables", tables)
    
    if args.iframes or args.all:
        iframes = extract_iframes(soup)
        results["iframes"] = iframes
        print_result("Iframes", iframes)
    
    if args.keywords or args.all:
        keywords = extract_keywords(soup)
        results["keywords"] = keywords
        print_result("Keywords", keywords)
        
    # New advanced security checks
    if args.cors or args.all:
        cors_policy = check_cors_policy(response)
        results["cors_policy"] = cors_policy
        print_result("CORS Policy", cors_policy)
        
    if args.csp or args.all:
        csp_policy = check_csp_policy(response)
        results["csp_policy"] = csp_policy
        print_result("Content Security Policy", csp_policy)
        
    if args.feature_policy or args.all:
        feature_policy = check_feature_policy(response)
        results["feature_policy"] = feature_policy
        print_result("Feature/Permissions Policy", feature_policy)
        
    if args.sensitive_files or args.all:
        sensitive_files = check_for_sensitive_files(domain)
        results["sensitive_files"] = sensitive_files
        print_result("Sensitive Files Check", sensitive_files)
        
    if args.subdomains or args.all:
        use_wordlist = args.subdomain_wordlist if hasattr(args, 'subdomain_wordlist') else False
        subdomains = check_subdomains(domain, use_wordlist)
        results["subdomains"] = subdomains
        print_result("Subdomains Check", subdomains)
        
    if args.waf or args.all:
        waf = check_waf_presence(url)
        results["waf"] = waf
        print_result("WAF Detection", waf)
        
    if args.sec_headers or args.all:
        security_headers = check_security_headers(response)
        results["security_headers"] = security_headers
        print_result("Security Headers", security_headers)
        
    if args.leaks or args.all:
        leaks = check_for_leaks(soup, response)
        results["information_leaks"] = leaks
        print_result("Information Leaks", leaks)
        
    if args.ports or args.all:
        ports = check_open_ports(domain, True)  # Common ports only
        results["common_ports"] = ports
        print_result("Open Ports (Common)", ports)
        
    if args.ports_all or args.all:
        ports = check_open_ports(domain, False)  # Extended scan
        results["all_ports"] = ports
        print_result("Open Ports (All)", ports)
        
    if args.ssl or args.all:
        ssl_info = check_ssl_info(domain)
        results["ssl_info"] = ssl_info
        print_result("SSL/TLS Information", ssl_info)
        
    if args.methods or args.all:
        methods = check_http_methods(url)
        results["http_methods"] = methods
        print_result("HTTP Methods", methods)
        
    if args.cookie_sec or args.all:
        cookie_security = check_cookie_security(response)
        results["cookie_security"] = cookie_security
        print_result("Cookie Security", cookie_security)
        
    if args.cache or args.all:
        cache_headers = check_caching_headers(response)
        results["cache_headers"] = cache_headers
        print_result("Caching Headers", cache_headers)
        
    if args.server_info or args.all:
        server_info = extract_server_info(response)
        results["server_info"] = server_info
        print_result("Server Information", server_info)
        
    if args.vulns or args.all:
        vulnerabilities = check_for_vulns(url, soup)
        results["vulnerabilities"] = vulnerabilities
        print_result("Vulnerability Checks", vulnerabilities)
        
    if args.clickjacking or args.all:
        clickjacking = check_for_clickjacking(response)
        results["clickjacking"] = clickjacking
        print_result("Clickjacking Protection", clickjacking)
        
    if args.uploads or args.all:
        upload_forms = check_file_upload_forms(soup)
        results["upload_forms"] = upload_forms
        print_result("File Upload Forms", upload_forms)
        
    if args.passwords or args.all:
        password_forms = check_password_forms(soup)
        results["password_forms"] = password_forms
        print_result("Password Forms", password_forms)
        
    if args.api or args.all:
        api_endpoints = check_api_endpoints(soup, url)
        results["api_endpoints"] = api_endpoints
        print_result("API Endpoints", api_endpoints)
        
    if args.perf or args.all:
        performance = check_server_status(url)
        results["server_performance"] = performance
        print_result("Server Performance", performance)
        
    if args.email_protection or args.all:
        email_protection = check_email_protection(soup)
        results["email_protection"] = email_protection
        print_result("Email Protection", email_protection)
        
    if args.honeypots or args.all:
        honeypots = check_for_honeypots(soup)
        results["form_honeypots"] = honeypots
        print_result("Form Honeypots", honeypots)
        
    if args.iframe_security or args.all:
        iframe_security = check_iframe_security(soup)
        results["iframe_security"] = iframe_security
        print_result("Iframe Security", iframe_security)
        
    if args.third_party or args.all:
        third_party = check_third_party_resources(soup, url)
        results["third_party_resources"] = third_party
        print_result("Third-Party Resources", third_party)
        
    if args.content_type or args.all:
        content_types = check_content_types(response)
        results["content_types"] = content_types
        print_result("Content Types", content_types)
        
    if args.mixed_content or args.all:
        mixed_content = check_mixed_content(soup, url)
        results["mixed_content"] = mixed_content
        print_result("Mixed Content Check", mixed_content)
        
    if args.deserialize or args.all:
        deserialization = check_insecure_deserialization(soup)
        results["insecure_deserialization"] = deserialization
        print_result("Insecure Deserialization Check", deserialization)
    
    # New functions in clike2.py
    if hasattr(args, 'sql_search') and args.sql_search:
        output_type = args.output if hasattr(args, 'output') else 'p'
        sql_files = search_sql_files(url, output_type)
        results["sql_files"] = sql_files
        # Output is handled within the function
    
    if hasattr(args, 'view_file') and args.view_file:
        file_content = view_sensitive_file_content(url, args.view_file)
        results["sensitive_file_content"] = {
            "path": args.view_file,
            "content": file_content
        }
        print_info(f"Viewing content of file: {args.view_file}")
        print(file_content)
    
    # Format results if requested
    if hasattr(args, 'format_results') and args.format_results and results:
        include_timestamp = args.timestamp if hasattr(args, 'timestamp') else True
        formatted_results = format_results(results, include_timestamp)
        print("\n" + formatted_results)
    
    # Calculate and add threat score
    if args.all or any([
        args.security, args.ssl, args.csp, args.cors, args.sec_headers,
        args.cookie_sec, args.clickjacking, args.mixed_content, args.vulns,
        args.leaks, args.passwords, args.iframe_security, args.deserialize
    ]):
        # Update threat scores
        if args.security and "security_info" in results:
            score = calculate_threat_score("security", results["security_info"])
            THREAT_SCORES[url]["security"] = score
            THREAT_DETAILS[url]["security"] = {
                "score": score,
                "reason": "HTTPS and security header issues"
            }
            
        if args.ssl and "ssl_info" in results:
            score = calculate_threat_score("ssl", results["ssl_info"])
            THREAT_SCORES[url]["ssl"] = score
            THREAT_DETAILS[url]["ssl"] = {
                "score": score,
                "reason": "SSL/TLS certificate issues"
            }
            
        if args.csp and "csp_policy" in results:
            score = calculate_threat_score("csp", results["csp_policy"])
            THREAT_SCORES[url]["csp"] = score
            THREAT_DETAILS[url]["csp"] = {
                "score": score,
                "reason": "Content Security Policy issues"
            }
            
        if args.clickjacking and "clickjacking" in results:
            score = calculate_threat_score("clickjacking", results["clickjacking"])
            THREAT_SCORES[url]["clickjacking"] = score
            THREAT_DETAILS[url]["clickjacking"] = {
                "score": score,
                "reason": "Clickjacking protection issues"
            }
            
        if args.mixed_content and "mixed_content" in results:
            score = calculate_threat_score("mixed_content", results["mixed_content"])
            THREAT_SCORES[url]["mixed_content"] = score
            THREAT_DETAILS[url]["mixed_content"] = {
                "score": score,
                "reason": "Mixed content issues"
            }
            
        if args.cookie_sec and "cookie_security" in results:
            score = calculate_threat_score("cookie_sec", results["cookie_security"])
            THREAT_SCORES[url]["cookie_sec"] = score
            THREAT_DETAILS[url]["cookie_sec"] = {
                "score": score,
                "reason": "Cookie security issues"
            }
            
        if args.leaks and "information_leaks" in results:
            score = calculate_threat_score("leaks", results["information_leaks"])
            THREAT_SCORES[url]["leaks"] = score
            THREAT_DETAILS[url]["leaks"] = {
                "score": score,
                "reason": "Information leakage issues"
            }
            
        if args.sec_headers and "security_headers" in results:
            score = calculate_threat_score("sec_headers", results["security_headers"])
            THREAT_SCORES[url]["sec_headers"] = score
            THREAT_DETAILS[url]["sec_headers"] = {
                "score": score,
                "reason": "Missing security headers"
            }
            
        if args.vulns and "vulnerabilities" in results:
            score = calculate_threat_score("vulns", results["vulnerabilities"])
            THREAT_SCORES[url]["vulns"] = score
            THREAT_DETAILS[url]["vulns"] = {
                "score": score,
                "reason": "Vulnerability issues"
            }
            
        if args.passwords and "password_forms" in results:
            score = calculate_threat_score("passwords", results["password_forms"])
            THREAT_SCORES[url]["passwords"] = score
            THREAT_DETAILS[url]["passwords"] = {
                "score": score,
                "reason": "Password form security issues"
            }
            
        if args.iframe_security and "iframe_security" in results:
            score = calculate_threat_score("iframe_security", results["iframe_security"])
            THREAT_SCORES[url]["iframe_security"] = score
            THREAT_DETAILS[url]["iframe_security"] = {
                "score": score,
                "reason": "Iframe security issues"
            }
            
        if args.deserialize and "insecure_deserialization" in results:
            score = calculate_threat_score("deserialize", results["insecure_deserialization"])
            THREAT_SCORES[url]["deserialize"] = score
            THREAT_DETAILS[url]["deserialize"] = {
                "score": score,
                "reason": "Insecure deserialization issues"
            }
        
        # Calculate overall threat score
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        score, details = calculate_overall_threat_score(url)
        
        # Add to results
        results["threat_score"] = {
            "score": score,
            "category": get_threat_category(score)[0],
            "details": details
        }
        
        # Display the threat score
        print_threat_score(domain, score, details)
    
    return results


def process_batch(file_path: str, args) -> None:
    """Process multiple URLs from a file"""
    try:
        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
            
        if not urls:
            print_error(f"No URLs found in file: {file_path}")
            return
            
        print_info(f"Processing {len(urls)} URLs from {file_path}")
        
        all_results = {}
        for i, url in enumerate(urls):
            print("\n" + "=" * 60)
            print_info(f"Processing URL {i+1}/{len(urls)}: {url}")
            print("=" * 60 + "\n")
            
            # Collect results for this URL if exporting
            if args.export_results:
                url_results = process_url_with_results(url, args)
                all_results[url] = url_results
            else:
                process_url(url, args)
            
        # Export results if requested or send to webhook
        if (args.export_results or args.webhook) and all_results:
            # Export to file if requested
            if args.export_results:
                export_format = args.format or 'json'
                export_results(all_results, export_format, args.output_file)
            
            # Send to webhook if provided
            if args.webhook:
                webhook_response = send_to_webhook(all_results, args.webhook)
                if webhook_response["success"]:
                    print_info(f"Successfully sent batch results to webhook: {args.webhook}")
                else:
                    print_error(f"Failed to send batch results to webhook: {webhook_response['message']}")
            
    except Exception as e:
        print_error(f"Error processing batch file: {str(e)}")


def send_to_webhook(data: Dict[str, Any], webhook_url: str) -> Dict[str, Any]:
    """
    Send scan results to a webhook URL
    
    Args:
        data: Dictionary containing the scan results
        webhook_url: URL of the webhook to send data to
        
    Returns:
        Dictionary with status and response information
    """
    result = {
        "success": False,
        "status_code": None,
        "message": ""
    }
    
    try:
        print_info(f"Sending results to webhook: {webhook_url}")
        
        # Format the data as JSON
        json_data = json.dumps(data, indent=2)
        
        # Set up the request headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT
        }
        
        # Send the POST request to the webhook
        response = requests.post(webhook_url, data=json_data, headers=headers, timeout=30)
        
        # Update the result based on the response
        result["status_code"] = response.status_code
        
        if 200 <= response.status_code < 300:
            result["success"] = True
            result["message"] = f"Successfully sent to webhook (Status: {response.status_code})"
            print_info(result["message"])
        else:
            result["message"] = f"Error sending to webhook: HTTP {response.status_code}"
            print_error(result["message"])
            
    except requests.RequestException as e:
        result["message"] = f"Error sending to webhook: {str(e)}"
        print_error(result["message"])
    except Exception as e:
        result["message"] = f"Unexpected error: {str(e)}"
        print_error(result["message"])
        
    return result


def export_results(data: Dict[str, Any], export_format: str, filename: str) -> None:
    """
    Export results to a file in the specified format (txt, csv, json)
    
    Args:
        data: Dictionary containing the results to export
        export_format: Format to export (txt, csv, json)
        filename: Name of the file to save results
    """
    if not filename:
        filename = f"clike_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    if not filename.endswith(f".{export_format}"):
        filename = f"{filename}.{export_format}"
    
    try:
        if export_format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
        
        elif export_format.lower() == 'csv':
            # Flatten the nested dictionary structure for CSV
            flattened_data = []
            
            for url, url_data in data.items():
                row = {'url': url}
                
                # Add all first-level key-values
                for k, v in url_data.items():
                    if isinstance(v, (str, int, bool, float)) or v is None:
                        row[k] = v
                    elif isinstance(v, (dict, list)):
                        # For complex objects, store as JSON string
                        row[k] = json.dumps(v)
                
                flattened_data.append(row)
            
            if flattened_data:
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=flattened_data[0].keys())
                    writer.writeheader()
                    writer.writerows(flattened_data)
            else:
                print_error("No data to export to CSV")
                return
        
        elif export_format.lower() == 'txt':
            with open(filename, 'w') as f:
                f.write("CLIKE URL Analysis Results\n")
                f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for url, url_data in data.items():
                    f.write(f"URL: {url}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for section, section_data in url_data.items():
                        f.write(f"{section.upper()}:\n")
                        f.write("-" * 40 + "\n")
                        
                        if isinstance(section_data, (dict, list)):
                            f.write(json.dumps(section_data, indent=2))
                        else:
                            f.write(str(section_data))
                        
                        f.write("\n\n")
                    
                    f.write("\n\n")
        
        else:
            print_error(f"Unsupported export format: {export_format}")
            return
        
        print_info(f"Results exported to {filename}")
    
    except Exception as e:
        print_error(f"Error exporting results: {str(e)}")


def process_input_urls(args) -> None:
    """Process URLs provided through user input"""
    print_info("Enter URLs to analyze (one per line). Enter a blank line to finish:")
    print_info("TIP: On Termux, you can paste multiple URLs at once")
    urls = []
    
    # Try to handle case where user pastes multiple URLs at once (common in Termux)
    try:
        while True:
            user_input = input().strip()
            if not user_input:
                break
            
            # Check if the input contains multiple lines or escaped newlines (common when pasting in Termux)
            if '\n' in user_input or '\\n' in user_input:
                # Handle both actual newlines and escaped newline characters
                if '\\n' in user_input:
                    # This handles cases where paste includes escaped newlines like "example.com\ngoogle.com"
                    parts = user_input.split('\\n')
                else:
                    # This handles cases where paste includes actual newlines
                    parts = user_input.split('\n')
                
                multi_urls = [u.strip() for u in parts if u.strip()]
                urls.extend(multi_urls)
                print_info(f"Added {len(multi_urls)} URLs from pasted content")
                break
            else:
                urls.append(user_input)
    except EOFError:
        # Handle EOF error which can occur in Termux
        print_warning("Input terminated unexpectedly")
    
    if not urls:
        print_error("No URLs were provided")
        return
    
    print_info(f"Processing {len(urls)} URLs from user input")
    
    all_results = {}
    for i, url in enumerate(urls):
        print("\n" + "=" * 60)
        print_info(f"Processing URL {i+1}/{len(urls)}: {url}")
        print("=" * 60 + "\n")
        
        # Collect results for this URL
        url_results = {}
        if args.export_results:
            url_results = process_url_with_results(url, args)
            all_results[url] = url_results
        else:
            process_url(url, args)
    
    # Export results if requested
    if (args.export_results or args.webhook) and all_results:
        # Export to file if requested
        if args.export_results:
            export_format = args.format or 'json'
            export_results(all_results, export_format, args.output_file)
        
        # Send to webhook if provided
        if args.webhook:
            webhook_response = send_to_webhook(all_results, args.webhook)
            if webhook_response["success"]:
                print_info(f"Successfully sent results to webhook: {args.webhook}")
            else:
                print_error(f"Failed to send results to webhook: {webhook_response['message']}")


def check_cors_policy(response: requests.Response) -> Dict:
    """Check Cross-Origin Resource Sharing (CORS) policy"""
    cors_info = {
        "has_cors_headers": False,
        "allows_any_origin": False,
        "allows_credentials": False,
        "allowed_origins": None,
        "allowed_methods": None
    }
    
    # Check CORS headers
    access_control_allow_origin = response.headers.get('Access-Control-Allow-Origin')
    if access_control_allow_origin:
        cors_info["has_cors_headers"] = True
        cors_info["allowed_origins"] = access_control_allow_origin
        
        # Check if it allows any origin (security concern)
        if access_control_allow_origin == '*':
            cors_info["allows_any_origin"] = True
            
    # Check for credentials permission
    if response.headers.get('Access-Control-Allow-Credentials') == 'true':
        cors_info["allows_credentials"] = True
        
    # Check allowed methods
    if 'Access-Control-Allow-Methods' in response.headers:
        cors_info["allowed_methods"] = response.headers.get('Access-Control-Allow-Methods')
        
    return cors_info


def check_csp_policy(response: requests.Response) -> Dict:
    """Check Content Security Policy (CSP)"""
    csp_info = {
        "has_csp": False,
        "policy": None,
        "unsafe_inline": False,
        "unsafe_eval": False,
        "report_only": False
    }
    
    # Check for CSP header
    csp = response.headers.get('Content-Security-Policy')
    if csp:
        csp_info["has_csp"] = True
        csp_info["policy"] = csp
        
        # Check for unsafe directives
        if "'unsafe-inline'" in csp:
            csp_info["unsafe_inline"] = True
        if "'unsafe-eval'" in csp:
            csp_info["unsafe_eval"] = True
    
    # Check for report-only mode
    if 'Content-Security-Policy-Report-Only' in response.headers:
        csp_info["report_only"] = True
        if not csp_info["has_csp"]:
            csp_info["policy"] = response.headers.get('Content-Security-Policy-Report-Only')
            
    return csp_info


def check_feature_policy(response: requests.Response) -> Dict:
    """Check Feature-Policy and Permissions-Policy headers"""
    policy_info = {
        "has_feature_policy": False,
        "has_permissions_policy": False,
        "feature_policy": None,
        "permissions_policy": None
    }
    
    # Check for Feature-Policy header
    feature_policy = response.headers.get('Feature-Policy')
    if feature_policy:
        policy_info["has_feature_policy"] = True
        policy_info["feature_policy"] = feature_policy
        
    # Check for Permissions-Policy header (newer version of Feature-Policy)
    permissions_policy = response.headers.get('Permissions-Policy')
    if permissions_policy:
        policy_info["has_permissions_policy"] = True
        policy_info["permissions_policy"] = permissions_policy
        
    return policy_info


def check_for_sensitive_files(domain: str) -> Dict:
    """Check for commonly exposed sensitive files"""
    sensitive_files = [
        "/.git/HEAD",
        "/.env",
        "/wp-config.php",
        "/config.php",
        "/.htaccess",
        "/server-status",
        "/phpinfo.php",
        "/.svn/entries",
        "/.DS_Store",
        "/cgi-bin/",
        "/.well-known/security.txt"
    ]
    
    results = {}
    
    for file_path in sensitive_files:
        url = f"https://{domain}{file_path}"
        try:
            response = requests.head(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
            
            results[file_path] = {
                "status_code": response.status_code,
                "accessible": 200 <= response.status_code < 400,
                "url": url
            }
            
        except Exception as e:
            results[file_path] = {
                "status_code": 0,
                "accessible": False,
                "error": str(e),
                "url": url
            }
            
    return results


def check_subdomains(domain: str, use_wordlist: bool = False) -> Dict:
    """
    Check for common subdomains of a domain
    
    If use_wordlist is True, it will check using a small hardcoded wordlist.
    Otherwise, it will only check for common ones like www, mail, etc.
    """
    results = {
        "found": [],
        "total_checked": 0,
        "errors": []
    }
    
    # Common subdomains to check
    common_subdomains = ["www", "mail", "webmail", "blog", "dev", "test", "admin", "api"]
    
    # Add more from wordlist if requested and not in lite mode
    if use_wordlist and not LITE_MODE:
        additional_subs = [
            "stage", "staging", "app", "apps", "shop", "secure", "vpn", "cdn", 
            "demo", "portal", "beta", "dev", "development", "status", "m",
            "mobile", "internal", "intranet", "git", "gitlab", "jenkins", "jira",
            "confluence", "wiki", "support", "help", "ftp", "sftp", "client",
            "clients", "store", "payment", "payments", "billing"
        ]
        common_subdomains.extend(additional_subs)
    
    results["total_checked"] = len(common_subdomains)
    
    for subdomain in common_subdomains:
        fqdn = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            results["found"].append({
                "subdomain": fqdn,
                "ip": ip
            })
        except socket.gaierror:
            # Subdomain doesn't resolve, skip
            pass
        except Exception as e:
            results["errors"].append({
                "subdomain": fqdn,
                "error": str(e)
            })
            
    return results


def check_waf_presence(url: str) -> Dict:
    """
    Check for Web Application Firewall (WAF) presence
    by looking for common WAF signatures in responses
    """
    waf_info = {
        "detected": False,
        "name": None,
        "signatures_found": []
    }
    
    # Common WAF signatures in headers and response body
    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "AWS WAF": ["awselb", "x-amzn-trace-id"],
        "Imperva/Incapsula": ["incap_ses", "_incapsula_"],
        "Akamai": ["akamai", "x-akamai-transformed"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "F5 BigIP": ["BigIP", "TS01a7"],
        "Sucuri": ["sucuri", "x-sucuri"],
        "Barracuda": ["barracuda"],
        "Wordfence": ["wordfence"],
        "Fortinet FortiWeb": ["fortiweb"]
    }
    
    try:
        # Make a request
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        
        # Check headers and cookies for WAF signatures
        headers_str = str(response.headers).lower()
        cookies_str = str(response.cookies).lower()
        combined_text = headers_str + cookies_str
        
        # Try to find WAF signatures
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in combined_text:
                    waf_info["detected"] = True
                    waf_info["name"] = waf_name
                    waf_info["signatures_found"].append(sig)
                    break
                    
        # Try specifically forcing a WAF to trigger with a fake attack
        if not waf_info["detected"]:
            test_url = url + "/?id=1' OR '1'='1"
            test_response = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT)
            
            # Check if we get a special status code or different response
            if test_response.status_code in [403, 406, 429, 503] and response.status_code != test_response.status_code:
                waf_info["detected"] = True
                waf_info["name"] = "Unknown WAF"
                waf_info["signatures_found"].append(f"Blocking behavior on test parameter (Status: {test_response.status_code})")
                
    except Exception as e:
        waf_info["error"] = str(e)
        
    return waf_info


def check_security_headers(response: requests.Response) -> Dict:
    """
    Comprehensive check for security-related HTTP headers
    """
    security_headers = {
        "missing": [],
        "present": {},
        "score": 0,
        "max_score": 10
    }
    
    # Critical security headers to check
    important_headers = {
        "Strict-Transport-Security": "Protects against downgrade attacks and cookie hijacking",
        "Content-Security-Policy": "Prevents XSS and data injection attacks",
        "X-Content-Type-Options": "Prevents MIME-sniffing",
        "X-Frame-Options": "Protects against clickjacking",
        "X-XSS-Protection": "Browser's XSS filtering",
        "Referrer-Policy": "Controls what information is sent in the Referer header",
        "Feature-Policy": "Controls which browser features can be used",
        "Permissions-Policy": "Modern replacement for Feature-Policy",
        "Cache-Control": "Controls caching of sensitive content",
        "Clear-Site-Data": "Clears browsing data for the origin"
    }
    
    for header, description in important_headers.items():
        if header in response.headers:
            security_headers["present"][header] = {
                "value": response.headers[header],
                "description": description
            }
            security_headers["score"] += 1
        else:
            security_headers["missing"].append({
                "header": header,
                "description": description
            })
            
    return security_headers


def check_for_leaks(soup: BeautifulSoup, response: requests.Response) -> Dict:
    """
    Check for potential information leaks in HTML comments, headers, etc.
    """
    from bs4.element import Comment
    
    leak_info = {
        "html_comments": [],
        "server_info": None,
        "email_addresses": [],
        "ip_addresses": [],
        "potential_credentials": False
    }
    
    # Extract HTML comments
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        comment_text = comment.strip()
        # Skip empty comments
        if comment_text and len(comment_text) > 5:
            leak_info["html_comments"].append(comment_text[:150] + "..." if len(comment_text) > 150 else comment_text)
    
    # Check for server information in headers
    if 'Server' in response.headers:
        leak_info["server_info"] = response.headers['Server']
    
    # Look for email addresses in the page
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    html_content = str(soup)
    emails = re.findall(email_pattern, html_content)
    if emails:
        leak_info["email_addresses"] = list(set(emails))[:10]  # Limit to 10 unique emails
    
    # Look for potential IP addresses in the page
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, html_content)
    if ips:
        leak_info["ip_addresses"] = list(set(ips))[:10]  # Limit to 10 unique IPs
    
    # Check for potential credentials in code
    credential_patterns = [
        r'password\s*=\s*[\'"][^\'"]+[\'"]',
        r'passwd\s*=\s*[\'"][^\'"]+[\'"]',
        r'pwd\s*=\s*[\'"][^\'"]+[\'"]',
        r'username\s*=\s*[\'"][^\'"]+[\'"]',
        r'user\s*=\s*[\'"][^\'"]+[\'"]',
        r'apikey\s*=\s*[\'"][^\'"]+[\'"]',
        r'api_key\s*=\s*[\'"][^\'"]+[\'"]',
        r'token\s*=\s*[\'"][^\'"]+[\'"]'
    ]
    
    for pattern in credential_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            leak_info["potential_credentials"] = True
            break
            
    return leak_info


def check_open_ports(domain: str, common_only: bool = True) -> Dict:
    """
    Check for commonly open ports on the domain
    
    If common_only is True, it will only check the most common ports.
    """
    port_info = {
        "open_ports": [],
        "scanned_ports": [],
        "errors": []
    }
    
    # Common ports to check based on services
    if common_only or LITE_MODE:
        ports_to_scan = [21, 22, 25, 80, 443, 8080, 8443, 3389]
    else:
        ports_to_scan = [
            21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 
            445, 993, 995, 1433, 1521, 3306, 3389, 5060, 5222, 5432, 
            5900, 8080, 8443, 8888, 9100, 27017
        ]
    
    port_info["scanned_ports"] = ports_to_scan
    
    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Short timeout to avoid long waits
            result = sock.connect_ex((domain, port))
            sock.close()
            
            if result == 0:
                port_info["open_ports"].append(port)
                
        except Exception as e:
            port_info["errors"].append({
                "port": port,
                "error": str(e)
            })
            
    return port_info


def check_ssl_info(domain: str) -> Dict:
    """
    Check SSL/TLS certificate information
    """
    ssl_info = {
        "has_ssl": False,
        "issuer": None,
        "subject": None,
        "version": None,
        "valid_from": None,
        "valid_until": None,
        "serial_number": None,
        "error": None
    }
    
    try:
        import ssl
        from datetime import datetime
        
        # Create connection to get certificate
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(TIMEOUT)
        
        try:
            conn.connect((domain, 443))
            ssl_info["has_ssl"] = True
            
            # Get certificate details
            cert = conn.getpeercert()
            
            # Extract certificate information
            ssl_info["subject"] = dict(x[0] for x in cert["subject"])
            ssl_info["issuer"] = dict(x[0] for x in cert["issuer"])
            ssl_info["version"] = cert["version"]
            ssl_info["valid_from"] = cert["notBefore"]
            ssl_info["valid_until"] = cert["notAfter"]
            ssl_info["serial_number"] = cert["serialNumber"]
            
            # Calculate days until expiration
            expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            current_date = datetime.now()
            ssl_info["days_until_expiry"] = (expiry_date - current_date).days
            
        except socket.error as e:
            ssl_info["error"] = f"Socket error: {str(e)}"
        finally:
            conn.close()
            
    except Exception as e:
        ssl_info["error"] = str(e)
        
    return ssl_info


def check_http_methods(url: str) -> Dict:
    """
    Check which HTTP methods are supported by the server
    """
    methods_info = {
        "supported_methods": [],
        "potentially_risky_methods": []
    }
    
    # Common HTTP methods to check
    http_methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH"]
    
    # Methods that could potentially be risky if enabled
    risky_methods = ["PUT", "DELETE", "TRACE"]
    
    for method in http_methods:
        try:
            response = requests.request(method, url, headers=HEADERS, timeout=TIMEOUT)
            
            # Consider the method supported if we don't get a 405 Method Not Allowed
            # or 501 Not Implemented
            if response.status_code not in [405, 501]:
                methods_info["supported_methods"].append(method)
                
                # Check if this is a potentially risky method
                if method in risky_methods:
                    methods_info["potentially_risky_methods"].append(method)
                    
        except Exception:
            # Skip methods that cause errors
            continue
            
    return methods_info


def check_cookie_security(response: requests.Response) -> Dict:
    """
    Check cookies for security attributes like HttpOnly, Secure, SameSite
    """
    cookie_security = {
        "cookies": [],
        "insecure_cookies": [],
        "secure_cookie_count": 0,
        "httponly_cookie_count": 0,
        "samesite_cookie_count": 0
    }
    
    for cookie in response.cookies:
        cookie_data = {
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr('HttpOnly'),
            "samesite": None,
            "domain": cookie.domain,
            "path": cookie.path,
            "expires": cookie.expires
        }
        
        # Check for SameSite attribute
        if cookie.has_nonstandard_attr('SameSite'):
            for attr in cookie._rest.keys():
                if attr.lower() == 'samesite':
                    cookie_data["samesite"] = cookie._rest[attr]
        
        # Count secure attributes
        if cookie_data["secure"]:
            cookie_security["secure_cookie_count"] += 1
        if cookie_data["httponly"]:
            cookie_security["httponly_cookie_count"] += 1
        if cookie_data["samesite"]:
            cookie_security["samesite_cookie_count"] += 1
            
        # Add cookie to appropriate list
        cookie_security["cookies"].append(cookie_data)
        
        # Check if cookie is insecure
        if not cookie_data["secure"] or not cookie_data["httponly"]:
            cookie_security["insecure_cookies"].append(cookie.name)
            
    return cookie_security


def check_caching_headers(response: requests.Response) -> Dict:
    """
    Check caching-related headers and policies
    """
    caching_info = {
        "cache_control": None,
        "pragma": None,
        "expires": None,
        "etag": None,
        "last_modified": None,
        "no_cache": False,
        "no_store": False,
        "has_caching_headers": False
    }
    
    # Check for caching headers
    if 'Cache-Control' in response.headers:
        caching_info["cache_control"] = response.headers['Cache-Control']
        caching_info["has_caching_headers"] = True
        
        # Check for no-cache and no-store directives
        if 'no-cache' in response.headers['Cache-Control']:
            caching_info["no_cache"] = True
        if 'no-store' in response.headers['Cache-Control']:
            caching_info["no_store"] = True
            
    if 'Pragma' in response.headers:
        caching_info["pragma"] = response.headers['Pragma']
        caching_info["has_caching_headers"] = True
        
    if 'Expires' in response.headers:
        caching_info["expires"] = response.headers['Expires']
        caching_info["has_caching_headers"] = True
        
    if 'ETag' in response.headers:
        caching_info["etag"] = response.headers['ETag']
        caching_info["has_caching_headers"] = True
        
    if 'Last-Modified' in response.headers:
        caching_info["last_modified"] = response.headers['Last-Modified']
        caching_info["has_caching_headers"] = True
        
    return caching_info


def extract_server_info(response: requests.Response) -> Dict:
    """
    Extract detailed server information from HTTP headers
    """
    server_info = {
        "server": None,
        "x_powered_by": None,
        "via": None,
        "technology_stack": []
    }
    
    # Extract basic server headers
    if 'Server' in response.headers:
        server_info["server"] = response.headers['Server']
        
    if 'X-Powered-By' in response.headers:
        server_info["x_powered_by"] = response.headers['X-Powered-By']
        
    if 'Via' in response.headers:
        server_info["via"] = response.headers['Via']
        
    # Try to detect technology stack
    # Web server
    if server_info["server"]:
        for tech in ["Apache", "nginx", "IIS", "LiteSpeed", "Tomcat", "Jetty", "Node.js", "Gunicorn"]:
            if tech.lower() in server_info["server"].lower():
                server_info["technology_stack"].append(tech)
                
    # Programming languages and frameworks
    if server_info["x_powered_by"]:
        for tech in ["PHP", "ASP.NET", "JSF", "Django", "Express", "Laravel", "Ruby", "Java"]:
            if tech.lower() in server_info["x_powered_by"].lower():
                server_info["technology_stack"].append(tech)
                
    # Check headers for common technologies
    for header, value in response.headers.items():
        if 'django' in header.lower() or 'django' in value.lower():
            server_info["technology_stack"].append("Django")
        if 'rails' in header.lower() or 'rails' in value.lower():
            server_info["technology_stack"].append("Ruby on Rails")
        if 'spring' in header.lower() or 'spring' in value.lower():
            server_info["technology_stack"].append("Spring")
            
    # Deduplicate technologies
    server_info["technology_stack"] = list(set(server_info["technology_stack"]))
    
    return server_info


def check_for_vulns(url: str, soup: BeautifulSoup) -> Dict:
    """
    Perform basic vulnerability checks
    """
    vuln_info = {
        "potential_vulns": [],
        "checks_performed": [],
        "disclaimer": "This is a passive scan and may produce false positives or miss vulnerabilities."
    }
    
    # 1. Check for potential XSS in reflected parameters
    vuln_info["checks_performed"].append("Reflected parameter check")
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.query:
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for param, values in query_params.items():
            for value in values:
                if value and value in str(soup):
                    vuln_info["potential_vulns"].append({
                        "type": "Potential Reflected XSS",
                        "description": f"Parameter '{param}' with value '{value}' found in page response",
                        "severity": "Medium"
                    })
    
    # 2. Check for forms without CSRF tokens
    vuln_info["checks_performed"].append("CSRF protection check")
    forms = soup.find_all('form', method=lambda m: m and m.lower() == 'post')
    for form in forms:
        has_csrf_token = False
        
        # Look for hidden input fields that might be CSRF tokens
        hidden_inputs = form.find_all('input', type='hidden')
        for hidden in hidden_inputs:
            input_name = hidden.get('name', '').lower()
            if 'csrf' in input_name or 'token' in input_name:
                has_csrf_token = True
                break
                
        if not has_csrf_token:
            form_action = form.get('action', '[no action]')
            vuln_info["potential_vulns"].append({
                "type": "Potential CSRF Vulnerability",
                "description": f"Form with action '{form_action}' lacks CSRF protection",
                "severity": "Medium"
            })
    
    # 3. Check for potential open redirects
    vuln_info["checks_performed"].append("Open redirect check")
    redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'returnTo', 'redirect_uri', 'redir']
    links = soup.find_all('a', href=True)
    
    for link in links:
        href = link['href']
        parsed_href = urllib.parse.urlparse(href)
        
        if parsed_href.query:
            query_params = urllib.parse.parse_qs(parsed_href.query)
            for param in redirect_params:
                if param in query_params:
                    vuln_info["potential_vulns"].append({
                        "type": "Potential Open Redirect",
                        "description": f"Link contains redirect parameter '{param}': {href}",
                        "severity": "Low"
                    })
                    break
    
    # 4. Check for potential host header injection
    vuln_info["checks_performed"].append("Host header injection check")
    all_links = soup.find_all(['a', 'form', 'img', 'script', 'link'], src=True) + soup.find_all(['a', 'form'], href=True)
    
    for element in all_links:
        attr = 'href' if element.has_attr('href') else 'src'
        url_value = element[attr]
        
        # Check for URLs without scheme and domain
        if url_value.startswith('/') and not url_value.startswith('//'):
            continue  # These are safe relative URLs
            
        # Check for URLs that might use the Host header
        if '//' in url_value[:8]:  # Protocol-relative URLs
            vuln_info["potential_vulns"].append({
                "type": "Potential Host Header Injection",
                "description": f"Protocol-relative URL found: {url_value}",
                "severity": "Low"
            })
            break
    
    # 5. Check for potentially outdated libraries
    vuln_info["checks_performed"].append("Outdated library check")
    outdated_patterns = {
        "jquery": [
            (r'jquery.+?([0-2]\.[0-9]\.[0-9])', "jQuery < 3.0.0"),
            (r'jquery-([0-9]\.[0-9]\.[0-9])', "jQuery via filename")
        ],
        "bootstrap": [
            (r'bootstrap.+?([0-3]\.[0-9]\.[0-9])', "Bootstrap < 4.0.0")
        ],
        "angular": [
            (r'angular.+?([0-1]\.[0-9]\.[0-9])', "AngularJS < 1.7.0 (potentially outdated)")
        ]
    }
    
    # Check script tags for outdated libraries
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = script['src']
        
        for lib, patterns in outdated_patterns.items():
            for pattern, desc in patterns:
                if re.search(pattern, src, re.IGNORECASE):
                    vuln_info["potential_vulns"].append({
                        "type": "Potentially Outdated Library",
                        "description": f"{desc} detected: {src}",
                        "severity": "Low"
                    })
                    
    return vuln_info


def check_for_clickjacking(response: requests.Response) -> Dict:
    """
    Check for clickjacking protection (X-Frame-Options and CSP frame-ancestors)
    """
    clickjacking_info = {
        "protected": False,
        "protection_method": None,
        "x_frame_options": None,
        "csp_frame_ancestors": None
    }
    
    # Check X-Frame-Options header
    if 'X-Frame-Options' in response.headers:
        clickjacking_info["x_frame_options"] = response.headers['X-Frame-Options']
        clickjacking_info["protected"] = True
        clickjacking_info["protection_method"] = "X-Frame-Options"
        
    # Check CSP frame-ancestors directive
    if 'Content-Security-Policy' in response.headers:
        csp = response.headers['Content-Security-Policy']
        frame_ancestors_match = re.search(r'frame-ancestors\s+([^;]+)', csp)
        
        if frame_ancestors_match:
            clickjacking_info["csp_frame_ancestors"] = frame_ancestors_match.group(1).strip()
            clickjacking_info["protected"] = True
            if not clickjacking_info["protection_method"]:
                clickjacking_info["protection_method"] = "CSP frame-ancestors"
            else:
                clickjacking_info["protection_method"] = "Both X-Frame-Options and CSP frame-ancestors"
                
    return clickjacking_info


def check_file_upload_forms(soup: BeautifulSoup) -> Dict:
    """
    Identify and analyze file upload forms
    """
    upload_info = {
        "total_upload_forms": 0,
        "forms": []
    }
    
    # Look for forms with file input elements
    forms = soup.find_all('form')
    for form in forms:
        file_inputs = form.find_all('input', type='file')
        
        if file_inputs:
            form_data = {
                "action": form.get('action', ''),
                "method": form.get('method', 'GET').upper(),
                "enctype": form.get('enctype', ''),
                "total_file_inputs": len(file_inputs),
                "file_input_names": [input_tag.get('name', '') for input_tag in file_inputs],
                "accept_attributes": [input_tag.get('accept', '') for input_tag in file_inputs],
                "correct_enctype": form.get('enctype', '') == 'multipart/form-data'
            }
            
            upload_info["forms"].append(form_data)
            upload_info["total_upload_forms"] += 1
            
    return upload_info


def check_password_forms(soup: BeautifulSoup) -> Dict:
    """
    Analyze forms containing password fields for security issues
    """
    password_form_info = {
        "total_password_forms": 0,
        "forms": [],
        "secure_forms": 0,
        "insecure_forms": 0
    }
    
    forms = soup.find_all('form')
    for form in forms:
        password_inputs = form.find_all('input', type='password')
        
        if password_inputs:
            # Gather form data
            form_data = {
                "action": form.get('action', ''),
                "method": form.get('method', 'GET').upper(),
                "has_autocomplete_off": False,
                "submits_over_https": False,
                "has_csrf_token": False,
                "has_captcha": False
            }
            
            # Check for autocomplete=off
            for pw_input in password_inputs:
                if pw_input.get('autocomplete', '').lower() == 'off':
                    form_data["has_autocomplete_off"] = True
                    break
            
            # Check if form submits over HTTPS
            action = form_data["action"]
            if action.startswith('https://') or (not action.startswith('http://') and not action.startswith('//')):
                form_data["submits_over_https"] = True
                
            # Check for CSRF token
            hidden_inputs = form.find_all('input', type='hidden')
            for hidden in hidden_inputs:
                input_name = hidden.get('name', '').lower()
                if 'csrf' in input_name or 'token' in input_name:
                    form_data["has_csrf_token"] = True
                    break
                    
            # Check for CAPTCHA
            form_html = str(form).lower()
            if 'captcha' in form_html or 'recaptcha' in form_html:
                form_data["has_captcha"] = True
                
            # Count as secure or insecure
            if form_data["method"] == "POST" and form_data["submits_over_https"]:
                password_form_info["secure_forms"] += 1
            else:
                password_form_info["insecure_forms"] += 1
                
            password_form_info["forms"].append(form_data)
            password_form_info["total_password_forms"] += 1
            
    return password_form_info


def check_api_endpoints(soup: BeautifulSoup, base_url: str) -> Dict:
    """
    Identify potential API endpoints from JavaScript code
    """
    api_info = {
        "potential_endpoints": [],
        "total_found": 0
    }
    
    # Common API endpoint patterns
    api_patterns = [
        r'/api/[a-zA-Z0-9_/-]+',
        r'/v[0-9]+/[a-zA-Z0-9_/-]+',
        r'/rest/[a-zA-Z0-9_/-]+',
        r'/ajax/[a-zA-Z0-9_/-]+',
        r'/service/[a-zA-Z0-9_/-]+',
        r'/graphql'
    ]
    
    # Extract all script contents
    scripts = soup.find_all('script')
    script_contents = [script.string for script in scripts if script.string]
    combined_js = "\n".join([s for s in script_contents if s])
    
    # Find potential API endpoints using patterns
    for pattern in api_patterns:
        matches = re.findall(pattern, combined_js)
        for match in matches:
            # Filter out duplicates and normalize
            if match not in api_info["potential_endpoints"]:
                api_info["potential_endpoints"].append(match)
                
    # Find .json or .xml endpoints specifically
    data_file_pattern = r'(?:"|\'|\()(/[a-zA-Z0-9_/-]+\.(?:json|xml))(?:"|\)|\')'
    data_file_matches = re.findall(data_file_pattern, combined_js)
    for match in data_file_matches:
        if match not in api_info["potential_endpoints"]:
            api_info["potential_endpoints"].append(match)
    
    # Convert relative URLs to absolute
    for i, endpoint in enumerate(api_info["potential_endpoints"]):
        if endpoint.startswith('/'):
            parsed_base = urllib.parse.urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            api_info["potential_endpoints"][i] = base_domain + endpoint
            
    api_info["total_found"] = len(api_info["potential_endpoints"])
    
    return api_info


def check_server_status(url: str) -> Dict:
    """
    Check server response time, status, redirects, and performance metrics
    """
    status_info = {
        "status_code": None,
        "response_time": None,
        "redirects": [],
        "headers": {},
        "response_size": None,
        "performance_grade": None
    }
    
    try:
        start_time = time.time()
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        end_time = time.time()
        
        # Basic response info
        status_info["status_code"] = response.status_code
        status_info["response_time"] = round(end_time - start_time, 3)
        status_info["headers"] = dict(response.headers)
        status_info["response_size"] = len(response.content)
        
        # Track redirects
        for resp in response.history:
            status_info["redirects"].append({
                "status_code": resp.status_code,
                "url": resp.url,
                "location": resp.headers.get('Location', 'N/A')
            })
            
        # Simple performance grading based on response time
        if status_info["response_time"] < 0.5:
            status_info["performance_grade"] = "Excellent"
        elif status_info["response_time"] < 1.0:
            status_info["performance_grade"] = "Good"
        elif status_info["response_time"] < 2.0:
            status_info["performance_grade"] = "Average"
        elif status_info["response_time"] < 4.0:
            status_info["performance_grade"] = "Poor"
        else:
            status_info["performance_grade"] = "Very Poor"
            
    except Exception as e:
        status_info["error"] = str(e)
        
    return status_info


def check_email_protection(soup: BeautifulSoup) -> Dict:
    """
    Check for email address protection methods
    """
    email_protection_info = {
        "plain_emails": [],
        "obfuscated_emails": [],
        "using_protection": False,
        "protection_methods": []
    }
    
    # Check for plain emails
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    html_content = str(soup)
    emails = re.findall(email_pattern, html_content)
    if emails:
        email_protection_info["plain_emails"] = list(set(emails))[:10]  # Limit to 10 unique emails
        
    # Check for common email obfuscation techniques
    
    # 1. JavaScript encoded emails
    if 'document.write' in html_content and '@' in html_content:
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'document.write' in script.string and ('@' in script.string or '&#' in script.string):
                email_protection_info["using_protection"] = True
                if "JavaScript encoding" not in email_protection_info["protection_methods"]:
                    email_protection_info["protection_methods"].append("JavaScript encoding")
                    
    # 2. HTML entity encoded emails
    entity_pattern = r'&#[0-9]+;&#[0-9]+;&#[0-9]+;'  # Simplified pattern for entity-encoded emails
    if re.search(entity_pattern, html_content):
        email_protection_info["using_protection"] = True
        if "HTML entity encoding" not in email_protection_info["protection_methods"]:
            email_protection_info["protection_methods"].append("HTML entity encoding")
            
    # 3. Image-based emails
    email_images = soup.find_all('img', alt=lambda alt: alt and '@' in alt)
    if email_images:
        email_protection_info["using_protection"] = True
        if "Image-based emails" not in email_protection_info["protection_methods"]:
            email_protection_info["protection_methods"].append("Image-based emails")
            
    # 4. CSS-protected emails
    if '.email' in html_content or '#email' in html_content:
        styles = soup.find_all('style')
        for style in styles:
            if style.string and ('email' in style.string or 'mail-protection' in style.string):
                email_protection_info["using_protection"] = True
                if "CSS protection" not in email_protection_info["protection_methods"]:
                    email_protection_info["protection_methods"].append("CSS protection")
                    
    # 5. Contact forms instead of email
    contact_forms = soup.find_all('form', action=lambda a: a and 'contact' in a.lower())
    if contact_forms:
        email_protection_info["using_protection"] = True
        if "Contact form" not in email_protection_info["protection_methods"]:
            email_protection_info["protection_methods"].append("Contact form")
            
    # Find potential obfuscated emails
    at_replacements = [' at ', '[at]', '(at)', '{at}', ' AT ']
    dot_replacements = [' dot ', '[dot]', '(dot)', '{dot}', ' DOT ']
    
    text = soup.get_text()
    for line in text.split('\n'):
        for at_repl in at_replacements:
            if at_repl in line:
                for dot_repl in dot_replacements:
                    if dot_repl in line and len(line) < 100:  # Limit to shorter lines
                        email_protection_info["obfuscated_emails"].append(line.strip())
                        email_protection_info["using_protection"] = True
                        if "Text obfuscation" not in email_protection_info["protection_methods"]:
                            email_protection_info["protection_methods"].append("Text obfuscation")
                        break
                        
    # Deduplicate obfuscated emails
    email_protection_info["obfuscated_emails"] = list(set(email_protection_info["obfuscated_emails"]))
    
    return email_protection_info


def check_for_honeypots(soup: BeautifulSoup) -> Dict:
    """
    Check for form honeypots to detect bots/automated scanners
    """
    honeypot_info = {
        "potential_honeypots": [],
        "honeypot_detected": False
    }
    
    # Check for common honeypot techniques
    
    # 1. Hidden inputs with bot-attractive names
    honeypot_names = ['name', 'email', 'website', 'url', 'phone', 'address', 'comment', 'message']
    hidden_inputs = soup.find_all('input', type='hidden')
    
    for input_tag in hidden_inputs:
        name = input_tag.get('name', '').lower()
        for hp_name in honeypot_names:
            if hp_name in name:
                honeypot_info["potential_honeypots"].append({
                    "type": "Hidden input with attractive name",
                    "element": f"<input type='hidden' name='{name}'>"
                })
                honeypot_info["honeypot_detected"] = True
                break
                
    # 2. CSS-hidden fields
    # Look for inputs with display:none or visibility:hidden
    style_patterns = ['display:none', 'visibility:hidden', 'opacity:0', 'height:0', 'position:absolute;left:-9999px']
    
    for input_tag in soup.find_all('input'):
        style = input_tag.get('style', '')
        if any(pattern in style for pattern in style_patterns):
            honeypot_info["potential_honeypots"].append({
                "type": "CSS-hidden input",
                "element": f"<input type='{input_tag.get('type', '')}' name='{input_tag.get('name', '')}' style='{style}'>"
            })
            honeypot_info["honeypot_detected"] = True
            
    # 3. Form fields in hidden containers
    for div in soup.find_all('div', style=True):
        style = div.get('style', '')
        if any(pattern in style for pattern in style_patterns):
            inputs = div.find_all('input')
            if inputs:
                honeypot_info["potential_honeypots"].append({
                    "type": "Inputs in hidden container",
                    "element": f"<div style='{style}'> containing {len(inputs)} input(s)"
                })
                honeypot_info["honeypot_detected"] = True
                
    # 4. Fields with suspicious class names
    suspicious_classes = ['honey', 'pot', 'trap', 'hp-', 'honeypot', 'spam', 'bot']
    for input_tag in soup.find_all('input'):
        class_attr = input_tag.get('class', [])
        if isinstance(class_attr, list):
            for cls in class_attr:
                if any(susp in cls.lower() for susp in suspicious_classes):
                    honeypot_info["potential_honeypots"].append({
                        "type": "Input with suspicious class",
                        "element": f"<input type='{input_tag.get('type', '')}' name='{input_tag.get('name', '')}' class='{' '.join(class_attr)}'>"
                    })
                    honeypot_info["honeypot_detected"] = True
                    break
        elif isinstance(class_attr, str) and any(susp in class_attr.lower() for susp in suspicious_classes):
            honeypot_info["potential_honeypots"].append({
                "type": "Input with suspicious class",
                "element": f"<input type='{input_tag.get('type', '')}' name='{input_tag.get('name', '')}' class='{class_attr}'>"
            })
            honeypot_info["honeypot_detected"] = True
            
    return honeypot_info


def check_iframe_security(soup: BeautifulSoup) -> Dict:
    """
    Check iframes for security issues
    """
    iframe_security = {
        "total_iframes": 0,
        "iframes": [],
        "sandboxed_iframes": 0,
        "insecure_iframes": []
    }
    
    iframes = soup.find_all('iframe')
    iframe_security["total_iframes"] = len(iframes)
    
    for iframe in iframes:
        iframe_data = {
            "src": iframe.get('src', ''),
            "title": iframe.get('title', ''),
            "has_sandbox": 'sandbox' in iframe.attrs,
            "sandbox_value": iframe.get('sandbox', ''),
            "uses_https": iframe.get('src', '').startswith('https://'),
            "iframe_id": iframe.get('id', ''),
            "has_allow": 'allow' in iframe.attrs,
            "allow_value": iframe.get('allow', '')
        }
        
        iframe_security["iframes"].append(iframe_data)
        
        # Count sandboxed iframes
        if iframe_data["has_sandbox"]:
            iframe_security["sandboxed_iframes"] += 1
            
        # Check for security issues
        if not iframe_data["has_sandbox"] or not iframe_data["uses_https"]:
            iframe_security["insecure_iframes"].append({
                "src": iframe_data["src"],
                "issues": []
            })
            
            if not iframe_data["has_sandbox"]:
                iframe_security["insecure_iframes"][-1]["issues"].append("No sandbox attribute")
                
            if not iframe_data["uses_https"] and iframe_data["src"] and not iframe_data["src"].startswith('/'):
                iframe_security["insecure_iframes"][-1]["issues"].append("Not using HTTPS")
                
    return iframe_security


def check_third_party_resources(soup: BeautifulSoup, base_url: str) -> Dict:
    """
    Analyze third-party resources loaded by the page
    """
    third_party_info = {
        "total_third_party": 0,
        "analytics": [],
        "social_media": [],
        "advertising": [],
        "cdn": [],
        "other": [],
        "domains": {}
    }
    
    # Extract base domain for comparison
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc
    if base_domain.startswith('www.'):
        base_domain = base_domain[4:]
        
    # Common services by category
    analytics_services = ['google-analytics', 'analytics', 'matomo', 'piwik', 'statcounter', 'mixpanel', 'hotjar', 'heap']
    social_media_services = ['facebook', 'twitter', 'linkedin', 'instagram', 'pinterest', 'youtube', 'tiktok', 'snapchat']
    advertising_services = ['doubleclick', 'adsense', 'adroll', 'taboola', 'outbrain', 'criteo', 'pubmatic', 'openx']
    cdn_services = ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'unpkg', 'jsdelivr', 'cdnjs', 'bootstrapcdn']
    
    # Find all elements with external resources
    external_resources = []
    
    # Scripts
    for script in soup.find_all('script', src=True):
        external_resources.append(('script', script['src']))
        
    # Stylesheets
    for link in soup.find_all('link', rel="stylesheet", href=True):
        external_resources.append(('stylesheet', link['href']))
        
    # Images
    for img in soup.find_all('img', src=True):
        external_resources.append(('image', img['src']))
        
    # Iframes
    for iframe in soup.find_all('iframe', src=True):
        external_resources.append(('iframe', iframe['src']))
        
    # Process all external resources
    for res_type, res_url in external_resources:
        if not res_url or res_url.startswith('data:'):
            continue
            
        # Convert to absolute URL if relative
        if not res_url.startswith(('http://', 'https://')):
            res_url = urllib.parse.urljoin(base_url, res_url)
            
        # Extract domain
        parsed_res = urllib.parse.urlparse(res_url)
        res_domain = parsed_res.netloc
        
        # Skip if it's the same domain
        if not res_domain or res_domain == base_domain or (res_domain.startswith('www.') and res_domain[4:] == base_domain):
            continue
            
        # Count as third-party
        third_party_info["total_third_party"] += 1
        
        # Add to domain counter
        if res_domain in third_party_info["domains"]:
            third_party_info["domains"][res_domain] += 1
        else:
            third_party_info["domains"][res_domain] = 1
            
        # Categorize the resource
        res_domain_lower = res_domain.lower()
        
        # Check which category it belongs to
        if any(service in res_domain_lower or service in res_url.lower() for service in analytics_services):
            if res_url not in third_party_info["analytics"]:
                third_party_info["analytics"].append(res_url)
        elif any(service in res_domain_lower for service in social_media_services):
            if res_url not in third_party_info["social_media"]:
                third_party_info["social_media"].append(res_url)
        elif any(service in res_domain_lower for service in advertising_services):
            if res_url not in third_party_info["advertising"]:
                third_party_info["advertising"].append(res_url)
        elif any(service in res_domain_lower for service in cdn_services):
            if res_url not in third_party_info["cdn"]:
                third_party_info["cdn"].append(res_url)
        else:
            if res_url not in third_party_info["other"]:
                third_party_info["other"].append(res_url)
                
    return third_party_info


def check_content_types(response: requests.Response) -> Dict:
    """
    Analyze content types and encoding
    """
    content_info = {
        "content_type": None,
        "charset": None,
        "content_length": None,
        "content_encoding": None,
        "language": None
    }
    
    # Extract Content-Type header
    if 'Content-Type' in response.headers:
        content_info["content_type"] = response.headers['Content-Type']
        
        # Extract charset if present
        charset_match = re.search(r'charset=([^;]+)', content_info["content_type"])
        if charset_match:
            content_info["charset"] = charset_match.group(1).strip()
            
    # Content-Length
    if 'Content-Length' in response.headers:
        content_info["content_length"] = response.headers['Content-Length']
        
    # Content-Encoding
    if 'Content-Encoding' in response.headers:
        content_info["content_encoding"] = response.headers['Content-Encoding']
        
    # Content-Language
    if 'Content-Language' in response.headers:
        content_info["language"] = response.headers['Content-Language']
        
    return content_info


def check_mixed_content(soup: BeautifulSoup, url: str) -> Dict:
    """
    Check for mixed content (HTTP resources on HTTPS pages)
    """
    mixed_content = {
        "has_mixed_content": False,
        "mixed_resources": [],
        "is_https_page": url.startswith("https://")
    }
    
    # Only check for mixed content on HTTPS pages
    if not mixed_content["is_https_page"]:
        return mixed_content
        
    # Look for HTTP resources
    resource_tags = {
        'script': 'src',
        'link': 'href',
        'img': 'src',
        'iframe': 'src',
        'audio': 'src',
        'video': 'src',
        'source': 'src',
        'form': 'action'
    }
    
    for tag, attr in resource_tags.items():
        for element in soup.find_all(tag, {attr: True}):
            res_url = element[attr]
            if res_url.startswith('http://'):
                mixed_content["has_mixed_content"] = True
                mixed_content["mixed_resources"].append({
                    "type": tag,
                    "url": res_url
                })
                
    # Check inline styles with HTTP URLs
    for style_tag in soup.find_all('style'):
        if style_tag.string:
            http_urls = re.findall(r'url\([\'"]?(http://[^\'")\s]+)', style_tag.string)
            for http_url in http_urls:
                mixed_content["has_mixed_content"] = True
                mixed_content["mixed_resources"].append({
                    "type": "style",
                    "url": http_url
                })
                
    # Check inline style attributes
    for element in soup.find_all(style=True):
        http_urls = re.findall(r'url\([\'"]?(http://[^\'")\s]+)', element['style'])
        for http_url in http_urls:
            mixed_content["has_mixed_content"] = True
            mixed_content["mixed_resources"].append({
                "type": "inline style",
                "url": http_url
            })
            
    return mixed_content


def check_insecure_deserialization(soup: BeautifulSoup) -> Dict:
    """
    Check for potential insecure deserialization patterns in JavaScript code
    """
    deser_info = {
        "potential_issues": [],
        "checked": True,
        "disclaimer": "This is a heuristic check and may produce false positives or miss vulnerabilities."
    }
    
    # Extract all script contents
    scripts = soup.find_all('script')
    script_contents = [script.string for script in scripts if script.string]
    combined_js = "\n".join([s for s in script_contents if s])
    
    # Risky deserialization patterns in JavaScript
    risky_patterns = [
        (r'eval\s*\(\s*(?:JSON\.parse|atob)\s*\(', "eval() with JSON.parse or atob"),
        (r'document\.write\s*\(\s*(?:JSON\.parse|atob)\s*\(', "document.write with parsed data"),
        (r'innerHTML\s*=\s*(?:JSON\.parse|atob)\s*\(', "innerHTML assignment with parsed data"),
        (r'JSON\.parse\s*\(\s*localStorage\.getItem', "JSON.parse with localStorage data"),
        (r'JSON\.parse\s*\(\s*sessionStorage\.getItem', "JSON.parse with sessionStorage data"),
        (r'unserialize\s*\(', "PHP-style unserialize function (may be custom implementation)"),
        (r'deserialize\s*\(', "Custom deserialize function"),
        (r'fromJSON\s*\(', "Custom fromJSON function")
    ]
    
    # Check each pattern
    for pattern, description in risky_patterns:
        matches = re.findall(pattern, combined_js)
        if matches:
            deser_info["potential_issues"].append({
                "pattern": description,
                "occurrences": len(matches),
                "severity": "Medium" 
            })
            
    return deser_info


# New functions added in clike2.py as requested

def attempt_login_bruteforce(url: str, username_wordlist: List[str] = None, password_wordlist: List[str] = None, 
                         form_identifier: str = None, max_attempts: int = 10, delay: float = 0.5) -> Dict:
    """
    Attempt to guess usernames and passwords on a login page
    
    IMPORTANT: This function should only be used on systems you have permission to test.
    Unauthorized access attempts may be illegal and unethical.
    
    Args:
        url: URL of the login page
        username_wordlist: List of usernames to try (if None, uses a small default list)
        password_wordlist: List of passwords to try (if None, uses a small default list)
        form_identifier: CSS selector or ID to identify the login form (if None, tries to auto-detect)
        max_attempts: Maximum number of attempts to try (default: 10)
        delay: Delay between attempts in seconds (default: 0.5)
    
    Returns:
        Dictionary with test results and information
    """
    print_info(f"Analyzing login form at {url} for credential testing...")
    
    # Default small wordlists for demonstration purposes
    # In a real implementation, these would be loaded from files
    default_usernames = [
        "admin", "administrator", "root", "user", "test", 
        "guest", "demo", "system", "webmaster", "info"
    ]
    
    default_passwords = [
        "password", "123456", "admin", "welcome", "pass123", 
        "test", "123", "demo", "qwerty", "letmein"
    ]
    
    usernames = username_wordlist or default_usernames
    passwords = password_wordlist or default_passwords
    
    # Limit to max_attempts
    if max_attempts > 0:
        usernames = usernames[:max_attempts//2]
        passwords = passwords[:max_attempts//2]
    
    # Check if URL is valid
    response = check_url(url)
    if not response:
        return {
            "status": "error",
            "message": f"Could not access the URL: {url}",
            "attempts": 0,
            "found": False
        }
    
    # Parse the HTML
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find login form
    login_form = None
    
    if form_identifier:
        # Try to find form by provided identifier
        if form_identifier.startswith('#'):
            login_form = soup.select_one(form_identifier)
        else:
            login_form = soup.find('form', id=form_identifier) or soup.find('form', class_=form_identifier)
    
    # If form not found or no identifier provided, try to auto-detect
    if not login_form:
        # Look for forms with password fields
        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields:
            for password_field in password_fields:
                parent_form = password_field.find_parent('form')
                if parent_form:
                    login_form = parent_form
                    break
    
    if not login_form:
        # Try to find forms with login-related attributes
        for form in soup.find_all('form'):
            form_html = str(form).lower()
            if any(keyword in form_html for keyword in ['login', 'signin', 'log in', 'sign in', 'auth']):
                login_form = form
                break
    
    if not login_form:
        return {
            "status": "error",
            "message": "Could not identify a login form on the page",
            "attempts": 0,
            "found": False
        }
    
    # Extract form details
    form_action = login_form.get('action', '')
    form_method = login_form.get('method', 'post').lower()
    
    # Resolve form action URL
    if form_action:
        if form_action.startswith('http'):
            action_url = form_action
        elif form_action.startswith('/'):
            parsed_url = urllib.parse.urlparse(url)
            action_url = f"{parsed_url.scheme}://{parsed_url.netloc}{form_action}"
        else:
            action_url = urllib.parse.urljoin(url, form_action)
    else:
        action_url = url
    
    # Find username and password fields
    username_field = None
    password_field = None
    
    # Find password field
    password_field = login_form.find('input', {'type': 'password'})
    if not password_field:
        return {
            "status": "error",
            "message": "Could not find password field in the form",
            "attempts": 0,
            "found": False
        }
    
    # Find username field - typically a text input before the password field
    # It could be type="text", type="email", or type="tel"
    username_field_types = ['text', 'email', 'tel']
    for field_type in username_field_types:
        potential_username_fields = login_form.find_all('input', {'type': field_type})
        for field in potential_username_fields:
            field_html = str(field).lower()
            if any(keyword in field_html for keyword in ['user', 'email', 'login', 'name', 'account']):
                username_field = field
                break
    
    # If we still didn't find it, take the first text input
    if not username_field:
        username_field = login_form.find('input', {'type': 'text'})
    
    if not username_field:
        return {
            "status": "error",
            "message": "Could not find username/email field in the form",
            "attempts": 0,
            "found": False
        }
    
    # Get field names
    username_field_name = username_field.get('name', '')
    password_field_name = password_field.get('name', '')
    
    if not username_field_name or not password_field_name:
        return {
            "status": "error",
            "message": "Could not determine form field names",
            "attempts": 0,
            "found": False
        }
    
    # Find other form fields that might be required (hidden fields, etc.)
    other_fields = {}
    for input_field in login_form.find_all('input'):
        if input_field != username_field and input_field != password_field:
            field_type = input_field.get('type', '')
            field_name = input_field.get('name', '')
            field_value = input_field.get('value', '')
            
            if field_name and field_type != 'submit' and field_type != 'button':
                other_fields[field_name] = field_value
    
    # Prepare for login attempts
    csrf_token = None
    session = requests.Session()
    
    # Look for CSRF token
    for name, value in other_fields.items():
        if any(token_name in name.lower() for token_name in ['csrf', 'token', 'nonce']):
            csrf_token = name
    
    # Store results
    attempts = 0
    results = {
        "status": "completed",
        "message": "Login form analysis completed",
        "form_action": action_url,
        "form_method": form_method,
        "username_field": username_field_name,
        "password_field": password_field_name,
        "has_csrf": csrf_token is not None,
        "attempts": 0,
        "found": False,
        "credentials_tested": []
    }
    
    print_info(f"Starting controlled credential testing (max {len(usernames) * len(passwords)} attempts, limited to {max_attempts})")
    print_warning("Remember: Only use this on systems you have explicit permission to test")
    
    # Display form information
    print_info(f"Form action: {action_url}")
    print_info(f"Form method: {form_method}")
    print_info(f"Username field: {username_field_name}")
    print_info(f"Password field: {password_field_name}")
    if csrf_token:
        print_info(f"CSRF token field: {csrf_token}")
    
    # Education warning in output
    result_warnings = [
        "This function is for educational purposes only.",
        "Always obtain explicit permission before testing any authentication system.",
        "Unauthorized access attempts may be illegal."
    ]
    
    # Perform limited login attempts
    for username in usernames:
        for password in passwords:
            # Enforce maximum attempts
            attempts += 1
            if max_attempts > 0 and attempts > max_attempts:
                print_warning(f"Reached maximum allowed attempts ({max_attempts})")
                results["message"] = f"Reached maximum attempts ({max_attempts})"
                break
            
            # If CSRF token exists, we need to get a fresh one for each attempt
            if csrf_token:
                try:
                    form_response = session.get(url)
                    form_soup = BeautifulSoup(form_response.text, 'html.parser')
                    form_element = form_soup.find('form', action=form_action) or form_soup.find('form')
                    if form_element:
                        token_field = form_element.find('input', {'name': csrf_token})
                        if token_field:
                            other_fields[csrf_token] = token_field.get('value', '')
                except Exception as e:
                    print_error(f"Error refreshing CSRF token: {str(e)}")
            
            # Create form data for this attempt
            form_data = other_fields.copy()
            form_data[username_field_name] = username
            form_data[password_field_name] = password
            
            # Log attempt details
            print_info(f"Testing credentials [{attempts}/{max_attempts if max_attempts > 0 else 'unlimited'}]: {username} / {password}")
            
            # Store credentials tested
            results["credentials_tested"].append({
                "username": username,
                "password": password,
                "attempt": attempts
            })
            
            # Perform the request
            try:
                if form_method == 'post':
                    login_response = session.post(action_url, data=form_data, allow_redirects=True)
                else:
                    login_response = session.get(action_url, params=form_data, allow_redirects=True)
                
                # Simple detection of successful login
                # In a real implementation, this would be more sophisticated
                login_response_text = login_response.text.lower()
                
                # Check for potential success indicators
                logout_indicators = ['logout', 'sign out', 'log out', 'account', 'profile', 'dashboard']
                error_indicators = ['incorrect', 'invalid', 'failed', 'wrong password', 'try again']
                
                has_logout = any(indicator in login_response_text for indicator in logout_indicators)
                has_error = any(indicator in login_response_text for indicator in error_indicators)
                
                # Very basic heuristic - in real implementation, this would be much more sophisticated
                potential_success = has_logout and not has_error
                
                if potential_success:
                    print_warning(f"Potential valid credentials found: {username} / {password}")
                    results["found"] = True
                    results["potential_valid_credentials"] = {
                        "username": username,
                        "password": password,
                        "attempt": attempts,
                        "confidence": "low"  # Without specific success criteria, confidence is low
                    }
                    break
                
                # Add delay between attempts
                if delay > 0:
                    time.sleep(delay)
                    
            except Exception as e:
                print_error(f"Error during login attempt: {str(e)}")
                continue
        
        if results["found"] or (max_attempts > 0 and attempts >= max_attempts):
            break
    
    # Update attempt count
    results["attempts"] = attempts
    results["warnings"] = result_warnings
    
    return results

def search_sql_files(url: str, output_type: str = 'p') -> Dict:
    """
    Search for SQL files on the target website
    
    Args:
        url: Target URL to search for SQL files
        output_type: How to handle the output
            'p' - print to console (plain text)
            'w' - send to webhook
            'f' - export to CSV file
    
    Returns:
        Dictionary with search results
    """
    print_info(f"Searching for SQL files on {url}")
    
    # Common SQL file extensions and paths to check
    sql_paths = [
        '/backup.sql', '/db.sql', '/database.sql', '/mysql.sql',
        '/dump.sql', '/data.sql', '/backup/db.sql', '/admin/backup.sql',
        '/wp-content/backup-db/', '/backups/', '/sqldump.sql',
        '/1.sql', '/backup-db.sql', '/sql/', '/db/', '/database/',
        '/db.inc', '/database.inc', '/configuration.php', '/users.sql'
    ]
    
    results = {
        "found_files": [],
        "scan_time": get_current_timestamp_str(),
        "url": url
    }
    
    # Get base domain
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Search for SQL files
    for path in sql_paths:
        target_url = base_url + path
        try:
            response = requests.head(target_url, headers=HEADERS, timeout=TIMEOUT)
            
            # If file exists (200 OK, 301 Moved, 302 Found, etc.)
            if 200 <= response.status_code < 400:
                # Try to get file size
                try:
                    file_size = int(response.headers.get('Content-Length', 0))
                    size_str = f"{file_size / 1024:.2f} KB" if file_size else "Unknown size"
                except:
                    size_str = "Unknown size"
                
                results["found_files"].append({
                    "url": target_url,
                    "status_code": response.status_code,
                    "size": size_str,
                    "content_type": response.headers.get('Content-Type', 'Unknown')
                })
                print_warning(f"Found SQL file: {target_url} ({size_str})")
        except Exception as e:
            continue
    
    results["total_found"] = len(results["found_files"])
    
    # Handle output based on output_type
    if output_type.lower() == 'w':
        # Send to webhook (will integrate with webhook functionality)
        print_info("Preparing to send SQL files list to webhook")
        try:
            # This would call the webhook function
            # For now, just inform that it would be sent to webhook
            print_info("SQL files would be sent to webhook (implementation pending)")
            return results
        except Exception as e:
            print_error(f"Failed to send to webhook: {str(e)}")
    
    elif output_type.lower() == 'f':
        # Export to CSV file
        print_info("Exporting SQL files to CSV")
        try:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            csv_filename = f"sql_files_{parsed_url.netloc}_{timestamp}.csv"
            
            with open(csv_filename, 'w', newline='') as csvfile:
                fieldnames = ['url', 'status_code', 'size', 'content_type']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for file in results["found_files"]:
                    writer.writerow(file)
            
            print_info(f"SQL files exported to {csv_filename}")
        except Exception as e:
            print_error(f"Failed to export to CSV: {str(e)}")
    
    else:  # 'p' or any other value - print to console
        # Format and print results
        if results["total_found"] > 0:
            print_result("SQL Files Found", results["found_files"])
        else:
            print_info("No SQL files found")
    
    return results


def get_current_timestamp_str() -> str:
    """
    Get current timestamp as a formatted string
    
    Returns:
        String with format 'YYYY-MM-DD HH:MM:SS'
    """
    return time.strftime("%Y-%m-%d %H:%M:%S")


def format_results(results: Dict, include_timestamp: bool = True) -> str:
    """
    Format scan results in a clean, readable format (not JSON)
    
    Args:
        results: Dictionary containing scan results
        include_timestamp: Whether to include a timestamp in the output
    
    Returns:
        Formatted string with results
    """
    output = []
    
    # Add header
    output.append("=" * 50)
    output.append("CLIKE SECURITY SCAN RESULTS")
    output.append("=" * 50)
    
    # Add timestamp if requested
    if include_timestamp:
        output.append(f"Scan Time: {get_current_timestamp_str()}")
    
    # Add target URL
    if "url" in results:
        output.append(f"Target URL: {results['url']}")
    
    # Add separator
    output.append("-" * 50)
    
    # Process each section of the results
    for section, data in results.items():
        if section in ['url', 'scan_time']:
            continue  # Already handled
            
        output.append(f"\n[{section.upper().replace('_', ' ')}]")
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (list, dict)):
                    output.append(f"  {key.replace('_', ' ').title()}:")
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                for sub_key, sub_value in item.items():
                                    output.append(f"    - {sub_key}: {sub_value}")
                                output.append("    ---")
                            else:
                                output.append(f"    - {item}")
                    else:  # dict
                        for sub_key, sub_value in value.items():
                            output.append(f"    - {sub_key}: {sub_value}")
                else:
                    output.append(f"  {key.replace('_', ' ').title()}: {value}")
        
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key, value in item.items():
                        output.append(f"  - {key}: {value}")
                    output.append("  ---")
                else:
                    output.append(f"  - {item}")
        
        else:
            output.append(f"  {data}")
    
    # Add footer
    output.append("\n" + "=" * 50)
    output.append("End of Report")
    output.append("=" * 50)
    
    return "\n".join(output)


def view_sensitive_file_content(url: str, file_path: str) -> str:
    """
    View the content of sensitive files found during a scan
    
    Args:
        url: Base URL of the target website
        file_path: Path to the sensitive file to view
    
    Returns:
        Content of the file if accessible, or error message
    """
    print_info(f"Attempting to view content of sensitive file: {file_path}")
    
    # Normalize URL and file path
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Ensure file_path starts with a slash
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    
    target_url = base_url + file_path
    
    try:
        # Attempt to fetch the file
        response, error = fetch_url(target_url)
        
        if error:
            return f"Error accessing file: {error}"
        
        if response.status_code != 200:
            return f"File not accessible. Status code: {response.status_code}"
        
        # Check content type
        content_type = response.headers.get('Content-Type', '')
        file_size = len(response.text)
        
        # If file is too large, truncate it
        if file_size > 10000 and (LITE_MODE and not DISABLE_LITE_MODE):
            content = response.text[:10000] + "\n\n[... Content truncated (file too large) ...]"
        else:
            content = response.text
        
        # Prepare result with metadata
        result = (
            f"=== FILE METADATA ===\n"
            f"URL: {target_url}\n"
            f"Content-Type: {content_type}\n"
            f"Size: {file_size / 1024:.2f} KB\n"
            f"Accessed: {get_current_timestamp_str()}\n"
            f"\n=== FILE CONTENT ===\n\n"
            f"{content}"
        )
        
        return result
        
    except Exception as e:
        return f"Error retrieving file content: {str(e)}"


def search_sql_files(url: str, output_type: str = 'p') -> Dict:
    """
    Search for SQL files on the target website
    
    Args:
        url: Target URL to search for SQL files
        output_type: How to handle the output
            'p' - print to console (plain text)
            'w' - send to webhook
            'f' - export to CSV file
    
    Returns:
        Dictionary with search results
    """
    print_info(f"Searching for SQL files on {url}...")
    
    # Common SQL file extensions and patterns
    sql_patterns = [
        '.sql', 'backup.sql', 'dump.sql', 'db.sql', 'database.sql',
        'mysql.sql', 'site.sql', 'backup/db.sql', 'admin/db.sql',
        'sql/backup.sql', 'data.sql', 'backup/database.sql',
        'wp-content/backup-db/backup.sql', 'backup-db.sql',
        'sqldump.sql', 'localhost.sql', 'temp.sql', 'temp/db.sql',
        'db_backup.sql', 'db_dump.sql', 'backup_db.sql', 'export.sql',
        'db-backup.sql', 'db_structure.sql', 'db_schema.sql',
        'sql/db-backup.sql', 'backup/mysql.sql', 'mysql-dump.sql',
        'mysqldump.sql', 'sql/mysqldump.sql', 'web.sql', 'install.sql',
        'setup.sql'
    ]
    
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if not base_url.endswith('/'):
        base_url += '/'
    
    results = {
        "url": url,
        "timestamp": get_current_timestamp_str(),
        "found_files": [],
        "total_checked": len(sql_patterns),
        "total_found": 0
    }
    
    for pattern in sql_patterns:
        target_url = base_url + pattern.lstrip('/')
        try:
            response = requests.head(target_url, timeout=5, 
                                     headers={"User-Agent": USER_AGENT}, 
                                     allow_redirects=False)
            
            status = response.status_code
            if 200 <= status < 300:
                file_info = {
                    "url": target_url,
                    "status_code": status,
                    "content_type": response.headers.get('Content-Type', 'Unknown'),
                    "content_length": response.headers.get('Content-Length', 'Unknown')
                }
                
                # For found files, try to get a small sample of the content
                try:
                    content_response = requests.get(target_url, timeout=5, 
                                                   headers={"User-Agent": USER_AGENT},
                                                   stream=True)
                    
                    # Read only the first 500 bytes for a preview
                    sample = content_response.raw.read(500).decode('utf-8', errors='ignore')
                    file_info["sample"] = sample
                except Exception as e:
                    file_info["sample_error"] = str(e)
                
                results["found_files"].append(file_info)
                print_warning(f"SQL file found: {target_url} (Status: {status})")
        except requests.RequestException:
            # Skip connection errors
            continue
    
    results["total_found"] = len(results["found_files"])
    
    # Handle output based on output_type
    if results["total_found"] > 0:
        if output_type == 'p':
            # Print to console (default)
            print_result("SQL Files Found", results)
            
        elif output_type == 'w':
            # Send to webhook
            webhook_url = input("Enter webhook URL to send results: ")
            if webhook_url:
                webhook_response = send_to_webhook({url: {"sql_files": results}}, webhook_url)
                if webhook_response["success"]:
                    print_info(f"Successfully sent SQL files results to webhook")
                else:
                    print_error(f"Failed to send SQL files results to webhook: {webhook_response['message']}")
            else:
                print_error("No webhook URL provided")
                
        elif output_type == 'f':
            # Export to CSV file
            filename = f"sql_files_{parsed_url.netloc}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            try:
                with open(filename, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['URL', 'Status Code', 'Content Type', 'Content Length', 'Sample'])
                    
                    for file in results["found_files"]:
                        writer.writerow([
                            file["url"],
                            file["status_code"],
                            file["content_type"],
                            file["content_length"],
                            file.get("sample", "N/A")[:100]  # Limit sample size
                        ])
                        
                print_info(f"SQL files results exported to {filename}")
            except Exception as e:
                print_error(f"Error exporting SQL files results: {str(e)}")
    else:
        print_info("No SQL files found")
    
    return results


def get_current_timestamp_str() -> str:
    """
    Get current timestamp as a formatted string
    
    Returns:
        String with format 'YYYY-MM-DD HH:MM:SS'
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_results(results: Dict, include_timestamp: bool = True) -> str:
    """
    Format scan results in a clean, readable format (not JSON)
    
    Args:
        results: Dictionary containing scan results
        include_timestamp: Whether to include a timestamp in the output
    
    Returns:
        Formatted string with results
    """
    formatted = "CLIKE URL Analysis Results\n"
    formatted += "=" * 50 + "\n"
    
    if include_timestamp:
        formatted += f"Timestamp: {get_current_timestamp_str()}\n\n"
    
    # Add URL if present in the first level
    if "url" in results:
        formatted += f"Target URL: {results['url']}\n\n"
    
    # Process each section
    for section, data in results.items():
        # Skip URL field which we already processed
        if section == "url":
            continue
            
        # Skip large sections that would make the output too verbose
        if section in ["text_content"]:
            continue
            
        # Format section header
        section_name = section.replace("_", " ").title()
        formatted += f"{section_name}\n"
        formatted += "-" * len(section_name) + "\n"
        
        # Format the data based on its type
        if isinstance(data, dict):
            for key, value in data.items():
                key_str = str(key).replace("_", " ").title()
                if isinstance(value, (dict, list)):
                    # For nested structures, use a simplified representation
                    formatted += f"  {key_str}: {type(value).__name__} with {len(value)} items\n"
                else:
                    formatted += f"  {key_str}: {value}\n"
        elif isinstance(data, list):
            if data and isinstance(data[0], dict):
                # For lists of dictionaries, show count and first item as sample
                formatted += f"  {len(data)} items found\n"
                if len(data) > 0:
                    formatted += "  Sample: " + ", ".join(f"{k}: {v}" for k, v in list(data[0].items())[:3]) + "\n"
            else:
                # For simple lists, just list all items (limited to first 10)
                for i, item in enumerate(data[:10]):
                    formatted += f"  {i+1}. {item}\n"
                if len(data) > 10:
                    formatted += f"  ... and {len(data) - 10} more items\n"
        else:
            # For simple values
            formatted += f"  {data}\n"
        
        formatted += "\n"
    
    # Add threat score information if present
    if "threat_score" in results:
        score = results["threat_score"]["score"]
        category = results["threat_score"]["category"]
        
        formatted += "Security Threat Assessment\n"
        formatted += "------------------------\n"
        formatted += f"Overall Threat Score: {score}/100 ({category})\n"
        
        if "details" in results["threat_score"]:
            formatted += "Issues Found:\n"
            for issue, value in results["threat_score"]["details"].items():
                formatted += f"  - {issue}: {value}\n"
        
        formatted += "\n"
    
    formatted += "=" * 50 + "\n"
    formatted += "Generated by CLIKE URL Penetration Testing Tool\n"
    
    return formatted


def view_sensitive_file_content(url: str, file_path: str) -> str:
    """
    View the content of sensitive files found during a scan
    
    Args:
        url: Base URL of the target website
        file_path: Path to the sensitive file to view
    
    Returns:
        Content of the file if accessible, or error message
    """
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Ensure the file path starts with a slash
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    
    target_url = base_url + file_path
    
    print_info(f"Attempting to access: {target_url}")
    
    try:
        response = requests.get(
            target_url,
            headers={"User-Agent": USER_AGENT},
            timeout=10
        )
        
        if response.status_code == 200:
            content = response.text
            if len(content) > 0:
                return content
            else:
                return "File exists but is empty"
        else:
            return f"Cannot access file: HTTP {response.status_code}"
    
    except requests.RequestException as e:
        return f"Error accessing file: {str(e)}"


def main():
    """Main function"""
    global LITE_MODE, DISABLE_LITE_MODE
    
    # Auto-detect Termux and enable lite mode
    termux_detected = False
    try:
        if os.path.exists("/data/data/com.termux") or 'TERMUX_VERSION' in os.environ:
            termux_detected = True
            LITE_MODE = True
            print_info("Termux detected, automatically enabling lite mode")
    except:
        pass
    
    # Create argument parser
    parser = argparse.ArgumentParser(add_help=False, description='CLIKE URL Penetration Testing Tool')
    
    # Basic options
    parser.add_argument('-u', '--url', help='URL of website to analyze')
    parser.add_argument('-b', '--batch', help='Process multiple URLs from a file (one URL per line)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode - enter URLs manually')
    parser.add_argument('-h', '--help', action='store_true', help='Display help message')
    parser.add_argument('--lite', action='store_true', help='Low resource mode')
    parser.add_argument('--disable-lite', action='store_true', help='Disable lite mode for Termux (consume more resources)')
    parser.add_argument('-all', '--all', action='store_true', help='Run all checks (includes Real-time Threat Score)')
    
    # Export options
    parser.add_argument('-e', '--export-results', action='store_true', help='Export results to a file')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json', 
                        help='Format to export results (json, csv, txt)')
    parser.add_argument('-o', '--output-file', help='Name of the output file')
    parser.add_argument('--webhook', help='Send results to a webhook URL (e.g., Discord, Slack)')
    
    # Analysis options
    parser.add_argument('-d', '--dns', action='store_true', help='DNS information')
    parser.add_argument('-r', '--redirects', action='store_true', help='URL redirects')
    parser.add_argument('-f', '--forms', action='store_true', help='Forms on page')
    parser.add_argument('-n', '--network', action='store_true', help='Network information')
    parser.add_argument('-m', '--meta', action='store_true', help='Meta tags')
    parser.add_argument('-c', '--cookies', action='store_true', help='Cookies')
    parser.add_argument('-s', '--security', action='store_true', help='HTTPS security')
    parser.add_argument('-t', '--title', action='store_true', help='Page title')
    parser.add_argument('-img', '--images', action='store_true', help='Count images')
    parser.add_argument('-l', '--links', action='store_true', help='Links analysis')
    parser.add_argument('-x', '--external', action='store_true', help='External links')
    parser.add_argument('-v', '--available', action='store_true', help='URL availability')
    parser.add_argument('-w', '--words', action='store_true', help='Word count')
    parser.add_argument('-j', '--js', action='store_true', help='JavaScript tags')
    parser.add_argument('--css', action='store_true', help='CSS resources')
    parser.add_argument('--sm', '--sitemap', action='store_true', dest='sitemap', help='Sitemap check')
    parser.add_argument('--robots', action='store_true', help='Robots.txt check')
    parser.add_argument('--vid', '--videos', action='store_true', dest='videos', help='Count videos')
    parser.add_argument('--broken', action='store_true', help='Check for broken links')
    parser.add_argument('--mobile', action='store_true', help='Mobile support check')
    parser.add_argument('--h1', action='store_true', help='Header tags')
    parser.add_argument('--lang', action='store_true', help='Page language')
    parser.add_argument('--export', action='store_true', help='Export text content')
    parser.add_argument('--sql', action='store_true', help='SQL leak check')
    
    # Additional advanced security checks (new)
    parser.add_argument('--cors', action='store_true', help='Check CORS policy')
    parser.add_argument('--csp', action='store_true', help='Check Content Security Policy')
    parser.add_argument('--feature-policy', action='store_true', help='Check Feature Policy headers')
    parser.add_argument('--sensitive-files', action='store_true', help='Check for sensitive files')
    parser.add_argument('--subdomains', action='store_true', help='Check common subdomains')
    parser.add_argument('--subdomain-wordlist', action='store_true', help='Use extended wordlist for subdomain check')
    parser.add_argument('--waf', action='store_true', help='Check for WAF presence')
    parser.add_argument('--sec-headers', action='store_true', help='Check security headers')
    parser.add_argument('--leaks', action='store_true', help='Check for information leaks')
    parser.add_argument('--ports', action='store_true', help='Check open ports (common only)')
    parser.add_argument('--ports-all', action='store_true', help='Check open ports (extended scan)')
    parser.add_argument('--ssl', action='store_true', help='Check SSL/TLS certificate info')
    parser.add_argument('--methods', action='store_true', help='Check HTTP methods')
    parser.add_argument('--cookie-sec', action='store_true', help='Check cookie security')
    parser.add_argument('--cache', action='store_true', help='Check caching headers')
    parser.add_argument('--server-info', action='store_true', help='Extract server information')
    parser.add_argument('--vulns', action='store_true', help='Check for common vulnerabilities')
    parser.add_argument('--clickjacking', action='store_true', help='Check clickjacking protection')
    parser.add_argument('--uploads', action='store_true', help='Analyze file upload forms')
    parser.add_argument('--passwords', action='store_true', help='Analyze password forms')
    parser.add_argument('--api', action='store_true', help='Identify potential API endpoints')
    parser.add_argument('--perf', action='store_true', help='Check server performance')
    parser.add_argument('--email-protection', action='store_true', help='Check email address protection')
    parser.add_argument('--honeypots', action='store_true', help='Check for form honeypots')
    parser.add_argument('--iframe-security', action='store_true', help='Check iframe security')
    parser.add_argument('--third-party', action='store_true', help='Analyze third-party resources')
    parser.add_argument('--content-type', action='store_true', help='Analyze content types')
    parser.add_argument('--mixed-content', action='store_true', help='Check for mixed content')
    parser.add_argument('--deserialize', action='store_true', help='Check for insecure deserialization')
    
    # New functions added in clike2.py
    parser.add_argument('--sql-search', action='store_true', help='Search for SQL files on the target website')
    parser.add_argument('-op', '--output', choices=['p', 'w', 'f'], default='p', 
                      help='Output type for SQL search (p=print to console, w=webhook, f=CSV file)')
    parser.add_argument('--view-file', help='View the content of a sensitive file (provide file path)')
    parser.add_argument('--format-results', action='store_true', help='Format results in a clean, readable format')
    parser.add_argument('--timestamp', action='store_true', help='Include timestamp in formatted results')
    parser.add_argument('--login-check', action='store_true', help='Attempt to identify login forms and test common credentials (educational use only)')
    parser.add_argument('--form-id', help='CSS selector or ID to identify the login form (e.g., #login-form)')
    parser.add_argument('--max-attempts', type=int, default=10, help='Maximum number of login attempts to try (default: 10)')
    parser.add_argument('--attempt-delay', type=float, default=0.5, help='Delay between login attempts in seconds (default: 0.5)')
    
    # Extraction options
    parser.add_argument('--headers', action='store_true', help='Get HTTP headers')
    parser.add_argument('--internal', action='store_true', help='Get internal links')
    parser.add_argument('--assets', action='store_true', help='Get assets')
    parser.add_argument('--scripts', action='store_true', help='Get scripts')
    parser.add_argument('--inputs', action='store_true', help='Get input fields')
    parser.add_argument('--buttons', action='store_true', help='Get buttons')
    parser.add_argument('--tables', action='store_true', help='Get tables')
    parser.add_argument('--iframes', action='store_true', help='Get iframes')
    parser.add_argument('--content', action='store_true', help='Get content')
    parser.add_argument('--keywords', action='store_true', help='Get keywords')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Print logo
    print(LOGO)
    
    # Display help if requested or if no other operation mode specified
    if args.help or (not args.url and not args.batch and not args.interactive):
        print_help()
        return
    
    # Set lite mode if requested
    LITE_MODE = args.lite
    DISABLE_LITE_MODE = args.disable_lite
    
    if LITE_MODE:
        print_warning("Lite mode enabled, some operations will be limited")
    
    if DISABLE_LITE_MODE:
        print_warning("Lite mode disabled for Termux, this may use more resources")
    
    # Process batch of URLs if provided
    if args.batch:
        process_batch(args.batch, args)
        return
        
    # Interactive mode - get URLs from user input
    if args.interactive:
        process_input_urls(args)
        return
    
    # Process single URL
    if args.export_results or args.webhook:
        results = process_url_with_results(args.url, args)
        # Export results for single URL
        all_results = {args.url: results}
        
        # Export results to a file if requested
        if args.export_results:
            export_format = args.format or 'json'
            export_results(all_results, export_format, args.output_file)
        
        # Send results to webhook if provided
        if args.webhook:
            webhook_response = send_to_webhook(all_results, args.webhook)
            if webhook_response["success"]:
                print_info(f"Successfully sent results to webhook: {args.webhook}")
            else:
                print_error(f"Failed to send results to webhook: {webhook_response['message']}")
    else:
        process_url(args.url, args)


def attempt_login_bruteforce(url: str, username_wordlist: List[str] = None, password_wordlist: List[str] = None, 
                         form_identifier: str = None, max_attempts: int = 10, delay: float = 0.5) -> Dict:
    """
    Attempt to guess usernames and passwords on a login page
    
    IMPORTANT: This function should only be used on systems you have permission to test.
    Unauthorized access attempts may be illegal and unethical.
    
    Args:
        url: URL of the login page
        username_wordlist: List of usernames to try (if None, uses a small default list)
        password_wordlist: List of passwords to try (if None, uses a small default list)
        form_identifier: CSS selector or ID to identify the login form (if None, tries to auto-detect)
        max_attempts: Maximum number of attempts to try (default: 10)
        delay: Delay between attempts in seconds (default: 0.5)
    
    Returns:
        Dictionary with test results and information
    """
    # Default small wordlists (for demonstration/education only!)
    default_usernames = ["admin", "user", "test", "demo", "guest"]
    default_passwords = ["password", "123456", "admin", "welcome", "test"]
    
    # Use provided wordlists or defaults
    usernames = username_wordlist if username_wordlist else default_usernames
    passwords = password_wordlist if password_wordlist else default_passwords
    
    print_info(f"Checking login form security on {url}")
    print_info(f"Maximum attempts set to: {max_attempts}")
    
    # Results structure
    results = {
        "url": url,
        "form_found": False,
        "form_details": {},
        "attempts": [],
        "successful_login": False,
        "successful_credentials": None,
        "total_attempts": 0,
        "protection_detected": False,
        "protection_details": []
    }
    
    # Try to get the login page
    response, error = fetch_url(url)
    if error:
        results["error"] = f"Failed to access URL: {error}"
        return results
    
    # Parse HTML
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find login form
    login_form = None
    
    # If form identifier specified, try to find it
    if form_identifier:
        if form_identifier.startswith('#'):
            login_form = soup.select_one(form_identifier)
        else:
            login_form = soup.find('form', id=form_identifier)
            if not login_form:
                login_form = soup.find('form', class_=form_identifier)
    
    # If not found, try auto-detection
    if not login_form:
        # Look for forms with password fields
        password_fields = soup.find_all('input', {'type': 'password'})
        for password_field in password_fields:
            # Find the parent form
            parent_form = password_field.find_parent('form')
            if parent_form:
                login_form = parent_form
                break
    
    # Still couldn't find login form
    if not login_form:
        results["form_found"] = False
        results["error"] = "Could not detect a login form on the page"
        return results
    
    # We found a form
    results["form_found"] = True
    
    # Extract form details
    form_action = login_form.get('action', '')
    form_method = login_form.get('method', 'post').lower()
    
    # If action is relative, make it absolute
    if form_action and not form_action.startswith(('http://', 'https://')):
        form_action = urljoin(url, form_action)
    elif not form_action:
        form_action = url
    
    results["form_details"] = {
        "action": form_action,
        "method": form_method,
    }
    
    # Find username and password fields
    username_field = None
    password_field = None
    
    # Common username field names
    username_field_names = ['username', 'user', 'email', 'login', 'id', 'userid']
    
    # Look for password field
    password_field = login_form.find('input', {'type': 'password'})
    if not password_field:
        results["error"] = "No password field found in the form"
        return results
    
    # Try to find username field
    # First check for text/email inputs
    input_fields = login_form.find_all('input', {'type': ['text', 'email']})
    
    for field in input_fields:
        field_name = field.get('name', '').lower()
        field_id = field.get('id', '').lower()
        
        # Check if field name or id contains common username identifiers
        for username_identifier in username_field_names:
            if username_identifier in field_name or username_identifier in field_id:
                username_field = field
                break
                
        if username_field:
            break
    
    # If still not found, just take the first text/email input
    if not username_field and input_fields:
        username_field = input_fields[0]
    
    # If still no username field
    if not username_field:
        results["error"] = "Could not identify username field in the form"
        return results
    
    # Extract field names
    username_field_name = username_field.get('name', '')
    password_field_name = password_field.get('name', '')
    
    results["form_details"]["username_field"] = username_field_name
    results["form_details"]["password_field"] = password_field_name
    
    # Find other form fields that might be required
    other_fields = {}
    for input_field in login_form.find_all('input'):
        if input_field != username_field and input_field != password_field:
            field_type = input_field.get('type', '').lower()
            if field_type not in ['submit', 'button', 'reset']:
                field_name = input_field.get('name', '')
                field_value = input_field.get('value', '')
                if field_name:
                    other_fields[field_name] = field_value
    
    results["form_details"]["other_fields"] = other_fields
    
    # Begin testing (limited to max_attempts)
    attempt_count = 0
    
    # Iterate through username/password combinations
    for username in usernames:
        for password in passwords:
            # Stop if reached max attempts
            if attempt_count >= max_attempts:
                break
                
            attempt_count += 1
            
            # Attempt details
            attempt = {
                "username": username,
                "password": password,
                "response_code": None,
                "response_size": None,
                "time_taken": None
            }
            
            # Prepare form data
            form_data = {
                username_field_name: username,
                password_field_name: password,
                **other_fields
            }
            
            # Delay between attempts
            if attempt_count > 1:
                time.sleep(delay)
            
            try:
                start_time = time.time()
                
                # Submit the form
                if form_method == 'post':
                    login_response = requests.post(form_action, data=form_data, allow_redirects=True)
                else:
                    login_response = requests.get(form_action, params=form_data, allow_redirects=True)
                
                end_time = time.time()
                
                # Record response details
                attempt["response_code"] = login_response.status_code
                attempt["response_size"] = len(login_response.text)
                attempt["time_taken"] = round(end_time - start_time, 3)
                
                # Check for indicators of successful login
                success_indicators = [
                    "logout" in login_response.text.lower(),
                    "welcome" in login_response.text.lower(),
                    "profile" in login_response.text.lower(),
                    "dashboard" in login_response.text.lower(),
                    "account" in login_response.text.lower() and "login" not in login_response.text.lower()
                ]
                
                # Check for protection mechanisms
                protection_indicators = [
                    login_response.status_code == 429,  # Too Many Requests
                    "captcha" in login_response.text.lower(),
                    "recaptcha" in login_response.text.lower(),
                    "too many attempts" in login_response.text.lower(),
                    "rate limit" in login_response.text.lower(),
                    "blocked" in login_response.text.lower(),
                    "temporary lock" in login_response.text.lower()
                ]
                
                # Check for protection
                for indicator, present in enumerate(protection_indicators):
                    if present:
                        protection_type = [
                            "Rate limiting (429 status code)",
                            "CAPTCHA protection",
                            "reCAPTCHA protection",
                            "Attempt limiting",
                            "Rate limiting message",
                            "IP blocking",
                            "Account locking"
                        ][indicator]
                        
                        if protection_type not in results["protection_details"]:
                            results["protection_details"].append(protection_type)
                            results["protection_detected"] = True
                
                # Check if login successful based on indicators
                login_successful = any(success_indicators)
                
                if login_successful:
                    attempt["success"] = True
                    results["successful_login"] = True
                    results["successful_credentials"] = {
                        "username": username,
                        "password": password
                    }
                else:
                    attempt["success"] = False
                
                # Add attempt to results
                results["attempts"].append(attempt)
                
                # If login successful, stop testing
                if login_successful:
                    print_warning(f"Found possible valid credentials: {username}/{password}")
                    break
            
            except Exception as e:
                attempt["error"] = str(e)
                results["attempts"].append(attempt)
        
        # Break outer loop if hit max attempts or successful login
        if attempt_count >= max_attempts or results["successful_login"]:
            break
    
    # Update total attempts
    results["total_attempts"] = attempt_count
    
    # Security assessment
    assessment = []
    
    if results["successful_login"]:
        assessment.append("CRITICAL: Login was possible with common credentials")
    
    if not results["protection_detected"]:
        assessment.append("HIGH RISK: No protection mechanisms detected against brute force")
    else:
        assessment.append(f"PROTECTION DETECTED: {', '.join(results['protection_details'])}")
    
    # If we found valid credentials
    if results["successful_login"]:
        # Add recommendation to change default/weak passwords
        assessment.append(f"RECOMMENDATION: Change default/weak credentials immediately")
    
    results["security_assessment"] = assessment
    
    return results


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("Operation cancelled by user", "INTERRUPT")
    except Exception as e:
        print_error(f"An unexpected error occurred: {str(e)}")
