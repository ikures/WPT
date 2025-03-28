#!/usr/bin/env python3
"""
CLIKE - Command Line URL Penetration Testing Tool
A colorful command-line URL penetration testing tool with ASCII art logo, 
timestamps, and comprehensive help functionality.
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
import trafilatura

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
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 10
LITE_MODE = False


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
    
    with ThreadPoolExecutor(max_workers=5) as executor:
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
    
    if LITE_MODE:
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
    
    with ThreadPoolExecutor(max_workers=5) as executor:
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
    """Export main text content from the URL"""
    try:
        downloaded = trafilatura.fetch_url(url)
        text = trafilatura.extract(downloaded)
        return text or "No text content could be extracted"
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


def process_url(url: str, args) -> None:
    """Process a single URL with the given arguments"""
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


def print_help() -> None:
    """Print help message"""
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
    -all, --all       Run all checks

{Fore.GREEN}EXPORT OPTIONS:{Style.RESET_ALL}
    -e, --export-results  Export results to a file
    --format              Format to export results (json, csv, txt)
    -o, --output-file     Name of the output file

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
"""
    print(help_text)


def process_url_with_results(url: str, args) -> Dict[str, Any]:
    """
    Process URL with all specified checks and return results as a dictionary
    
    This version is similar to process_url but instead of just displaying results,
    it collects them in a dictionary to be returned for export
    """
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
            
        # Export results if requested
        if args.export_results and all_results:
            export_format = args.format or 'json'
            export_results(all_results, export_format, args.output_file)
            
    except Exception as e:
        print_error(f"Error processing batch file: {str(e)}")


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
    urls = []
    while True:
        user_input = input().strip()
        if not user_input:
            break
        urls.append(user_input)
    
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
    if args.export_results and all_results:
        export_format = args.format or 'json'
        export_results(all_results, export_format, args.output_file)


def main():
    """Main function"""
    global LITE_MODE
    
    # Create argument parser
    parser = argparse.ArgumentParser(add_help=False, description='CLIKE URL Penetration Testing Tool')
    
    # Basic options
    parser.add_argument('-u', '--url', help='URL of website to analyze')
    parser.add_argument('-b', '--batch', help='Process multiple URLs from a file (one URL per line)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode - enter URLs manually')
    parser.add_argument('-h', '--help', action='store_true', help='Display help message')
    parser.add_argument('--lite', action='store_true', help='Low resource mode')
    parser.add_argument('-all', '--all', action='store_true', help='Run all checks')
    
    # Export options
    parser.add_argument('-e', '--export-results', action='store_true', help='Export results to a file')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json', 
                        help='Format to export results (json, csv, txt)')
    parser.add_argument('-o', '--output-file', help='Name of the output file')
    
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
    if LITE_MODE:
        print_warning("Lite mode enabled, some operations will be limited")
    
    # Process batch of URLs if provided
    if args.batch:
        process_batch(args.batch, args)
        return
        
    # Interactive mode - get URLs from user input
    if args.interactive:
        process_input_urls(args)
        return
    
    # Process single URL
    if args.export_results:
        results = process_url_with_results(args.url, args)
        # Export results for single URL
        all_results = {args.url: results}
        export_format = args.format or 'json'
        export_results(all_results, export_format, args.output_file)
    else:
        process_url(args.url, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("Operation cancelled by user", "INTERRUPT")
    except Exception as e:
        print_error(f"An unexpected error occurred: {str(e)}")
