#!/usr/bin/env python3
"""
ReconIKE - A Python-based command-line utility for website reconnaissance and information gathering
Termux Optimized Version
"""

import sys
import time
import logging
import re
from datetime import datetime

# Lazy imports - only load when needed to reduce startup time and memory usage
IMPORTS = {
    'requests': None,
    'socket': None,
    'urlparse': None,
    'BeautifulSoup': None,
    'ssl': None
}

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)

# Constants
USER_AGENT = 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36'
TIMEOUT = 8  # seconds - reduced for mobile
MAX_LINKS_TO_SHOW = 10  # Reduced for smaller screens
MAX_REDIRECTS = 5  # Limit redirects for mobile data conservation

def lazy_import(module_name):
    """Lazy import modules only when needed"""
    global IMPORTS
    if module_name == 'urlparse':
        if not IMPORTS[module_name]:
            from urllib.parse import urlparse
            IMPORTS[module_name] = urlparse
        return IMPORTS[module_name]
    elif module_name == 'BeautifulSoup':
        if not IMPORTS[module_name]:
            from bs4 import BeautifulSoup
            IMPORTS[module_name] = BeautifulSoup
        return IMPORTS[module_name]
    elif not IMPORTS[module_name]:
        IMPORTS[module_name] = __import__(module_name)
    return IMPORTS[module_name]

def display_banner():
    """Display the tool's banner"""
    banner = r"""
/,_,| IKE |
|   |======
|'._| [Termux]
"""
    print(banner)

def log_action(action):
    """Log an action with a timestamp"""
    current_time = datetime.now().strftime("%H:%M:%S")
    print(f"[{current_time}] {action}")

def display_help():
    """Display the help message with available commands"""
    help_text = """
Available Commands:
-u : URL of website
-d : DNS info
-r : URL redirects
-f : Forms on page
-n : Network info
-m : Meta tags
-c : Cookies
-s : HTTPS security
-t : Page title
-i : Count images
-l : Count links
-x : External links
-v : URL availability
-w : Word count
-j : JavaScript tags
-css : CSS resources
-sm : Sitemap check
-robots : Robots.txt
-vid : Count videos
-broken : Broken links
-mobile : Mobile support
-h1 : Header tags
-lang : Page language
-export : Export text
-sql : SQL leak check
-all : Run all checks
-h : Help message
-lite : Low resource mode

Examples:
python reconike_termux.py -u https://example.com -t -d
python reconike_termux.py -u https://example.com -all -lite
"""
    print(help_text)

def get_session():
    """Create and return a requests session with default headers"""
    requests = lazy_import('requests')
    session = requests.Session()
    session.headers.update({
        'User-Agent': USER_AGENT
    })
    return session

def get_soup(url, lite_mode=False):
    """Get BeautifulSoup object from a URL"""
    try:
        requests = lazy_import('requests')
        BeautifulSoup = lazy_import('BeautifulSoup')
        
        session = get_session()
        response = session.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        
        # Use html.parser instead of lxml for better Termux compatibility and lower resource usage
        parser = 'html.parser'
        return BeautifulSoup(response.text, parser)
    except requests.RequestException as e:
        logging.error(f"Failed to get HTML content: {e}")
        return None

def get_dns_info(url, lite_mode=False):
    """Get DNS information for a URL"""
    log_action("Getting DNS info")
    socket = lazy_import('socket')
    urlparse = lazy_import('urlparse')
    
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Get IP address
        ip_address = socket.gethostbyname(hostname)
        print(f"Host: {hostname}")
        print(f"IP: {ip_address}")
        
        # Get additional DNS information if not in lite mode
        if not lite_mode:
            try:
                # Get reverse DNS (PTR record)
                reverse_dns = socket.gethostbyaddr(ip_address)[0]
                print(f"Reverse DNS: {reverse_dns}")
            except socket.herror:
                print("Reverse DNS: Not available")
                
    except socket.gaierror as e:
        print(f"DNS Error: {e}")
    except Exception as e:
        print(f"Error: {e}")

def get_redirects(url, lite_mode=False):
    """Track URL redirects"""
    log_action("Tracking redirects")
    requests = lazy_import('requests')
    
    try:
        session = get_session()
        # Note: max_redirects is not a standard parameter for requests.get
        # Instead, we'll adjust the timeout for lite mode
        response = session.get(url, allow_redirects=True, 
                              timeout=TIMEOUT/2 if lite_mode else TIMEOUT)
        
        if response.history:
            print(f"Redirects: {len(response.history)}")
            for i, resp in enumerate(response.history):
                print(f"  {i+1}. {resp.url} -> {resp.status_code}")
            print(f"Final: {response.url}")
        else:
            print("No redirects found")
            
    except requests.RequestException as e:
        print(f"Error: {e}")

def get_forms(url, lite_mode=False):
    """Get forms from a webpage"""
    log_action("Getting forms")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        forms = soup.find_all('form')
        if forms:
            print(f"Forms: {len(forms)}")
            # Limit form display in lite mode
            display_forms = forms[:2] if lite_mode else forms
            
            for i, form in enumerate(display_forms, 1):
                action = form.get('action', 'Not specified')
                method = form.get('method', 'GET').upper()
                print(f"\nForm #{i}:")
                print(f"  Action: {action}")
                print(f"  Method: {method}")
                
                if not lite_mode:
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    if inputs:
                        print(f"  Fields: {len(inputs)}")
                        for input_field in inputs[:5]:  # Limit to first 5 fields
                            field_type = input_field.get('type', 'text' if input_field.name == 'input' else input_field.name)
                            field_name = input_field.get('name', 'No name')
                            print(f"    - {field_name} ({field_type})")
            
            if lite_mode and len(forms) > 2:
                print(f"  ... and {len(forms) - 2} more")
        else:
            print("No forms found")
            
    except Exception as e:
        print(f"Error: {e}")

def get_networking_info(url, lite_mode=False):
    """Get networking information"""
    log_action("Getting network info")
    socket = lazy_import('socket')
    urlparse = lazy_import('urlparse')
    requests = lazy_import('requests')
    
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Get basic socket information
        try:
            ip_address = socket.gethostbyname(hostname)
            print(f"Host: {hostname}")
            print(f"IP: {ip_address}")
            
            # Skip detailed info in lite mode
            if lite_mode:
                return
                
            # Get server information
            try:
                session = get_session()
                response = session.get(url, timeout=TIMEOUT)
                server = response.headers.get('Server', 'Not disclosed')
                print(f"\nServer: {server}")
                print("\nResponse Headers:")
                for header, value in response.headers.items():
                    print(f"  {header}: {value}")
            except requests.RequestException as e:
                print(f"Server info error: {e}")
                
        except socket.gaierror as e:
            print(f"DNS Error: {e}")
            
    except Exception as e:
        print(f"Error: {e}")

def get_meta_tags(url, lite_mode=False):
    """Get meta tags from a webpage"""
    log_action("Getting meta tags")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        meta_tags = soup.find_all('meta')
        if meta_tags:
            print(f"Meta tags: {len(meta_tags)}")
            
            # Display fewer tags in lite mode
            display_tags = meta_tags[:5] if lite_mode else meta_tags[:10]
            
            for i, tag in enumerate(display_tags, 1):
                name = tag.get('name', tag.get('property', 'No name'))
                content = tag.get('content', 'No content')
                # Truncate content for display
                if len(content) > 50:
                    content = content[:47] + "..."
                print(f"  {i}. {name}: {content}")
                
            remaining = len(meta_tags) - len(display_tags)
            if remaining > 0:
                print(f"  ... and {remaining} more")
        else:
            print("No meta tags found")
            
    except Exception as e:
        print(f"Error: {e}")

def get_cookies(url, lite_mode=False):
    """Get cookies from a webpage response"""
    log_action("Getting cookies")
    requests = lazy_import('requests')
    
    try:
        session = get_session()
        response = session.get(url, timeout=TIMEOUT)
        
        if response.cookies:
            print(f"Cookies: {len(response.cookies)}")
            
            # Display fewer cookies in lite mode
            display_cookies = list(response.cookies)[:3] if lite_mode else response.cookies
            
            for i, cookie in enumerate(display_cookies, 1):
                print(f"\nCookie #{i}:")
                print(f"  Name: {cookie.name}")
                # Truncate value
                if cookie.value and len(cookie.value) > 20:
                    value_display = cookie.value[:17] + "..."
                else:
                    value_display = cookie.value
                print(f"  Value: {value_display}")
                print(f"  Domain: {cookie.domain}")
                print(f"  Secure: {cookie.secure}")
                
            if lite_mode and len(response.cookies) > 3:
                print(f"  ... and {len(response.cookies) - 3} more")
        else:
            print("No cookies found")
            
    except requests.RequestException as e:
        print(f"Error: {e}")

def check_https_security(url, lite_mode=False):
    """Check HTTPS security status"""
    log_action("Checking HTTPS security")
    ssl = lazy_import('ssl')
    socket = lazy_import('socket')
    urlparse = lazy_import('urlparse')
    
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        if parsed_url.scheme != 'https':
            print("Warning: Not using HTTPS")
            return
            
        try:
            # Create an SSL context
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificate details
                    print("SSL/TLS Certificate:")
                    
                    # Subject
                    if 'subject' in cert and cert['subject']:
                        subject = dict(x[0] for x in cert['subject'])
                        print("  Subject:")
                        if 'commonName' in subject:
                            print(f"    CN: {subject['commonName']}")
                        if not lite_mode and 'organizationName' in subject:
                            print(f"    Org: {subject['organizationName']}")
                    
                    # Skip detailed issuer in lite mode
                    if not lite_mode:
                        # Issuer
                        if 'issuer' in cert and cert['issuer']:
                            issuer = dict(x[0] for x in cert['issuer'])
                            print("  Issuer:")
                            if 'commonName' in issuer:
                                print(f"    CN: {issuer['commonName']}")
                    
                    # Validity - always show
                    if 'notBefore' in cert and 'notAfter' in cert:
                        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        print("  Validity:")
                        print(f"    Not After: {not_after.strftime('%Y-%m-%d')}")
                        
                        # Check if certificate is valid
                        now = datetime.now()
                        if now < not_before:
                            print("  Status: Not yet valid")
                        elif now > not_after:
                            print("  Status: Expired")
                        else:
                            print("  Status: Valid")
                    
                    # Protocol and cipher
                    print(f"  Protocol: {ssock.version()}")
                    print(f"  Cipher: {ssock.cipher()[0]}")
                    
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")
        except socket.error as e:
            print(f"Socket Error: {e}")
            
    except Exception as e:
        print(f"Error: {e}")

def get_title(url, lite_mode=False):
    """Get the title of a webpage"""
    log_action("Getting page title")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        title = soup.title.string if soup.title else "No title found"
        print(f"Title: {title}")
            
    except Exception as e:
        print(f"Error: {e}")

def count_images(url, lite_mode=False):
    """Count the images on a webpage"""
    log_action("Counting images")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        images = soup.find_all('img')
        print(f"Images: {len(images)}")
        
        # Skip detailed listing in lite mode
        if not lite_mode and images:
            # Get details about first few images
            print("\nSample images:")
            for i, img in enumerate(images[:3], 1):
                src = img.get('src', 'No source')
                if len(src) > 40:  # Truncate long URLs
                    src = src[:37] + "..."
                alt = img.get('alt', 'No alt')
                print(f"  {i}. {src}")
                print(f"     Alt: {alt[:30] if len(alt) > 30 else alt}")
                
    except Exception as e:
        print(f"Error: {e}")

def count_links(url, lite_mode=False):
    """Count the hyperlinks on a webpage"""
    log_action("Counting hyperlinks")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        links = soup.find_all('a')
        print(f"Links: {len(links)}")
            
    except Exception as e:
        print(f"Error: {e}")

def get_external_links(url, lite_mode=False):
    """Get external links from a webpage"""
    log_action("Getting external links")
    urlparse = lazy_import('urlparse')
    
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        links = soup.find_all('a', href=True)
        external_links = []
        
        for link in links:
            href = link['href']
            if href.startswith('http'):
                link_domain = urlparse(href).netloc
                if link_domain and link_domain != domain:
                    external_links.append(href)
        
        if external_links:
            print(f"External links: {len(external_links)}")
            # Display fewer links in lite mode
            display_limit = 3 if lite_mode else MAX_LINKS_TO_SHOW
            
            for i, link in enumerate(external_links[:display_limit], 1):
                # Truncate long URLs
                if len(link) > 50:
                    link_display = link[:47] + "..."
                else:
                    link_display = link
                print(f"  {i}. {link_display}")
            
            remaining = len(external_links) - display_limit
            if remaining > 0:
                print(f"  ... and {remaining} more")
        else:
            print("No external links found")
            
    except Exception as e:
        print(f"Error: {e}")

def verify_url(url, lite_mode=False):
    """Verify the availability of a URL"""
    log_action("Verifying URL availability")
    requests = lazy_import('requests')
    
    try:
        session = get_session()
        start_time = time.time()
        response = session.get(url, timeout=TIMEOUT)
        end_time = time.time()
        
        response_time = round((end_time - start_time) * 1000)  # ms
        
        print(f"URL: {url}")
        print(f"Status: {response.status_code} {response.reason}")
        print(f"Response Time: {response_time} ms")
            
    except requests.RequestException as e:
        print(f"Error: {e}")

def count_words(url, lite_mode=False):
    """Count the number of words on a webpage"""
    log_action("Counting words")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Get all text content
        text = soup.get_text(separator=' ', strip=True)
        
        # Count words (simple estimation)
        words = text.split()
        print(f"Word count: ~{len(words)}")
            
    except Exception as e:
        print(f"Error: {e}")

def count_javascript(url, lite_mode=False):
    """Count the number of <script> tags on a webpage"""
    log_action("Counting JavaScript tags")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Find all script tags
        scripts = soup.find_all('script')
        
        # Count external vs inline scripts
        external_scripts = [s for s in scripts if s.get('src')]
        inline_scripts = [s for s in scripts if not s.get('src')]
        
        print(f"Script tags: {len(scripts)}")
        print(f"  External: {len(external_scripts)}")
        print(f"  Inline: {len(inline_scripts)}")
            
    except Exception as e:
        print(f"Error: {e}")

def count_css_styles(url, lite_mode=False):
    """Count the number of CSS stylesheets and <style> tags"""
    log_action("Counting CSS resources")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Find external stylesheets
        stylesheets = soup.find_all('link', rel='stylesheet')
        
        # Find style tags
        style_tags = soup.find_all('style')
        
        # Find inline styles
        inline_styles = soup.find_all(style=True)
        
        print("CSS Resources:")
        print(f"  Stylesheets: {len(stylesheets)}")
        print(f"  Style tags: {len(style_tags)}")
        print(f"  Inline styles: {len(inline_styles)}")
            
    except Exception as e:
        print(f"Error: {e}")

def check_sitemap(url, lite_mode=False):
    """Check for a sitemap.xml file"""
    log_action("Checking for sitemap.xml")
    requests = lazy_import('requests')
    urlparse = lazy_import('urlparse')
    
    try:
        parsed_url = urlparse(url)
        sitemap_url = f"{parsed_url.scheme}://{parsed_url.netloc}/sitemap.xml"
        
        session = get_session()
        response = session.get(sitemap_url, timeout=TIMEOUT)
        
        if response.status_code == 200:
            print(f"Sitemap found at {sitemap_url}")
            
            # Skip detailed analysis in lite mode
            if lite_mode:
                return
                
            # Check if it's valid XML
            try:
                BeautifulSoup = lazy_import('BeautifulSoup')
                soup = BeautifulSoup(response.text, 'html.parser')
                urls = soup.find_all('loc')
                
                if urls:
                    print(f"  Contains {len(urls)} URLs")
                    # Show sample URLs
                    for i, url_tag in enumerate(urls[:3], 1):
                        print(f"  {i}. {url_tag.text}")
                    if len(urls) > 3:
                        print(f"  ... and {len(urls) - 3} more")
            except Exception as e:
                print(f"  Error parsing sitemap: {e}")
        else:
            print(f"No sitemap found at {sitemap_url} (Status: {response.status_code})")
            
    except requests.RequestException as e:
        print(f"Error checking sitemap: {e}")

def check_robots(url, lite_mode=False):
    """Check for a robots.txt file"""
    log_action("Checking for robots.txt")
    requests = lazy_import('requests')
    urlparse = lazy_import('urlparse')
    
    try:
        parsed_url = urlparse(url)
        robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
        
        session = get_session()
        response = session.get(robots_url, timeout=TIMEOUT)
        
        if response.status_code == 200:
            print(f"Robots.txt found at {robots_url}")
            
            # Skip detailed analysis in lite mode
            if not lite_mode:
                # Look for disallowed entries
                disallowed = re.findall(r'Disallow:\s*(.+)', response.text)
                if disallowed:
                    print(f"  Contains {len(disallowed)} disallowed entries")
                    # Show sample disallowed entries
                    for i, entry in enumerate(disallowed[:5], 1):
                        print(f"  {i}. Disallow: {entry}")
                    if len(disallowed) > 5:
                        print(f"  ... and {len(disallowed) - 5} more")
                
                # Look for allowed entries
                allowed = re.findall(r'Allow:\s*(.+)', response.text)
                if allowed:
                    print(f"  Contains {len(allowed)} allowed entries")
        else:
            print(f"No robots.txt found at {robots_url} (Status: {response.status_code})")
            
    except requests.RequestException as e:
        print(f"Error checking robots.txt: {e}")

def count_videos(url, lite_mode=False):
    """Count the number of videos on a webpage"""
    log_action("Counting videos")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Find video tags
        video_tags = soup.find_all('video')
        
        # Find iframe tags with video services
        video_iframes = []
        iframes = soup.find_all('iframe')
        video_services = ['youtube.com', 'vimeo.com', 'dailymotion.com', 'player.']
        
        for iframe in iframes:
            src = iframe.get('src', '')
            if any(service in src for service in video_services):
                video_iframes.append(iframe)
        
        # Count total videos
        total_videos = len(video_tags) + len(video_iframes)
        
        print(f"Videos: {total_videos}")
        print(f"  Video tags: {len(video_tags)}")
        print(f"  Video iframes: {len(video_iframes)}")
            
    except Exception as e:
        print(f"Error counting videos: {e}")

def find_broken_links(url, lite_mode=False):
    """Find broken links on a webpage"""
    log_action("Finding broken links")
    requests = lazy_import('requests')
    
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Get all links
        links = soup.find_all('a', href=True)
        
        if not links:
            print("No links found on the webpage")
            return
            
        print(f"Checking {len(links)} links for availability")
        
        # Use fewer links in lite mode to save resources
        check_limit = 5 if lite_mode else 20
        links_to_check = links[:check_limit]
        
        if len(links) > check_limit:
            print(f"(Limited to first {check_limit} links in {'lite' if lite_mode else 'standard'} mode)")
            
        broken_links = []
        
        session = get_session()
        for link in links_to_check:
            href = link['href']
            
            # Skip anchor links
            if href.startswith('#'):
                continue
                
            # Handle relative URLs
            if not href.startswith(('http://', 'https://')):
                # Create absolute URL
                urlparse = lazy_import('urlparse')
                parsed_url = urlparse(url)
                base = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                if href.startswith('/'):
                    href = f"{base}{href}"
                else:
                    href = f"{base}/{href}"
            
            try:
                # Use HEAD request to save bandwidth
                response = session.head(href, timeout=TIMEOUT/2)
                if response.status_code >= 400:
                    broken_links.append((href, response.status_code))
            except requests.RequestException:
                broken_links.append((href, "Connection Error"))
        
        if broken_links:
            print(f"Found {len(broken_links)} broken link(s):")
            for link, status in broken_links:
                print(f"  {link} - Status: {status}")
        else:
            print(f"No broken links found among the {len(links_to_check)} checked links")
            
    except Exception as e:
        print(f"Error finding broken links: {e}")

def check_mobile_compatibility(url, lite_mode=False):
    """Check for mobile compatibility indicators"""
    log_action("Checking mobile compatibility")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Check for viewport meta tag
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        
        # Check for media queries in style tags
        media_queries = False
        for style in soup.find_all('style'):
            if style.string and '@media' in style.string:
                media_queries = True
                break
        
        # Check for responsive frameworks
        frameworks = []
        for link in soup.find_all('link', rel='stylesheet'):
            href = link.get('href', '').lower()
            if 'bootstrap' in href:
                frameworks.append('Bootstrap')
            elif 'foundation' in href:
                frameworks.append('Foundation')
        
        # Results
        print("Mobile Compatibility Indicators:")
        
        if viewport:
            viewport_content = viewport.get('content', '')
            print(f"  Viewport meta tag: Yes")
            if 'width=device-width' in viewport_content:
                print(f"  Responsive viewport: Yes")
            else:
                print(f"  Responsive viewport: No")
        else:
            print(f"  Viewport meta tag: No")
        
        print(f"  Media queries: {'Yes' if media_queries else 'No'}")
        
        if frameworks:
            print(f"  Responsive frameworks: {', '.join(frameworks)}")
        else:
            print(f"  Responsive frameworks: None detected")
            
    except Exception as e:
        print(f"Error checking mobile compatibility: {e}")

def get_headers(url, lite_mode=False):
    """Get header tags from a webpage"""
    log_action("Getting header tags")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        headers = {}
        
        for i in range(1, 7):
            headers[f'h{i}'] = soup.find_all(f'h{i}')
        
        print("Header Tags:")
        for tag, elements in headers.items():
            if elements:
                print(f"  {tag}: {len(elements)}")
                
                # Skip listing headers in lite mode
                if not lite_mode:
                    # Show sample headers
                    for i, header in enumerate(elements[:2], 1):
                        text = header.get_text(strip=True)
                        # Truncate long text
                        if len(text) > 40:
                            text = text[:37] + "..."
                        print(f"    {i}. {text}")
                    if len(elements) > 2:
                        print(f"    ... and {len(elements) - 2} more")
            
    except Exception as e:
        print(f"Error getting header tags: {e}")

def detect_language(url, lite_mode=False):
    """Detect the language of a webpage"""
    log_action("Detecting language")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Method 1: Check the lang attribute of html tag
        html_tag = soup.find('html')
        if html_tag and html_tag.get('lang'):
            print(f"Language (from HTML tag): {html_tag['lang']}")
            return
            
        # Method 2: Check for language meta tags
        meta_lang = soup.find('meta', attrs={'http-equiv': 'content-language'})
        if meta_lang and meta_lang.get('content'):
            print(f"Language (from meta tag): {meta_lang['content']}")
            return
            
        # Method 3: Simple heuristic based on common words
        # This is very basic and won't work for many languages
        text = soup.get_text(separator=' ', strip=True)
        words = text.lower().split()
        
        # Simple language detection based on common words
        en_words = ['the', 'and', 'to', 'of', 'in']
        es_words = ['el', 'la', 'en', 'y', 'de']
        fr_words = ['le', 'la', 'et', 'de', 'en']
        
        en_count = sum(1 for word in words if word in en_words)
        es_count = sum(1 for word in words if word in es_words)
        fr_count = sum(1 for word in words if word in fr_words)
        
        if en_count > es_count and en_count > fr_count:
            print("Language (best guess): English")
        elif es_count > en_count and es_count > fr_count:
            print("Language (best guess): Spanish")
        elif fr_count > en_count and fr_count > es_count:
            print("Language (best guess): French")
        else:
            print("Language: Could not determine")
            
    except Exception as e:
        print(f"Error detecting language: {e}")

def export_all_text(url, lite_mode=False):
    """Export all text from the webpage"""
    log_action("Exporting text")
    try:
        soup = get_soup(url, lite_mode)
        if not soup:
            return
            
        # Get all text content
        text = soup.get_text(separator='\n', strip=True)
        
        # In lite mode, just show a preview
        if lite_mode:
            print("Text preview (first 200 chars):")
            print(text[:200] + "..." if len(text) > 200 else text)
            print(f"Total length: {len(text)} characters")
            return
        
        # Generate filename
        urlparse = lazy_import('urlparse')
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace('.', '_')
        filename = f"{domain}_text.txt"
        
        # Save to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(text)
            
        print(f"Text exported to {filename}")
        print(f"Total length: {len(text)} characters")
            
    except Exception as e:
        print(f"Error exporting text: {e}")

def check_sql_databases(url, lite_mode=False):
    """Check for potential SQL database leaks"""
    log_action("Checking for SQL database leaks")
    requests = lazy_import('requests')
    
    try:
        session = get_session()
        response = session.get(url, timeout=TIMEOUT)
        
        # Check for common SQL error messages
        sql_errors = [
            'SQL syntax', 'mysql error', 'ORA-', 'sql server',
            'JET Database', 'mysql_fetch_array', 'ODBC',
            'postgres.', 'sqlstate', 'mysql_num_rows', 'Error Occurred'
        ]
        
        found_errors = []
        for error in sql_errors:
            if error.lower() in response.text.lower():
                found_errors.append(error)
        
        if found_errors:
            print("Warning: Potential SQL error messages detected:")
            for error in found_errors:
                print(f"  - {error}")
        else:
            print("No SQL error messages detected")
            
    except requests.RequestException as e:
        print(f"Error checking SQL leaks: {e}")

def run_all_checks(url, lite_mode=False):
    """Run all reconnaissance options"""
    log_action("Running all reconnaissance options")
    print(f"Target URL: {url}")
    print(f"Mode: {'Lite (resource-saving)' if lite_mode else 'Standard'}")
    print("-" * 40)
    
    # Basic information
    get_title(url, lite_mode)
    print("-" * 40)
    
    verify_url(url, lite_mode)
    print("-" * 40)
    
    get_dns_info(url, lite_mode)
    print("-" * 40)
    
    get_redirects(url, lite_mode)
    print("-" * 40)
    
    # Security checks
    check_https_security(url, lite_mode)
    print("-" * 40)
    
    get_cookies(url, lite_mode)
    print("-" * 40)
    
    check_robots(url, lite_mode)
    print("-" * 40)
    
    check_sitemap(url, lite_mode)
    print("-" * 40)
    
    check_sql_databases(url, lite_mode)
    print("-" * 40)
    
    # Content analysis
    count_words(url, lite_mode)
    print("-" * 40)
    
    count_images(url, lite_mode)
    print("-" * 40)
    
    count_videos(url, lite_mode)
    print("-" * 40)
    
    count_links(url, lite_mode)
    print("-" * 40)
    
    get_external_links(url, lite_mode)
    print("-" * 40)
    
    # Structure analysis
    get_forms(url, lite_mode)
    print("-" * 40)
    
    get_meta_tags(url, lite_mode)
    print("-" * 40)
    
    get_headers(url, lite_mode)
    print("-" * 40)
    
    check_mobile_compatibility(url, lite_mode)
    print("-" * 40)
    
    detect_language(url, lite_mode)
    print("-" * 40)
    
    # Skip these in lite mode to save resources
    if not lite_mode:
        count_javascript(url, lite_mode)
        print("-" * 40)
        
        count_css_styles(url, lite_mode)
        print("-" * 40)
        
        get_networking_info(url, lite_mode)
        print("-" * 40)
        
        find_broken_links(url, lite_mode)
        print("-" * 40)
    
    print("All reconnaissance checks completed!")

def main():
    """Main function to parse arguments and run commands"""
    display_banner()  # Show banner at the start
    
    if len(sys.argv) < 2:
        display_help()
        return

    url = None
    lite_mode = False
    
    commands = {
        '-d': get_dns_info,
        '-r': get_redirects,
        '-f': get_forms,
        '-n': get_networking_info,
        '-m': get_meta_tags,
        '-c': get_cookies,
        '-s': check_https_security,
        '-t': get_title,
        '-i': count_images,
        '-l': count_links,
        '-x': get_external_links,
        '-v': verify_url,
        '-w': count_words,
        '-j': count_javascript,
        '-css': count_css_styles,
        '-sm': check_sitemap,
        '-robots': check_robots,
        '-vid': count_videos,
        '-broken': find_broken_links,
        '-mobile': check_mobile_compatibility,
        '-h1': get_headers,
        '-lang': detect_language,
        '-export': export_all_text,
        '-sql': check_sql_databases,
        '-all': run_all_checks,
        '-h': display_help
    }

    # First check for lite mode
    if '-lite' in sys.argv:
        lite_mode = True
        print("[Lite mode enabled - reduced resource usage]")

    # Process arguments
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == '-u' and i + 1 < len(sys.argv):
            url = sys.argv[i + 1]
        elif sys.argv[i] in commands and sys.argv[i] != '-h':
            if url:
                commands[sys.argv[i]](url, lite_mode)
            else:
                print("Error: URL must be specified with -u command.")
                display_help()
                return
        elif sys.argv[i] == '-h':
            display_help()

if __name__ == "__main__":
    main()
