import asyncio
from playwright.async_api import async_playwright
from urllib.parse import urlparse
from datetime import datetime, timedelta
import logging
import os
import glob

class CookieAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.browser_path = self._find_browser_executable()
    
    def _find_browser_executable(self):
        """Find the Chromium browser executable path"""
        # Common paths where Playwright installs browsers
        possible_paths = [
            '/home/runner/workspace/.cache/ms-playwright/*/chrome-linux/chrome',
            '~/.cache/ms-playwright/*/chrome-linux/chrome',
            '/home/runner/.cache/ms-playwright/*/chrome-linux/chrome'
        ]
        
        for pattern in possible_paths:
            expanded_pattern = os.path.expanduser(pattern)
            matches = glob.glob(expanded_pattern)
            if matches:
                # Return the most recent version (highest version number)
                return sorted(matches)[-1]
        
        return None  # Let Playwright use default

    def analyze_website(self, url):
        """
        Analyze cookies for a given website URL
        Returns a dictionary with analysis results
        """
        try:
            return asyncio.run(self._analyze_async(url))
        except Exception as e:
            self.logger.error(f"Error in analyze_website: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'cookies': [],
                'summary': {},
                'recommendations': []
            }

    async def _analyze_async(self, url):
        """Async method to analyze website cookies using Playwright"""
        async with async_playwright() as p:
            browser = None
            try:
                # Launch browser with dynamic path detection
                launch_options = {
                    'headless': True,
                    'args': [
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor',
                        '--no-first-run',
                        '--disable-background-timer-throttling',
                        '--disable-renderer-backgrounding',
                        '--disable-backgrounding-occluded-windows',
                        '--disable-blink-features=AutomationControlled',
                        '--disable-extensions',
                        '--disable-plugins',
                        '--disable-default-apps',
                        '--disable-sync',
                        '--no-default-browser-check',
                        '--disable-client-side-phishing-detection',
                        '--disable-component-extensions-with-background-pages',
                        '--enable-automation'
                    ]
                }
                
                if self.browser_path:
                    launch_options['executable_path'] = self.browser_path
                    self.logger.debug(f"Using browser at: {self.browser_path}")
                
                browser = await p.chromium.launch(**launch_options)
                
                # Create context with realistic user agent and settings
                context = await browser.new_context(
                    user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080},
                    locale='en-US',
                    timezone_id='America/New_York'
                )
                
                page = await context.new_page()
                
                # Enable JavaScript and set up request interception to capture more cookies
                await page.set_extra_http_headers({
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                })
                
                # Set up request/response tracking to capture cookies during redirects
                all_responses = []
                all_requests = []
                
                def handle_response(response):
                    all_responses.append(response)
                    # Log important responses for debugging
                    if response.status in [200, 302, 301, 307, 308]:
                        self.logger.debug(f"Response: {response.url} - Status: {response.status}")
                
                def handle_request(request):
                    all_requests.append(request)
                    self.logger.debug(f"Request: {request.url}")
                
                page.on('response', handle_response)
                page.on('request', handle_request)
                
                # Navigate to the website with extended timeout for auth flows
                try:
                    response = await page.goto(url, wait_until='domcontentloaded', timeout=20000)
                except Exception as e:
                    self.logger.debug(f"Navigation error: {e}")
                    # Fallback: try with just load event
                    try:
                        response = await page.goto(url, wait_until='load', timeout=15000)
                    except Exception:
                        # Final fallback: basic navigation
                        response = await page.goto(url, timeout=10000)
                
                # Check if we were redirected and capture cookies from all steps
                final_url = page.url
                self.logger.info(f"Original URL: {url}, Final URL: {final_url}")
                
                # Capture cookies after initial navigation (including redirects)
                initial_cookies = await context.cookies()
                self.logger.info(f"Cookies after initial navigation: {len(initial_cookies)}")
                
                # If we're on a login/auth page, try to proceed with the auth flow
                is_auth_page = any(keyword in final_url.lower() for keyword in [
                    'login', 'signin', 'auth', 'sso', 'oauth', 'accounts.google'
                ])
                
                if is_auth_page:
                    self.logger.info("Detected authentication page, attempting to capture auth cookies")
                    
                    # Wait longer for auth redirects and cookie setting
                    await page.wait_for_timeout(5000)
                    
                    # Try to detect and handle common auth patterns
                    try:
                        # Look for Google Sign-In button or similar
                        google_signin_selectors = [
                            'button[data-provider="google"]',
                            'button:has-text("Sign in with Google")',
                            'button:has-text("Continue with Google")',
                            'a[href*="accounts.google.com"]',
                            '.google-signin-button',
                            '[data-testid*="google"]'
                        ]
                        
                        for selector in google_signin_selectors:
                            try:
                                element = await page.query_selector(selector)
                                if element:
                                    self.logger.info(f"Found Google sign-in element: {selector}")
                                    # Don't actually click, but capture any cookies set by hovering
                                    await element.hover(timeout=2000)
                                    await page.wait_for_timeout(3000)
                                    break
                            except:
                                continue
                                
                        # Check for OAuth redirects that might have occurred
                        if 'accounts.google.com' in final_url or 'oauth' in final_url.lower():
                            # We're in the middle of OAuth flow, wait for completion
                            try:
                                await page.wait_for_url('**experience.com**', timeout=15000)
                                await page.wait_for_timeout(3000)
                            except:
                                pass
                    except Exception as e:
                        self.logger.debug(f"Auth flow detection error: {e}")
                
                # Allow for dynamic loading and cookie setting after auth
                if response and response.status < 400:
                    status_ok = True
                else:
                    status_ok = False
                    self.logger.warning(f"Response status: {response.status if response else 'None'}")
                
                # Wait for network to be idle to ensure all requests complete
                try:
                    await page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass  # Continue even if networkidle times out
                
                # Wait additional time for dynamic content and cookies to load
                await page.wait_for_timeout(3000)
                
                # Trigger various page interactions that might set cookies
                try:
                    # Execute JavaScript to trigger any delayed cookie setting
                    await page.evaluate('''
                        // Trigger various events that might set cookies
                        window.dispatchEvent(new Event('load'));
                        window.dispatchEvent(new Event('DOMContentLoaded'));
                        
                        // Simulate user interaction events
                        document.dispatchEvent(new Event('mouseenter'));
                        document.dispatchEvent(new Event('focus'));
                        
                        // Check for any delayed cookie scripts
                        if (typeof gtag !== 'undefined') gtag('config', 'GA_MEASUREMENT_ID');
                        if (typeof fbq !== 'undefined') fbq('track', 'PageView');
                    ''')
                    await page.wait_for_timeout(2000)
                except:
                    pass
                
                # Scroll down to trigger any lazy-loaded content that might set cookies
                try:
                    await page.evaluate('''
                        window.scrollTo(0, document.body.scrollHeight);
                    ''')
                    await page.wait_for_timeout(1000)
                    
                    # Scroll back to top
                    await page.evaluate('window.scrollTo(0, 0);')
                    await page.wait_for_timeout(1000)
                except:
                    pass
                
                # Try hovering over common elements that might trigger cookie setting
                try:
                    common_selectors = [
                        'header', 'nav', 'footer', 'main', 
                        '[class*="header"]', '[class*="nav"]', '[class*="menu"]',
                        'button', 'a', 'input'
                    ]
                    
                    for selector in common_selectors[:3]:  # Limit to first 3 to avoid timeout
                        try:
                            element = await page.query_selector(selector)
                            if element:
                                await element.hover(timeout=1000)
                                await page.wait_for_timeout(500)
                                break
                        except:
                            continue
                except:
                    pass
                
                # Try to interact with common elements that might trigger cookie setting
                try:
                    # Look for and click cookie consent buttons with expanded selectors
                    consent_selectors = [
                        'button[id*="accept"]', 'button[class*="accept"]',
                        'button[id*="consent"]', 'button[class*="consent"]',
                        'button[id*="agree"]', 'button[class*="agree"]',
                        'button[id*="cookie"]', 'button[class*="cookie"]',
                        'a[id*="accept"]', 'a[class*="accept"]',
                        'button[id*="allow"]', 'button[class*="allow"]',
                        'button:has-text("Accept")', 'button:has-text("Allow")',
                        'button:has-text("I agree")', 'button:has-text("Continue")',
                        '[role="button"]:has-text("Accept")',
                        '[data-testid*="accept"]', '[data-cy*="accept"]'
                    ]
                    
                    for selector in consent_selectors:
                        try:
                            button = await page.query_selector(selector)
                            if button:
                                await button.click()
                                await page.wait_for_timeout(2000)
                                break
                        except:
                            continue
                except:
                    pass
                
                # Capture cookies after consent interactions
                post_consent_cookies = await context.cookies()
                self.logger.debug(f"Cookies after consent interaction: {len(post_consent_cookies)}")
                
                # Wait for any additional cookies that might be set after interactions
                await page.wait_for_timeout(3000)
                
                # Try to trigger any remaining JavaScript that might set cookies
                try:
                    await page.evaluate('''
                        // Force execution of any delayed analytics or tracking scripts
                        setTimeout(() => {
                            // Common patterns for delayed cookie setting
                            if (window.dataLayer) {
                                window.dataLayer.push({'event': 'page_view'});
                            }
                        }, 100);
                    ''')
                    await page.wait_for_timeout(2000)
                except:
                    pass
                
                # Get cookies from multiple sources and deduplicate them properly
                await page.wait_for_timeout(1000)
                
                # Get all cookies from context (includes all domains visited)
                all_cookies_raw = await context.cookies()
                
                # Get cookies for all related domains that might have been visited
                parsed_url = urlparse(url)
                base_domain = parsed_url.netloc.lower()
                
                # Try to get cookies for common auth domains
                auth_domains = [
                    base_domain,
                    f".{base_domain}",
                    ".google.com",
                    ".experience.com",
                    ".app.experience.com"
                ]
                
                for domain in auth_domains:
                    try:
                        domain_cookies = await context.cookies(domain)
                        for cookie in domain_cookies:
                            # Check if already exists
                            exists = any(
                                c.get('name') == cookie.get('name') and 
                                c.get('domain') == cookie.get('domain') and
                                c.get('path') == cookie.get('path')
                                for c in all_cookies_raw
                            )
                            if not exists:
                                all_cookies_raw.append(cookie)
                    except Exception as e:
                        self.logger.debug(f"Could not get cookies for domain {domain}: {e}")
                
                # Also try to get cookies directly from the page for any missed ones
                try:
                    page_cookies = await page.evaluate('''
                        () => {
                            const cookies = [];
                            if (document.cookie) {
                                document.cookie.split(';').forEach(cookie => {
                                    const parts = cookie.trim().split('=');
                                    if (parts.length >= 2) {
                                        cookies.push({
                                            name: parts[0].trim(),
                                            value: parts.slice(1).join('=').trim(),
                                            domain: window.location.hostname,
                                            path: '/',
                                            secure: window.location.protocol === 'https:',
                                            httpOnly: false,
                                            sameSite: 'Lax',
                                            expires: -1
                                        });
                                    }
                                });
                            }
                            return cookies;
                        }
                    ''')
                    
                    # Merge page cookies with context cookies
                    for page_cookie in page_cookies:
                        # Check if this cookie already exists in context cookies
                        exists = any(
                            c.get('name') == page_cookie['name'] and 
                            c.get('domain', '').endswith(page_cookie['domain'])
                            for c in all_cookies_raw
                        )
                        if not exists:
                            all_cookies_raw.append(page_cookie)
                            
                except Exception as e:
                    self.logger.debug(f"Could not extract page cookies: {e}")
                
                self.logger.info(f"Total raw cookies found: {len(all_cookies_raw)}")
                
                # Log all found cookies for debugging
                for cookie in all_cookies_raw:
                    self.logger.debug(f"Found cookie: {cookie.get('name')} on {cookie.get('domain')}")
                
                # Deduplicate cookies based on name, domain, and path
                seen_cookies = set()
                cookies = []
                
                for cookie in all_cookies_raw:
                    cookie_key = (cookie.get('name', ''), cookie.get('domain', ''), cookie.get('path', '/'))
                    if cookie_key not in seen_cookies:
                        seen_cookies.add(cookie_key)
                        cookies.append(cookie)
                
                self.logger.info(f"Deduplicated cookies: {len(cookies)}")
                
                # Log cookie details for debugging
                for cookie in cookies:
                    self.logger.debug(f"Cookie: {cookie.get('name')} - Domain: {cookie.get('domain')} - Path: {cookie.get('path')}")
                
                # Analyze cookies
                analyzed_cookies = []
                for cookie in cookies:
                    analyzed_cookie = self._analyze_cookie(cookie, url)
                    analyzed_cookies.append(analyzed_cookie)
                
                # Generate summary and recommendations
                summary = self._generate_summary(analyzed_cookies)
                recommendations = self._generate_recommendations(analyzed_cookies)
                
                return {
                    'success': True,
                    'cookies': analyzed_cookies,
                    'summary': summary,
                    'recommendations': recommendations,
                    'partial_analysis': not status_ok,
                    'final_url': final_url
                }
                
            except Exception as e:
                self.logger.error(f"Error in _analyze_async: {str(e)}")
                return {
                    'success': False,
                    'error': str(e),
                    'cookies': [],
                    'summary': {},
                    'recommendations': []
                }
            finally:
                if browser:
                    await browser.close()

    def _analyze_cookie(self, cookie, original_url):
        """Analyze individual cookie for security issues"""
        parsed_url = urlparse(original_url)
        original_domain = parsed_url.netloc.lower()
        
        # Basic cookie information
        analyzed = {
            'name': cookie.get('name', ''),
            'value': cookie.get('value', ''),
            'domain': cookie.get('domain', ''),
            'path': cookie.get('path', '/'),
            'secure': cookie.get('secure', False),
            'httpOnly': cookie.get('httpOnly', False),
            'sameSite': cookie.get('sameSite', 'None'),
            'expires': self._format_expires(cookie.get('expires', -1)),
            'size': len(cookie.get('name', '') + cookie.get('value', '')),
            'recommendations': [],
            'risk_level': 'Low'
        }
        
        # Add enhanced classification for authentication cookies
        analyzed['classification'] = self._classify_cookie(analyzed)
        
        # Determine if first-party or third-party
        cookie_domain = cookie.get('domain', '').lstrip('.')
        if cookie_domain and cookie_domain.lower() != original_domain:
            analyzed['type'] = 'Third-party'
        else:
            analyzed['type'] = 'First-party'
        
        # Check if session or persistent
        if cookie.get('expires', -1) == -1:
            analyzed['persistence'] = 'Session'
        else:
            analyzed['persistence'] = 'Persistent'
        
        # Security analysis and recommendations
        risk_factors = []
        
        # Check SameSite and Secure combination
        if analyzed['sameSite'] == 'None' and not analyzed['secure']:
            analyzed['recommendations'].append('Set Secure=true when using SameSite=None')
            risk_factors.append('samesite_insecure')
        
        # Check HttpOnly for session cookies
        if not analyzed['httpOnly'] and 'session' in analyzed['name'].lower():
            analyzed['recommendations'].append('Consider setting HttpOnly=true for session cookies')
            risk_factors.append('session_no_httponly')
        
        # Check for long expiry (>1 year)
        if cookie.get('expires', -1) != -1:
            expires_date = datetime.fromtimestamp(cookie['expires'])
            if expires_date > datetime.now() + timedelta(days=365):
                analyzed['recommendations'].append('Cookie has very long expiry (>1 year)')
                risk_factors.append('long_expiry')
        
        # Check for insecure cookies on HTTPS sites
        if original_url.startswith('https://') and not analyzed['secure']:
            analyzed['recommendations'].append('Set Secure=true for cookies on HTTPS sites')
            risk_factors.append('insecure_on_https')
        
        # Check for missing SameSite
        if not analyzed['sameSite'] or analyzed['sameSite'] == 'None':
            analyzed['recommendations'].append('Consider setting SameSite=Strict or Lax for CSRF protection')
            risk_factors.append('no_samesite')
        
        # Third-party cookie warning
        if analyzed['type'] == 'Third-party':
            analyzed['recommendations'].append('Third-party cookie - consider privacy implications')
            risk_factors.append('third_party')
        
        # Determine overall risk level
        if len(risk_factors) >= 3:
            analyzed['risk_level'] = 'High'
        elif len(risk_factors) >= 1:
            analyzed['risk_level'] = 'Medium'
        else:
            analyzed['risk_level'] = 'Low'
        
        if not analyzed['recommendations']:
            analyzed['recommendations'].append('No security issues detected')
        
        return analyzed

    def _classify_cookie(self, cookie):
        """Classify cookie based on its name and characteristics"""
        name = cookie['name'].lower()
        domain = cookie['domain'].lower()
        
        # Authentication cookies
        if any(auth_term in name for auth_term in [
            'session', 'sid', 'psid', 'auth', 'token', 'login', 'user',
            'sapisid', 'apisid', 'hsid', 'ssid', 'oauth', 'jwt'
        ]):
            return 'Authentication'
        
        # Analytics cookies
        if any(analytics_term in name for analytics_term in [
            '_ga', '_gid', '_gat', 'gtm', 'gtag', '_gcl', '_fbp', '_fbc',
            'analytics', 'tracking', 'utm'
        ]):
            return 'Analytics'
        
        # Advertisement cookies
        if any(ad_term in name for ad_term in [
            'ads', 'doubleclick', '_drt_', 'fr', 'datr', 'advertisement',
            'marketing', 'retargeting'
        ]):
            return 'Advertisement'
        
        # Performance cookies
        if any(perf_term in name for perf_term in [
            'performance', 'speed', 'load', 'cache', 'cdn'
        ]):
            return 'Performance'
        
        # Payment/Stripe cookies
        if 'stripe' in name or 'payment' in name:
            return 'Payment'
        
        # Functional cookies
        if any(func_term in name for func_term in [
            'lang', 'language', 'locale', 'timezone', 'theme', 'preferences',
            'settings', 'config', 'feature'
        ]):
            return 'Functional'
        
        # Google specific cookies
        if domain.endswith('.google.com'):
            if any(security_term in name for security_term in [
                'secure', 'nid', 'aec', 'search_samesite'
            ]):
                return 'Security'
            return 'Third-party'
        
        # Default classification
        return 'Functional'

    def _format_expires(self, expires):
        """Format cookie expiry timestamp to readable format"""
        if expires == -1:
            return 'Session'
        try:
            return datetime.fromtimestamp(expires).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return 'Invalid date'

    def _generate_summary(self, cookies):
        """Generate summary statistics for cookies"""
        if not cookies:
            return {
                'total': 0,
                'first_party': 0,
                'third_party': 0,
                'secure': 0,
                'insecure': 0,
                'http_only': 0,
                'session': 0,
                'persistent': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0
            }
        
        summary = {
            'total': len(cookies),
            'first_party': len([c for c in cookies if c['type'] == 'First-party']),
            'third_party': len([c for c in cookies if c['type'] == 'Third-party']),
            'secure': len([c for c in cookies if c['secure']]),
            'insecure': len([c for c in cookies if not c['secure']]),
            'http_only': len([c for c in cookies if c['httpOnly']]),
            'session': len([c for c in cookies if c['persistence'] == 'Session']),
            'persistent': len([c for c in cookies if c['persistence'] == 'Persistent']),
            'high_risk': len([c for c in cookies if c['risk_level'] == 'High']),
            'medium_risk': len([c for c in cookies if c['risk_level'] == 'Medium']),
            'low_risk': len([c for c in cookies if c['risk_level'] == 'Low'])
        }
        
        return summary

    def _generate_recommendations(self, cookies):
        """Generate overall security recommendations"""
        if not cookies:
            return ['No cookies found on this website.']
        
        recommendations = []
        
        # Count risk factors
        high_risk_count = len([c for c in cookies if c['risk_level'] == 'High'])
        medium_risk_count = len([c for c in cookies if c['risk_level'] == 'Medium'])
        insecure_count = len([c for c in cookies if not c['secure']])
        no_httponly_sessions = len([c for c in cookies if 'session' in c['name'].lower() and not c['httpOnly']])
        third_party_count = len([c for c in cookies if c['type'] == 'Third-party'])
        
        if high_risk_count > 0:
            recommendations.append(f'{high_risk_count} cookies have high security risks that should be addressed immediately.')
        
        if medium_risk_count > 0:
            recommendations.append(f'{medium_risk_count} cookies have medium security risks that should be reviewed.')
        
        if insecure_count > 0:
            recommendations.append(f'{insecure_count} cookies are not marked as Secure. Consider adding the Secure flag.')
        
        if no_httponly_sessions > 0:
            recommendations.append(f'{no_httponly_sessions} session cookies lack HttpOnly flag, making them vulnerable to XSS.')
        
        if third_party_count > 0:
            recommendations.append(f'{third_party_count} third-party cookies detected. Review for privacy compliance.')
        
        if not recommendations:
            recommendations.append('Overall cookie security looks good! Keep monitoring for changes.')
        
        return recommendations
