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
                
                # Navigate to the website with shorter timeout and fallback
                try:
                    response = await page.goto(url, wait_until='domcontentloaded', timeout=15000)
                except Exception:
                    # Fallback: try with just load event
                    response = await page.goto(url, wait_until='load', timeout=10000)
                
                if not response or response.status >= 400:
                    return {
                        'success': False,
                        'error': f'Failed to load website (Status: {response.status if response else "Unknown"})',
                        'cookies': [],
                        'summary': {},
                        'recommendations': []
                    }
                
                # Wait for network to be idle to ensure all requests complete
                try:
                    await page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass  # Continue even if networkidle times out
                
                # Wait additional time for dynamic content and cookies to load
                await page.wait_for_timeout(3000)
                
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
                
                # Try to interact with common elements that might trigger cookie setting
                try:
                    # Look for and click cookie consent buttons
                    consent_selectors = [
                        'button[id*="accept"]', 'button[class*="accept"]',
                        'button[id*="consent"]', 'button[class*="consent"]',
                        'button[id*="agree"]', 'button[class*="agree"]',
                        'button[id*="cookie"]', 'button[class*="cookie"]',
                        'a[id*="accept"]', 'a[class*="accept"]'
                    ]
                    
                    for selector in consent_selectors:
                        try:
                            button = await page.query_selector(selector)
                            if button:
                                await button.click()
                                await page.wait_for_timeout(1000)
                                break
                        except:
                            continue
                except:
                    pass
                
                # Wait for any additional cookies that might be set after interactions
                await page.wait_for_timeout(2000)
                
                # Get cookies and deduplicate them properly
                await page.wait_for_timeout(1000)
                all_cookies_raw = await context.cookies()
                
                # Deduplicate cookies based on name, domain, and path
                seen_cookies = set()
                cookies = []
                
                for cookie in all_cookies_raw:
                    cookie_key = (cookie.get('name', ''), cookie.get('domain', ''), cookie.get('path', '/'))
                    if cookie_key not in seen_cookies:
                        seen_cookies.add(cookie_key)
                        cookies.append(cookie)
                
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
                    'recommendations': recommendations
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
