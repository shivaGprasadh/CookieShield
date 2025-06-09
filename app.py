import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for, make_response
from cookie_analyzer import CookieAnalyzer
import csv
import io

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

@app.route('/')
def index():
    """Main page with URL input form"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze cookies for the submitted URL"""
    url = request.form.get('url', '').strip()

    if not url:
        flash('Please enter a valid URL', 'error')
        return redirect(url_for('index'))

    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        analyzer = CookieAnalyzer()
        results = analyzer.analyze_website(url)

        if not results['success']:
            flash(f'Error analyzing website: {results["error"]}', 'error')
            return redirect(url_for('index'))

        return render_template('results.html', 
                             url=url, 
                             cookies=results['cookies'],
                             summary=results['summary'],
                             recommendations=results['recommendations'])

    except Exception as e:
        logging.error(f"Error analyzing {url}: {str(e)}")
        flash(f'An error occurred while analyzing the website: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/export/<path:url>')
def export_csv(url):
    """Export analysis results to CSV"""
    try:
        analyzer = CookieAnalyzer()
        results = analyzer.analyze_website(url)

        if not results['success']:
            flash('Unable to export - analysis failed', 'error')
            return redirect(url_for('index'))

        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'Cookie Name', 'Domain', 'Path', 'Value', 'SameSite', 
            'Secure', 'HttpOnly', 'Expires', 'Size', 'Type', 
            'Persistence', 'Classification', 'Risk Level', 'Recommendations'
        ])

        # Write cookie data
        for cookie in results['cookies']:
            writer.writerow([
                cookie['name'],
                cookie['domain'],
                cookie['path'],
                cookie['value'][:50] + '...' if len(cookie['value']) > 50 else cookie['value'],
                cookie['sameSite'],
                cookie['secure'],
                cookie['httpOnly'],
                cookie['expires'],
                cookie['size'],
                cookie['type'],
                cookie['persistence'],
                cookie['classification'],
                cookie['risk_level'],
                '; '.join(cookie['recommendations'])
            ])

        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=cookie_analysis_{url.replace("://", "_").replace("/", "_")}.csv'

        return response

    except Exception as e:
        logging.error(f"Error exporting CSV for {url}: {str(e)}")
        flash('Error exporting results', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)