# Cookie Security Analyzer

A Flask-based web application that analyzes website cookies for security vulnerabilities using Playwright browser automation. The application provides comprehensive cookie security analysis including SameSite settings, Secure flags, HttpOnly attributes, expiration periods, and third-party tracking detection.

## Features

- **Comprehensive Cookie Analysis**: Extracts and analyzes all cookies from any website
- **Security Vulnerability Detection**: Identifies common cookie security issues
- **Risk Classification**: Categorizes cookies by risk level (High, Medium, Low)
- **First-party vs Third-party Detection**: Distinguishes between first-party and third-party cookies
- **Session vs Persistent Analysis**: Identifies session and persistent cookies
- **Security Recommendations**: Provides actionable security recommendations
- **CSV Export**: Export analysis results for further review
- **Responsive Design**: Clean, modern interface using Bootstrap
- **Real-time Analysis**: Uses headless browser automation for accurate results

## Security Checks

The analyzer performs the following security checks:

✅ **SameSite Attribute**: Warns if `SameSite=None` without `Secure` flag  
✅ **Secure Flag**: Identifies insecure cookies on HTTPS sites  
✅ **HttpOnly Flag**: Suggests HttpOnly for session cookies  
✅ **Cookie Expiration**: Flags cookies with excessive expiry periods (>1 year)  
✅ **Third-party Tracking**: Identifies and warns about third-party cookies  
✅ **CSRF Protection**: Recommends proper SameSite settings  

## Prerequisites

- Python 3.11 or higher
- pip or uv package manager

## Installation

### Method 1: Using UV (Recommended)

1. **Clone or download the project files**

2. **Install dependencies using UV**:
   ```bash
   uv add flask flask-sqlalchemy gunicorn playwright email-validator psycopg2-binary trafilatura
   ```

3. **Install Playwright browsers**:
   ```bash
   python -m playwright install chromium
   ```

### Method 2: Using PIP

1. **Create a virtual environment** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install flask flask-sqlalchemy gunicorn playwright email-validator psycopg2-binary trafilatura
   ```

3. **Install Playwright browsers**:
   ```bash
   python -m playwright install chromium
   ```

## Configuration

### Environment Variables

Set the following environment variables for production:

```bash
export SESSION_SECRET="your-secret-key-here"
export DATABASE_URL="sqlite:///cookies.db"  # Optional: for future database features
```

For development, the app will use default values.

## Running the Application

### Development Mode

```bash
python main.py
```

The application will start on `http://0.0.0.0:5000`

### Production Mode

```bash
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

## Usage

1. **Open your web browser** and navigate to `http://localhost:5000`

2. **Enter a website URL** in the input field (e.g., `https://example.com`)

3. **Click "Analyze Cookies"** to start the analysis

4. **Review the results**:
   - Summary statistics showing total cookies, security status, and risk levels
   - Detailed table with individual cookie analysis
   - Security recommendations for improving cookie security

5. **Export results** (optional): Click "Export CSV" to download analysis results

## Project Structure

```
cookie-security-analyzer/
├── app.py                 # Main Flask application
├── main.py               # Application entry point
├── cookie_analyzer.py    # Core cookie analysis logic
├── templates/
│   ├── index.html        # Home page template
│   └── results.html      # Results page template
├── static/
│   ├── css/
│   │   └── custom.css    # Custom styles
│   └── js/
│       └── app.js        # Frontend JavaScript
├── pyproject.toml        # Python dependencies
├── uv.lock              # Dependency lock file
└── README.md            # This file
```

## API Endpoints

- `GET /` - Home page with URL input form
- `POST /analyze` - Analyze cookies for submitted URL
- `GET /export/<path:url>` - Export analysis results as CSV

## Dependencies

### Core Dependencies
- **Flask**: Web framework
- **Playwright**: Browser automation for cookie extraction
- **Gunicorn**: WSGI HTTP server for production

### Optional Dependencies
- **Flask-SQLAlchemy**: Database ORM (for future features)
- **email-validator**: Email validation utilities
- **psycopg2-binary**: PostgreSQL adapter
- **trafilatura**: Web content extraction

## Troubleshooting

### Browser Installation Issues

If you encounter browser installation errors:

```bash
# Try installing with specific browser
python -m playwright install chromium

# Check browser installation
python -m playwright install --help
```

### Permission Issues

On some systems, you might need additional permissions:

```bash
# Linux/macOS
chmod +x chrome-linux/chrome

# Or run with no-sandbox flag (already configured in the app)
```

### Memory Issues

For systems with limited memory:

```bash
# Run with reduced memory usage
export PLAYWRIGHT_BROWSERS_PATH=/tmp/playwright
python -m playwright install chromium
```

## Security Considerations

- The application doesn't store any analyzed data
- All analysis is performed in real-time
- Headless browser runs in sandboxed environment
- No cookies or personal data are saved locally

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the browser installation requirements
3. Ensure all dependencies are properly installed
4. Verify network connectivity for the target website

## Changelog

### v1.0.0
- Initial release
- Complete cookie security analysis
- Bootstrap-based responsive UI
- CSV export functionality
- Comprehensive security recommendations