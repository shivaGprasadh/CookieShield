#!/bin/bash

# Cookie Security Analyzer Setup Script
# This script installs all required dependencies and sets up the application

set -e

echo "🛡️  Cookie Security Analyzer Setup"
echo "=================================="

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

# Install UV package manager if not present
if ! command -v uv &> /dev/null; then
    echo "Installing UV package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env
fi

# Install Python dependencies
echo "Installing Python dependencies..."
uv add flask flask-sqlalchemy gunicorn playwright email-validator psycopg2-binary trafilatura

# Install Playwright browsers
echo "Installing Playwright browsers (this may take a few minutes)..."
python3 -m playwright install chromium

# Set up environment variables
echo "Setting up environment..."
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat > .env << EOF
SESSION_SECRET=your-secret-key-change-in-production
DATABASE_URL=sqlite:///cookies.db
EOF
    echo "Created .env file with default values"
fi

# Create run script
echo "Creating run script..."
cat > run.sh << 'EOF'
#!/bin/bash
# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Start the application
echo "Starting Cookie Security Analyzer..."
echo "Open your browser and visit: http://localhost:5000"
python3 main.py
EOF

chmod +x run.sh

echo ""
echo "✅ Setup completed successfully!"
echo ""
echo "To start the application:"
echo "  ./run.sh"
echo ""
echo "Or run manually:"
echo "  python3 main.py"
echo ""
echo "The application will be available at: http://localhost:5000"