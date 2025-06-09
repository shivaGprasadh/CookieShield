// Cookie Security Analyzer JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Form submission handling with loading state
    const analyzeForm = document.getElementById('analyzeForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (analyzeForm && analyzeBtn) {
        analyzeForm.addEventListener('submit', function(e) {
            // Show loading state
            analyzeBtn.classList.add('loading');
            analyzeBtn.disabled = true;
            
            // Update button text
            const btnText = analyzeBtn.querySelector('.btn-text');
            const spinner = analyzeBtn.querySelector('.spinner-border');
            
            if (btnText) btnText.textContent = 'Analyzing...';
            if (spinner) spinner.classList.remove('d-none');
            
            // Optional: Add timeout to prevent hanging
            setTimeout(function() {
                if (analyzeBtn.classList.contains('loading')) {
                    analyzeBtn.classList.remove('loading');
                    analyzeBtn.disabled = false;
                    if (btnText) btnText.textContent = 'Analyze Cookies';
                    if (spinner) spinner.classList.add('d-none');
                }
            }, 60000); // 60 second timeout
        });
    }
    
    // URL input validation and formatting
    const urlInput = document.getElementById('url');
    if (urlInput) {
        urlInput.addEventListener('blur', function() {
            let url = this.value.trim();
            
            // Auto-add protocol if missing
            if (url && !url.match(/^https?:\/\//)) {
                // Check if it looks like a domain
                if (url.match(/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\..*$/)) {
                    this.value = 'https://' + url;
                }
            }
        });
        
        // Real-time validation feedback
        urlInput.addEventListener('input', function() {
            const url = this.value.trim();
            const isValid = url === '' || url.match(/^https?:\/\/.+/);
            
            if (isValid) {
                this.classList.remove('is-invalid');
                this.classList.add('is-valid');
            } else {
                this.classList.remove('is-valid');
                this.classList.add('is-invalid');
            }
        });
    }
    
    // Table enhancements
    const tables = document.querySelectorAll('.table');
    tables.forEach(function(table) {
        // Add hover effects and click handling for rows
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(function(row) {
            row.style.cursor = 'pointer';
            
            row.addEventListener('click', function() {
                // Toggle row selection/highlighting
                this.classList.toggle('table-active');
            });
        });
    });
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    // Tooltip initialization for any tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Copy to clipboard functionality for cookie names/values
    const codeElements = document.querySelectorAll('code');
    codeElements.forEach(function(codeEl) {
        codeEl.style.cursor = 'pointer';
        codeEl.title = 'Click to copy';
        
        codeEl.addEventListener('click', function() {
            navigator.clipboard.writeText(this.textContent).then(function() {
                // Show temporary success feedback
                const originalText = codeEl.textContent;
                codeEl.textContent = 'Copied!';
                codeEl.classList.add('text-success');
                
                setTimeout(function() {
                    codeEl.textContent = originalText;
                    codeEl.classList.remove('text-success');
                }, 1000);
            }).catch(function(err) {
                console.error('Failed to copy text: ', err);
            });
        });
    });
    
    // Search/filter functionality for large cookie tables
    const searchInput = document.getElementById('cookieSearch');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const tableRows = document.querySelectorAll('.table tbody tr');
            
            tableRows.forEach(function(row) {
                const text = row.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }
    
    // Risk level filtering
    const riskFilters = document.querySelectorAll('.risk-filter');
    riskFilters.forEach(function(filter) {
        filter.addEventListener('change', function() {
            const selectedRisks = Array.from(riskFilters)
                .filter(f => f.checked)
                .map(f => f.value);
            
            const tableRows = document.querySelectorAll('.table tbody tr');
            tableRows.forEach(function(row) {
                const riskBadge = row.querySelector('.badge');
                if (!riskBadge) return;
                
                const riskLevel = riskBadge.textContent.trim();
                if (selectedRisks.length === 0 || selectedRisks.includes(riskLevel)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    });
});

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Export functionality enhancement
function downloadCSV(data, filename) {
    const blob = new Blob([data], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.setAttribute('hidden', '');
    a.setAttribute('href', url);
    a.setAttribute('download', filename);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Print functionality
function printResults() {
    window.print();
}

// Theme toggle (if needed)
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

// Load saved theme preference
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
    }
});
