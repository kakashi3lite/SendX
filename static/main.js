/**
 * One-View Secrets - Main Application Logic
 * Handles UI interactions and orchestrates encryption/decryption
 */

document.addEventListener('DOMContentLoaded', function() {
    // Check WebCrypto support
    if (!CryptoManager.isSupported()) {
        showError('Your browser does not support the required encryption features. Please use a modern browser with HTTPS.');
        return;
    }

    // Initialize the application
    initializeApp();
});

function initializeApp() {
    const createForm = document.getElementById('createSecretForm');
    const createBtn = document.getElementById('createBtn');
    const copyBtn = document.getElementById('copyBtn');
    const showQrBtn = document.getElementById('showQrBtn');
    const createAnotherBtn = document.getElementById('createAnotherBtn');

    // Form submission handler
    if (createForm) {
        createForm.addEventListener('submit', handleCreateSecret);
    }

    // Copy button handler
    if (copyBtn) {
        copyBtn.addEventListener('click', handleCopyUrl);
    }

    // QR code button handler
    if (showQrBtn) {
        showQrBtn.addEventListener('click', handleShowQr);
    }

    // Create another secret button handler
    if (createAnotherBtn) {
        createAnotherBtn.addEventListener('click', handleCreateAnother);
    }

    // Auto-focus on secret text area
    const secretTextArea = document.getElementById('secretText');
    if (secretTextArea) {
        secretTextArea.focus();
    }
}

async function handleCreateSecret(event) {
    event.preventDefault();
    
    const secretText = document.getElementById('secretText').value.trim();
    const ttl = parseInt(document.getElementById('ttlSelect').value);
    
    // Validation
    if (!secretText) {
        showError('Please enter a secret to share.');
        return;
    }
    
    if (secretText.length > 50000) {
        showError('Secret is too long. Maximum 50,000 characters allowed.');
        return;
    }
    
    // AI Security Validation
    const securityCheck = AISecurityManager.validateUserInput(secretText);
    if (!securityCheck.valid) {
        showError('Your secret contains patterns that could be used for prompt injection attacks. Please modify your content and try again.');
        return;
    }
    
    try {
        // Show loading state
        showLoadingState();
        
        // Generate encryption key
        const encryptionKey = await CryptoManager.generateKey();
        
        // Encrypt the secret
        const encryptedData = await CryptoManager.encrypt(secretText, encryptionKey);
        
        // Export key for URL fragment
        const exportedKey = await CryptoManager.exportKey(encryptionKey);
        
        // Send encrypted data to server
        const response = await fetch('/api/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ciphertext: encryptedData,
                ttl: ttl
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `HTTP ${response.status}`);
        }
        
        const result = await response.json();
        
        // Create the secure URL with key in fragment
        const baseUrl = `${window.location.origin}/view?id=${result.secret_id}`;
        const secureUrl = `${baseUrl}#${exportedKey}`;
        
        // Show success state
        showSuccessState(secureUrl, result.secret_id, result.expires_in_hours);
        
        // Clear sensitive data
        CryptoManager.clearSensitiveData(secretText);
        document.getElementById('secretText').value = '';
        
    } catch (error) {
        console.error('Error creating secret:', error);
        if (error.message.includes('429')) {
            showError('Please wait a moment before creating another secret.');
        } else if (error.message.includes('400')) {
            showError('Secret content is invalid or too large. Please check your input.');
        } else {
            showError('Failed to create secret. Please try again.');
        }
    }
}

function handleCopyUrl() {
    const urlInput = document.getElementById('secretUrl');
    const copyBtn = document.getElementById('copyBtn');
    
    // Select and copy the URL
    urlInput.select();
    urlInput.setSelectionRange(0, 99999); // For mobile devices
    
    navigator.clipboard.writeText(urlInput.value).then(() => {
        // Show success feedback with better UX
        const originalHtml = copyBtn.innerHTML;
        copyBtn.innerHTML = '<i class="bi bi-check"></i> Link copied';
        copyBtn.classList.add('btn-success');
        copyBtn.classList.remove('btn-outline-secondary');
        copyBtn.disabled = true;
        
        // Show toast notification
        showToast('Link copied to clipboard!', 'success');
        
        setTimeout(() => {
            copyBtn.innerHTML = originalHtml;
            copyBtn.classList.remove('btn-success');
            copyBtn.classList.add('btn-outline-secondary');
            copyBtn.disabled = false;
        }, 2000);
    }).catch(() => {
        // Fallback for older browsers
        try {
            document.execCommand('copy');
            showTemporarySuccess(copyBtn, 'Copied!');
        } catch (err) {
            showError('Failed to copy URL. Please copy it manually.');
        }
    });
}

async function handleShowQr() {
    const secretUrl = document.getElementById('secretUrl').value;
    const qrContainer = document.getElementById('qrCodeContainer');
    const qrImg = document.getElementById('qrCodeImg');
    const showQrBtn = document.getElementById('showQrBtn');
    
    if (qrContainer.style.display === 'none') {
        try {
            // Extract secret ID from URL
            const urlObj = new URL(secretUrl);
            const secretId = urlObj.searchParams.get('id');
            
            if (!secretId) {
                throw new Error('Invalid URL format');
            }
            
            // Show loading state
            showQrBtn.disabled = true;
            showQrBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Generating...';
            
            // Generate QR code
            const qrResponse = await fetch(`/api/qr/${secretId}`);
            
            if (!qrResponse.ok) {
                throw new Error('Failed to generate QR code');
            }
            
            // Create blob URL for the image
            const blob = await qrResponse.blob();
            const imageUrl = URL.createObjectURL(blob);
            
            // Display QR code
            qrImg.src = imageUrl;
            qrContainer.style.display = 'block';
            showQrBtn.innerHTML = '<i class="bi bi-eye-slash"></i> Hide QR Code';
            
        } catch (error) {
            console.error('Error generating QR code:', error);
            showError('Failed to generate QR code. Please try again.');
        } finally {
            showQrBtn.disabled = false;
        }
    } else {
        // Hide QR code
        qrContainer.style.display = 'none';
        showQrBtn.innerHTML = '<i class="bi bi-qr-code"></i> Show QR Code';
        
        // Clean up blob URL
        if (qrImg.src.startsWith('blob:')) {
            URL.revokeObjectURL(qrImg.src);
        }
    }
}

function handleCreateAnother() {
    // Reset to initial state
    hideAllStates();
    document.getElementById('createSecretForm').style.display = 'block';
    document.getElementById('secretText').focus();
    
    // Clear any existing QR code
    const qrContainer = document.getElementById('qrCodeContainer');
    const qrImg = document.getElementById('qrCodeImg');
    if (qrContainer) {
        qrContainer.style.display = 'none';
        if (qrImg.src.startsWith('blob:')) {
            URL.revokeObjectURL(qrImg.src);
        }
    }
}

function showLoadingState() {
    hideAllStates();
    document.getElementById('loadingState').style.display = 'block';
}

function showSuccessState(secureUrl, secretId, expiresInHours) {
    hideAllStates();
    
    // Set the URL in the input
    document.getElementById('secretUrl').value = secureUrl;
    
    // Show success state
    document.getElementById('successResult').style.display = 'block';
    
    // Add fade-in animation
    document.getElementById('successResult').classList.add('fade-in');
}

function showError(message) {
    hideAllStates();
    
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorState').style.display = 'block';
    document.getElementById('createSecretForm').style.display = 'block';
    
    // Show error toast
    showToast(message, 'error');
}

function hideAllStates() {
    const states = [
        'loadingState',
        'successResult', 
        'errorState'
    ];
    
    states.forEach(stateId => {
        const element = document.getElementById(stateId);
        if (element) {
            element.style.display = 'none';
            element.classList.remove('fade-in');
        }
    });
}

function showTemporarySuccess(button, message) {
    const originalHtml = button.innerHTML;
    const originalClasses = button.className;
    
    button.innerHTML = `<i class="bi bi-check"></i> ${message}`;
    button.className = 'btn btn-success';
    
    setTimeout(() => {
        button.innerHTML = originalHtml;
        button.className = originalClasses;
    }, 2000);
}

// Utility function to validate URLs
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Security: Clear clipboard on page unload (best effort)
window.addEventListener('beforeunload', () => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText('').catch(() => {
            // Ignore errors - this is best effort
        });
    }
});

// Security: Clear form on page visibility change
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Page is hidden, clear sensitive form data
        const secretTextArea = document.getElementById('secretText');
        if (secretTextArea && secretTextArea.value.trim()) {
            // Only clear if user hasn't submitted yet
            const successResult = document.getElementById('successResult');
            if (!successResult || successResult.style.display === 'none') {
                // Don't clear if we're showing success state
                return;
            }
        }
    }
});

// Rate limiting feedback
let lastRequestTime = 0;
const RATE_LIMIT_DELAY = 1000; // 1 second between requests

function checkRateLimit() {
    const now = Date.now();
    if (now - lastRequestTime < RATE_LIMIT_DELAY) {
        return false;
    }
    lastRequestTime = now;
    return true;
}

// Toast notification system
function showToast(message, type = 'info', duration = 3000) {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '1055';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'primary'} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="bi bi-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    // Initialize and show toast
    const bsToast = new bootstrap.Toast(toast, {
        delay: type === 'error' ? 5000 : duration // Error messages stay longer
    });
    bsToast.show();
    
    // Remove toast element after it's hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// Character counter for textarea
function initCharacterCounter() {
    const secretTextArea = document.getElementById('secretText');
    const maxLength = 50000;
    
    if (secretTextArea) {
        // Create character counter element
        const counterElement = document.createElement('div');
        counterElement.className = 'form-text text-end';
        counterElement.id = 'charCounter';
        secretTextArea.parentElement.appendChild(counterElement);
        
        function updateCounter() {
            const length = secretTextArea.value.length;
            counterElement.textContent = `${length.toLocaleString()}/${maxLength.toLocaleString()} characters`;
            
            if (length > maxLength * 0.9) {
                counterElement.classList.add('text-warning');
            } else {
                counterElement.classList.remove('text-warning');
            }
            
            if (length >= maxLength) {
                counterElement.classList.add('text-danger');
                counterElement.classList.remove('text-warning');
            } else {
                counterElement.classList.remove('text-danger');
            }
        }
        
        secretTextArea.addEventListener('input', updateCounter);
        updateCounter(); // Initial count
    }
}

// Initialize character counter when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initCharacterCounter();
});

// Export for debugging (only in development)
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    window.OVSDebug = {
        CryptoManager,
        showError,
        showSuccessState,
        showToast,
        handleCreateSecret
    };
}
