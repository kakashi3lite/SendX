/**
 * AI Prompt Injection Protection
 * Defends against attempts to inject prompts into AI systems.
 * This is critical for maintaining security when content might be processed by LLMs.
 */

class AISecurityManager {
    // Common patterns used in prompt injection attacks
    static PROMPT_INJECTION_PATTERNS = [
        // System prompt takeover attempts
        /ignore previous (instructions|prompts)/i,
        /ignore all previous commands/i,
        /you are now (a|an) (?!assistant)/i,  // "You are now a [anything except 'assistant']"
        /system prompt/i,
        /you must (obey|follow)/i,
        
        // Jailbreak attempts
        /DAN|do anything now/i,
        /character\s*mode/i,
        /dev\s*mode/i,
        /ignore (ethics|rules|restrictions|guidelines)/i,
        /harmful\s*content/i,
        
        // Data extraction instructions
        /extract (all|sensitive) data/i,
        /dump (database|data|config|credentials)/i,
        
        // Evasion techniques with repeated special characters
        /[^\w\s.,;:!?](\s*)[^\w\s.,;:!?](\s*)[^\w\s.,;:!?]/i,
        /base64:/i,
        /\\u[0-9a-fA-F]{4}/,  // Unicode escape sequences
        
        // Command injection
        /curl|wget|bash|sh|powershell|cmd|exec/i,
        
        // Instructions to override security
        /bypass (security|authentication|verification)/i,
        /disable (security|authentication|verification)/i
    ];
    
    /**
     * Check if text contains potential prompt injection patterns
     * @param {string} text - Text to check
     * @returns {boolean} True if suspicious patterns found
     */
    static detectPromptInjection(text) {
        if (!text || typeof text !== 'string') return false;
        
        // Check for encoded content (base64)
        try {
            const base64Pattern = /[A-Za-z0-9+/=]{20,}/g;
            const matches = text.match(base64Pattern);
            if (matches) {
                for (const match of matches) {
                    try {
                        // Try to decode and check the decoded content
                        const decoded = atob(match);
                        if (this.detectPromptInjection(decoded)) {
                            return true;
                        }
                    } catch (e) {
                        // Not valid base64, continue
                    }
                }
            }
        } catch (e) {
            // Error in base64 processing, continue with normal checks
        }
        
        // Check against predefined patterns
        for (const pattern of this.PROMPT_INJECTION_PATTERNS) {
            if (pattern.test(text)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Sanitize text by removing potential prompt injection patterns
     * @param {string} text - Text to sanitize
     * @returns {string} Sanitized text
     */
    static sanitizeText(text) {
        if (!text || typeof text !== 'string') return text;
        
        let sanitized = text;
        
        // Replace common prompt injection markers
        sanitized = sanitized.replace(/system prompt/gi, "[filtered]");
        sanitized = sanitized.replace(/ignore previous/gi, "[filtered]");
        sanitized = sanitized.replace(/you are now a/gi, "[filtered]");
        
        // Remove multiple special characters that might be used for evasion
        sanitized = sanitized.replace(/([^\w\s.,;:!?])\1{2,}/g, "$1");
        
        return sanitized;
    }
    
    /**
     * Add AI security headers to a fetch request
     * @param {Object} options - Fetch options object
     * @returns {Object} Updated options with AI security headers
     */
    static addAISecurityHeaders(options = {}) {
        const headers = options.headers || {};
        
        // Add LLM security headers
        headers["X-LLM-Protection"] = "1; mode=block";
        headers["LLM-Processing-Policy"] = "no-processing";
        headers["LLM-Context-Policy"] = "no-external-context";
        headers["X-AI-Instructions"] = "none; no-process; no-training; no-indexing";
        
        return {
            ...options,
            headers
        };
    }
    
    /**
     * Validate user input for potential prompt injection before submission
     * @param {string} input - User input to validate
     * @returns {Object} Validation result {valid: boolean, reason: string}
     */
    static validateUserInput(input) {
        if (!input) {
            return { valid: true };
        }
        
        if (this.detectPromptInjection(input)) {
            return { 
                valid: false, 
                reason: "Your input contains patterns that violate our security policy." 
            };
        }
        
        return { valid: true };
    }
}

// Enhance existing form submissions with AI security checks
document.addEventListener('DOMContentLoaded', function() {
    // Intercept form submissions
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            // Check textarea and input elements for prompt injection
            const textInputs = this.querySelectorAll('textarea, input[type="text"]');
            
            for (const input of textInputs) {
                const validation = AISecurityManager.validateUserInput(input.value);
                
                if (!validation.valid) {
                    e.preventDefault();
                    
                    // Show error message
                    alert(validation.reason);
                    
                    // Highlight the problematic input
                    input.classList.add('error-input');
                    
                    // Log the event (without the actual content)
                    console.warn('Potential prompt injection detected in form submission');
                    
                    return;
                }
            }
        });
    });
    
    // Enhance fetch/XHR requests with AI security headers
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        const enhancedOptions = AISecurityManager.addAISecurityHeaders(options);
        return originalFetch.call(this, url, enhancedOptions);
    };
    
    // Add security for XMLHttpRequest
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function() {
        const xhr = this;
        const originalSend = xhr.send;
        
        xhr.send = function(body) {
            xhr.setRequestHeader("X-LLM-Protection", "1; mode=block");
            xhr.setRequestHeader("LLM-Processing-Policy", "no-processing");
            
            // Check if body contains potential prompt injection
            if (body && typeof body === 'string' && AISecurityManager.detectPromptInjection(body)) {
                console.error('Potential prompt injection detected in XHR request');
                throw new Error('Request blocked due to security policy violation');
            }
            
            return originalSend.apply(this, arguments);
        };
        
        return originalOpen.apply(this, arguments);
    };
    
    console.log('AI Security Protection initialized');
});

// Export for use in other scripts
window.AISecurityManager = AISecurityManager;
