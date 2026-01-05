/**
 * GentlyOS VS Code Extension - Security Utilities
 *
 * Token distilling and security practices:
 * - API key masking in logs
 * - Credential leak detection (TokenWatchdog integration)
 * - Response sanitization for prompt injection
 * - Token counting and limits
 */

import * as vscode from 'vscode';

// Token patterns from gently-security TokenWatchdog
const TOKEN_PATTERNS: { name: string; pattern: RegExp; mask: string }[] = [
    { name: 'anthropic', pattern: /sk-ant-api\d{2}-[A-Za-z0-9_-]{95}/g, mask: 'sk-ant-***' },
    { name: 'openai', pattern: /sk-[A-Za-z0-9]{48}/g, mask: 'sk-***' },
    { name: 'openai_proj', pattern: /sk-proj-[A-Za-z0-9_-]{100,}/g, mask: 'sk-proj-***' },
    { name: 'github', pattern: /ghp_[A-Za-z0-9]{36}/g, mask: 'ghp_***' },
    { name: 'github_oauth', pattern: /gho_[A-Za-z0-9]{36}/g, mask: 'gho_***' },
    { name: 'aws_access', pattern: /AKIA[A-Z0-9]{16}/g, mask: 'AKIA***' },
    { name: 'aws_secret', pattern: /[A-Za-z0-9/+=]{40}(?=\s|$|")/g, mask: '***AWS_SECRET***' },
    { name: 'groq', pattern: /gsk_[A-Za-z0-9]{52}/g, mask: 'gsk_***' },
    { name: 'huggingface', pattern: /hf_[A-Za-z0-9]{34}/g, mask: 'hf_***' },
    { name: 'deepseek', pattern: /sk-[a-f0-9]{32}/g, mask: 'sk-***' },
];

// Prompt injection patterns from gently-security intel daemon
const INJECTION_PATTERNS: RegExp[] = [
    /ignore\s+(all\s+)?previous\s+instructions?/i,
    /disregard\s+(all\s+)?prior\s+(instructions?|context)/i,
    /forget\s+(everything|all|your)\s+(you\s+)?know/i,
    /you\s+are\s+now\s+(a\s+)?DAN/i,
    /jailbreak/i,
    /pretend\s+you\s+(are|have)\s+no\s+(restrictions?|limitations?)/i,
    /<\|im_start\|>/,
    /<\|im_end\|>/,
    /<<SYS>>/,
    /\[INST\]/,
    /system:\s*you\s+are/i,
    /\{\{system\}\}/i,
    /ADMIN\s*OVERRIDE/i,
    /sudo\s+mode/i,
];

export interface SecurityConfig {
    tokenWatchdog: boolean;
    sanitizeResponses: boolean;
    maskTokensInLogs: boolean;
    maxRequestTokens: number;
    maxResponseTokens: number;
}

export function getSecurityConfig(): SecurityConfig {
    const config = vscode.workspace.getConfiguration('gentlyos');
    return {
        tokenWatchdog: config.get('security.tokenWatchdog', true),
        sanitizeResponses: config.get('security.sanitizeResponses', true),
        maskTokensInLogs: config.get('security.maskTokensInLogs', true),
        maxRequestTokens: config.get('tokenLimits.maxRequest', 4096),
        maxResponseTokens: config.get('tokenLimits.maxResponse', 2048),
    };
}

/**
 * Mask sensitive tokens in text for safe logging
 */
export function maskTokens(text: string): string {
    const config = getSecurityConfig();
    if (!config.maskTokensInLogs) {
        return text;
    }

    let masked = text;
    for (const { pattern, mask } of TOKEN_PATTERNS) {
        masked = masked.replace(pattern, mask);
    }
    return masked;
}

/**
 * Detect if text contains leaked credentials
 * Returns array of detected token types
 */
export function detectLeakedCredentials(text: string): string[] {
    const detected: string[] = [];
    for (const { name, pattern } of TOKEN_PATTERNS) {
        if (pattern.test(text)) {
            detected.push(name);
            // Reset lastIndex for global regex
            pattern.lastIndex = 0;
        }
    }
    return detected;
}

/**
 * Check if text contains prompt injection patterns
 */
export function detectPromptInjection(text: string): boolean {
    return INJECTION_PATTERNS.some(pattern => pattern.test(text));
}

/**
 * Sanitize LLM response for prompt injection attempts
 */
export function sanitizeResponse(response: string): { text: string; warnings: string[] } {
    const config = getSecurityConfig();
    const warnings: string[] = [];

    if (!config.sanitizeResponses) {
        return { text: response, warnings };
    }

    // Check for leaked credentials in response
    const leaked = detectLeakedCredentials(response);
    if (leaked.length > 0) {
        warnings.push(`Response contained potential ${leaked.join(', ')} credential(s) - masked`);
        response = maskTokens(response);
    }

    // Check for prompt injection patterns in response (suspicious if LLM outputs these)
    if (detectPromptInjection(response)) {
        warnings.push('Response contained suspicious prompt injection patterns');
    }

    return { text: response, warnings };
}

/**
 * Validate and sanitize user input before sending to LLM
 */
export function sanitizeInput(input: string): { text: string; warnings: string[] } {
    const config = getSecurityConfig();
    const warnings: string[] = [];

    // Check for credentials in input (warn user)
    const leaked = detectLeakedCredentials(input);
    if (leaked.length > 0 && config.tokenWatchdog) {
        warnings.push(`Input contains ${leaked.join(', ')} credential(s) - consider removing before sending`);
    }

    return { text: input, warnings };
}

/**
 * Estimate token count (rough approximation)
 * Uses ~4 chars per token heuristic for English text
 */
export function estimateTokens(text: string): number {
    // More accurate: split on whitespace and punctuation
    const words = text.split(/[\s\n\r]+/).filter(w => w.length > 0);
    // Average 1.3 tokens per word
    return Math.ceil(words.length * 1.3);
}

/**
 * Truncate text to fit within token limit
 */
export function truncateToTokenLimit(text: string, maxTokens: number): { text: string; truncated: boolean } {
    const estimated = estimateTokens(text);
    if (estimated <= maxTokens) {
        return { text, truncated: false };
    }

    // Rough truncation - 4 chars per token
    const maxChars = maxTokens * 4;
    const truncated = text.substring(0, maxChars);

    // Try to end at a sentence or word boundary
    const lastPeriod = truncated.lastIndexOf('.');
    const lastSpace = truncated.lastIndexOf(' ');
    const cutPoint = lastPeriod > maxChars * 0.8 ? lastPeriod + 1 : lastSpace;

    return {
        text: truncated.substring(0, cutPoint) + '\n[truncated]',
        truncated: true
    };
}

/**
 * BONEBLOB token optimization - apply CIRCLE elimination
 * Reduces token usage by removing eliminated content
 */
export function applyBoneblobOptimization(
    context: string,
    eliminations: string[]
): { text: string; reduction: number } {
    let optimized = context;
    const originalLength = context.length;

    for (const elimination of eliminations) {
        // Remove sentences/phrases matching elimination patterns
        const pattern = new RegExp(`[^.]*\\b${escapeRegex(elimination)}\\b[^.]*\\.?`, 'gi');
        optimized = optimized.replace(pattern, '');
    }

    // Clean up extra whitespace
    optimized = optimized.replace(/\s+/g, ' ').trim();

    const reduction = 1 - (optimized.length / originalLength);
    return { text: optimized, reduction };
}

function escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Security audit log entry
 */
export interface SecurityEvent {
    timestamp: Date;
    type: 'credential_leak' | 'injection_attempt' | 'token_limit' | 'sanitization';
    severity: 'info' | 'warning' | 'critical';
    message: string;
    details?: Record<string, unknown>;
}

const securityLog: SecurityEvent[] = [];
const MAX_LOG_SIZE = 1000;

/**
 * Log a security event
 */
export function logSecurityEvent(event: Omit<SecurityEvent, 'timestamp'>): void {
    const entry: SecurityEvent = {
        ...event,
        timestamp: new Date()
    };

    securityLog.push(entry);

    // Trim log if too large
    if (securityLog.length > MAX_LOG_SIZE) {
        securityLog.splice(0, securityLog.length - MAX_LOG_SIZE);
    }

    // Also output to VS Code output channel if critical
    if (event.severity === 'critical') {
        vscode.window.showWarningMessage(`GentlyOS Security: ${event.message}`);
    }
}

/**
 * Get recent security events
 */
export function getSecurityLog(limit: number = 100): SecurityEvent[] {
    return securityLog.slice(-limit);
}

/**
 * Clear security log
 */
export function clearSecurityLog(): void {
    securityLog.length = 0;
}
