/**
 * GentlyOS VS Code Extension - MCP Client
 *
 * Connects to gently-mcp server for:
 * - AI completions with BONEBLOB optimization
 * - Tool execution
 * - Alexandria knowledge graph queries
 * - Token-secure communication
 */

import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';
import {
    maskTokens,
    sanitizeResponse,
    sanitizeInput,
    estimateTokens,
    truncateToTokenLimit,
    getSecurityConfig,
    logSecurityEvent,
    SecurityConfig
} from '../utils/security';

export interface McpRequest {
    jsonrpc: '2.0';
    id: number;
    method: string;
    params?: Record<string, unknown>;
}

export interface McpResponse {
    jsonrpc: '2.0';
    id: number;
    result?: unknown;
    error?: {
        code: number;
        message: string;
        data?: unknown;
    };
}

export interface ChatMessage {
    role: 'user' | 'assistant' | 'system';
    content: string;
}

export interface ChatRequest {
    messages: ChatMessage[];
    provider?: string;
    boneblob?: boolean;
    max_tokens?: number;
    temperature?: number;
}

export interface ChatResponse {
    text: string;
    tokens_used: number;
    tokens_saved?: number;
    constraints_applied?: string[];
    provider: string;
}

export interface BoneblobResult {
    optimized_prompt: string;
    eliminations: string[];
    bones_applied: string[];
    reduction_percent: number;
    passes: number;
}

export interface AlexandriaSearchResult {
    concepts: Array<{
        id: string;
        name: string;
        description: string;
        relevance: number;
    }>;
    relationships: Array<{
        from: string;
        to: string;
        kind: string;
    }>;
}

export class McpClient {
    private process: ChildProcess | null = null;
    private requestId = 0;
    private pendingRequests: Map<number, {
        resolve: (value: McpResponse) => void;
        reject: (error: Error) => void;
    }> = new Map();
    private outputChannel: vscode.OutputChannel;
    private securityConfig: SecurityConfig;
    private isConnected = false;
    private buffer = '';

    constructor(private context: vscode.ExtensionContext) {
        this.outputChannel = vscode.window.createOutputChannel('GentlyOS MCP');
        this.securityConfig = getSecurityConfig();
    }

    /**
     * Start the MCP server process
     */
    async start(): Promise<void> {
        if (this.process) {
            return;
        }

        return new Promise((resolve, reject) => {
            try {
                // Try to find gently binary
                const gentlyPath = this.findGentlyBinary();

                this.log(`Starting MCP server: ${gentlyPath} mcp serve`);

                this.process = spawn(gentlyPath, ['mcp', 'serve', '--json'], {
                    stdio: ['pipe', 'pipe', 'pipe'],
                    env: { ...process.env }
                });

                this.process.stdout?.on('data', (data: Buffer) => {
                    this.handleData(data.toString());
                });

                this.process.stderr?.on('data', (data: Buffer) => {
                    this.log(`[stderr] ${maskTokens(data.toString())}`);
                });

                this.process.on('error', (err) => {
                    this.log(`Process error: ${err.message}`);
                    logSecurityEvent({
                        type: 'sanitization',
                        severity: 'warning',
                        message: `MCP process error: ${err.message}`
                    });
                    reject(err);
                });

                this.process.on('exit', (code) => {
                    this.log(`Process exited with code ${code}`);
                    this.isConnected = false;
                    this.process = null;
                });

                // Wait a moment for server to start
                setTimeout(() => {
                    this.isConnected = true;
                    this.log('MCP server started');
                    resolve();
                }, 500);

            } catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Stop the MCP server
     */
    stop(): void {
        if (this.process) {
            this.process.kill();
            this.process = null;
            this.isConnected = false;
            this.log('MCP server stopped');
        }
    }

    /**
     * Send a chat message with full security pipeline
     */
    async chat(request: ChatRequest): Promise<ChatResponse> {
        // Refresh security config
        this.securityConfig = getSecurityConfig();

        // Sanitize input messages
        const sanitizedMessages: ChatMessage[] = [];
        for (const msg of request.messages) {
            const { text, warnings } = sanitizeInput(msg.content);
            if (warnings.length > 0) {
                logSecurityEvent({
                    type: 'credential_leak',
                    severity: 'warning',
                    message: warnings.join('; '),
                    details: { role: msg.role }
                });
            }
            sanitizedMessages.push({ ...msg, content: text });
        }

        // Check token limits
        const totalTokens = sanitizedMessages.reduce(
            (sum, m) => sum + estimateTokens(m.content),
            0
        );

        if (totalTokens > this.securityConfig.maxRequestTokens) {
            logSecurityEvent({
                type: 'token_limit',
                severity: 'warning',
                message: `Request tokens (${totalTokens}) exceeds limit (${this.securityConfig.maxRequestTokens})`
            });

            // Truncate the last user message
            const lastUserIdx = sanitizedMessages.findLastIndex(m => m.role === 'user');
            if (lastUserIdx >= 0) {
                const { text, truncated } = truncateToTokenLimit(
                    sanitizedMessages[lastUserIdx].content,
                    this.securityConfig.maxRequestTokens - totalTokens + estimateTokens(sanitizedMessages[lastUserIdx].content)
                );
                sanitizedMessages[lastUserIdx].content = text;
                if (truncated) {
                    logSecurityEvent({
                        type: 'token_limit',
                        severity: 'info',
                        message: 'Request truncated to fit token limit'
                    });
                }
            }
        }

        // Apply BONEBLOB if enabled
        let boneblobResult: BoneblobResult | undefined;
        if (request.boneblob !== false) {
            const config = vscode.workspace.getConfiguration('gentlyos');
            if (config.get('boneblob.enabled', true)) {
                boneblobResult = await this.applyBoneblob(
                    sanitizedMessages[sanitizedMessages.length - 1].content
                );

                if (boneblobResult) {
                    // Replace last message with optimized version
                    sanitizedMessages[sanitizedMessages.length - 1].content =
                        boneblobResult.optimized_prompt;

                    this.log(`BONEBLOB: ${boneblobResult.reduction_percent.toFixed(1)}% reduction, ${boneblobResult.passes} passes`);
                }
            }
        }

        // Send to MCP
        const response = await this.request<{
            text: string;
            tokens_used: number;
            provider: string;
        }>('tools/call', {
            name: 'chat',
            arguments: {
                messages: sanitizedMessages,
                provider: request.provider,
                max_tokens: request.max_tokens || this.securityConfig.maxResponseTokens,
                temperature: request.temperature || 0.7
            }
        });

        if (!response.result) {
            throw new Error(response.error?.message || 'Chat failed');
        }

        const result = response.result as { text: string; tokens_used: number; provider: string };

        // Sanitize response
        const { text, warnings } = sanitizeResponse(result.text);
        if (warnings.length > 0) {
            logSecurityEvent({
                type: 'sanitization',
                severity: 'warning',
                message: warnings.join('; ')
            });
        }

        return {
            text,
            tokens_used: result.tokens_used,
            tokens_saved: boneblobResult
                ? Math.round(estimateTokens(request.messages[request.messages.length - 1].content) *
                    boneblobResult.reduction_percent / 100)
                : undefined,
            constraints_applied: boneblobResult?.bones_applied,
            provider: result.provider
        };
    }

    /**
     * Apply BONEBLOB optimization
     */
    async applyBoneblob(prompt: string): Promise<BoneblobResult | undefined> {
        const config = vscode.workspace.getConfiguration('gentlyos');
        const passes = config.get('boneblob.passes', 5);

        try {
            const response = await this.request<BoneblobResult>('tools/call', {
                name: 'bbbcp_optimize',
                arguments: {
                    prompt,
                    passes,
                    return_eliminations: true
                }
            });

            if (response.result) {
                return response.result as BoneblobResult;
            }
        } catch (err) {
            this.log(`BONEBLOB error: ${err}`);
        }

        return undefined;
    }

    /**
     * Search Alexandria knowledge graph
     */
    async searchAlexandria(query: string): Promise<AlexandriaSearchResult> {
        const { text } = sanitizeInput(query);

        const response = await this.request<AlexandriaSearchResult>('tools/call', {
            name: 'alexandria_search',
            arguments: {
                query: text,
                limit: 20
            }
        });

        if (response.error) {
            throw new Error(response.error.message);
        }

        return response.result as AlexandriaSearchResult;
    }

    /**
     * Execute an MCP tool
     */
    async executeTool(name: string, args: Record<string, unknown>): Promise<unknown> {
        const response = await this.request('tools/call', {
            name,
            arguments: args
        });

        if (response.error) {
            throw new Error(response.error.message);
        }

        return response.result;
    }

    /**
     * List available tools
     */
    async listTools(): Promise<Array<{ name: string; description: string }>> {
        const response = await this.request<Array<{ name: string; description: string }>>('tools/list', {});

        if (response.error) {
            throw new Error(response.error.message);
        }

        return response.result as Array<{ name: string; description: string }>;
    }

    /**
     * Get security status
     */
    async getSecurityStatus(): Promise<{
        fafo_mode: string;
        strikes: number;
        threats_blocked: number;
        token_leaks_detected: number;
    }> {
        const response = await this.request('tools/call', {
            name: 'security_status',
            arguments: {}
        });

        if (response.error) {
            // Return default if security tool not available
            return {
                fafo_mode: 'passive',
                strikes: 0,
                threats_blocked: 0,
                token_leaks_detected: 0
            };
        }

        return response.result as {
            fafo_mode: string;
            strikes: number;
            threats_blocked: number;
            token_leaks_detected: number;
        };
    }

    private async request<T>(method: string, params?: Record<string, unknown>): Promise<McpResponse> {
        if (!this.isConnected) {
            await this.start();
        }

        const id = ++this.requestId;
        const request: McpRequest = {
            jsonrpc: '2.0',
            id,
            method,
            params
        };

        return new Promise((resolve, reject) => {
            this.pendingRequests.set(id, { resolve, reject });

            const json = JSON.stringify(request) + '\n';
            this.log(`[request] ${maskTokens(json.trim())}`);

            if (this.process?.stdin) {
                this.process.stdin.write(json);
            } else {
                reject(new Error('MCP process not running'));
            }

            // Timeout after 30 seconds
            setTimeout(() => {
                if (this.pendingRequests.has(id)) {
                    this.pendingRequests.delete(id);
                    reject(new Error('Request timeout'));
                }
            }, 30000);
        });
    }

    private handleData(data: string): void {
        this.buffer += data;

        // Process complete JSON lines
        const lines = this.buffer.split('\n');
        this.buffer = lines.pop() || '';

        for (const line of lines) {
            if (line.trim()) {
                try {
                    const response = JSON.parse(line) as McpResponse;
                    this.log(`[response] ${maskTokens(line)}`);

                    const pending = this.pendingRequests.get(response.id);
                    if (pending) {
                        this.pendingRequests.delete(response.id);
                        pending.resolve(response);
                    }
                } catch (err) {
                    this.log(`[parse error] ${line}`);
                }
            }
        }
    }

    private findGentlyBinary(): string {
        // Check common locations
        const locations = [
            '/usr/local/bin/gently',
            '/usr/bin/gently',
            `${process.env.HOME}/.cargo/bin/gently`,
            `${process.env.HOME}/.local/bin/gently`,
            'gently' // PATH lookup
        ];

        // On Windows
        if (process.platform === 'win32') {
            locations.unshift(
                `${process.env.LOCALAPPDATA}\\Programs\\GentlyOS\\gently.exe`,
                `${process.env.ProgramFiles}\\GentlyOS\\gently.exe`
            );
        }

        // For now, just return 'gently' and let spawn find it in PATH
        return 'gently';
    }

    private log(message: string): void {
        const timestamp = new Date().toISOString();
        this.outputChannel.appendLine(`[${timestamp}] ${message}`);
    }

    dispose(): void {
        this.stop();
        this.outputChannel.dispose();
    }
}
