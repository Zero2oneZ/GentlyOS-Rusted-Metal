/**
 * GentlyOS VS Code Extension - Chat View
 *
 * Webview-based chat panel with:
 * - Token-secure messaging
 * - BONEBLOB optimization display
 * - Code insertion
 * - History persistence
 */

import * as vscode from 'vscode';
import { McpClient, ChatMessage, ChatResponse } from '../mcp/client';
import { maskTokens, sanitizeInput, logSecurityEvent } from '../utils/security';

interface WebviewMessage {
    type: 'send' | 'insert' | 'clear' | 'copy';
    content?: string;
    code?: string;
}

export class ChatViewProvider implements vscode.WebviewViewProvider {
    private webviewView?: vscode.WebviewView;
    private history: ChatMessage[] = [];
    private readonly maxHistory = 50;

    constructor(
        private context: vscode.ExtensionContext,
        private mcpClient: McpClient
    ) {
        // Load history from storage
        this.history = context.globalState.get('gentlyos.chatHistory', []);
    }

    resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this.webviewView = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this.context.extensionUri]
        };

        webviewView.webview.html = this.getHtmlContent();

        // Handle messages from webview
        webviewView.webview.onDidReceiveMessage(
            async (message: WebviewMessage) => {
                switch (message.type) {
                    case 'send':
                        if (message.content) {
                            await this.handleUserMessage(message.content);
                        }
                        break;

                    case 'insert':
                        if (message.code) {
                            await this.insertCodeAtCursor(message.code);
                        }
                        break;

                    case 'clear':
                        this.clearHistory();
                        break;

                    case 'copy':
                        if (message.content) {
                            await vscode.env.clipboard.writeText(message.content);
                            vscode.window.showInformationMessage('Copied to clipboard');
                        }
                        break;
                }
            }
        );

        // Send existing history to webview
        this.sendHistoryToWebview();
    }

    /**
     * Send a message programmatically (from commands)
     */
    async sendMessage(content: string): Promise<void> {
        if (!this.webviewView) {
            // Open the chat view first
            await vscode.commands.executeCommand('gentlyos.chat.focus');
            // Wait a moment for view to initialize
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        await this.handleUserMessage(content);
    }

    private async handleUserMessage(content: string): Promise<void> {
        // Sanitize input
        const { text, warnings } = sanitizeInput(content);
        if (warnings.length > 0) {
            this.postMessage({
                type: 'warning',
                message: warnings.join('\n')
            });
        }

        // Add to history
        const userMessage: ChatMessage = { role: 'user', content: text };
        this.history.push(userMessage);

        // Show user message in UI
        this.postMessage({
            type: 'userMessage',
            content: text
        });

        // Show typing indicator
        this.postMessage({ type: 'typing', show: true });

        try {
            // Send to MCP
            const response = await this.mcpClient.chat({
                messages: this.history,
                boneblob: true
            });

            // Add response to history
            const assistantMessage: ChatMessage = {
                role: 'assistant',
                content: response.text
            };
            this.history.push(assistantMessage);

            // Trim history if too long
            if (this.history.length > this.maxHistory) {
                this.history = this.history.slice(-this.maxHistory);
            }

            // Save history
            await this.context.globalState.update('gentlyos.chatHistory', this.history);

            // Show response
            this.postMessage({
                type: 'assistantMessage',
                content: response.text,
                tokensUsed: response.tokens_used,
                tokensSaved: response.tokens_saved,
                provider: response.provider,
                constraints: response.constraints_applied
            });

        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : String(err);
            logSecurityEvent({
                type: 'sanitization',
                severity: 'warning',
                message: `Chat error: ${maskTokens(errorMessage)}`
            });

            this.postMessage({
                type: 'error',
                message: `Error: ${maskTokens(errorMessage)}`
            });
        } finally {
            this.postMessage({ type: 'typing', show: false });
        }
    }

    private async insertCodeAtCursor(code: string): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor');
            return;
        }

        await editor.edit((editBuilder) => {
            editBuilder.insert(editor.selection.active, code);
        });

        vscode.window.showInformationMessage('Code inserted');
    }

    private clearHistory(): void {
        this.history = [];
        this.context.globalState.update('gentlyos.chatHistory', []);
        this.postMessage({ type: 'cleared' });
    }

    private sendHistoryToWebview(): void {
        for (const message of this.history) {
            this.postMessage({
                type: message.role === 'user' ? 'userMessage' : 'assistantMessage',
                content: message.content
            });
        }
    }

    private postMessage(message: Record<string, unknown>): void {
        this.webviewView?.webview.postMessage(message);
    }

    private getHtmlContent(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <title>GentlyOS Chat</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
            background: var(--vscode-sideBar-background);
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        #header {
            padding: 8px 12px;
            border-bottom: 1px solid var(--vscode-panel-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0;
        }
        #header h3 {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            opacity: 0.8;
        }
        #header button {
            background: transparent;
            border: none;
            color: var(--vscode-foreground);
            cursor: pointer;
            opacity: 0.7;
            font-size: 12px;
        }
        #header button:hover {
            opacity: 1;
        }
        #messages {
            flex: 1;
            overflow-y: auto;
            padding: 12px;
        }
        .message {
            margin-bottom: 12px;
            padding: 10px 12px;
            border-radius: 8px;
            max-width: 90%;
            word-wrap: break-word;
        }
        .message.user {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            margin-left: auto;
        }
        .message.assistant {
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
        }
        .message.error {
            background: var(--vscode-inputValidation-errorBackground);
            border: 1px solid var(--vscode-inputValidation-errorBorder);
        }
        .message.warning {
            background: var(--vscode-inputValidation-warningBackground);
            border: 1px solid var(--vscode-inputValidation-warningBorder);
            font-size: 11px;
        }
        .message-meta {
            font-size: 10px;
            opacity: 0.6;
            margin-top: 6px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .message-meta .saved {
            color: var(--vscode-charts-green);
        }
        .message pre {
            background: var(--vscode-textCodeBlock-background);
            padding: 8px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 8px 0;
            font-family: var(--vscode-editor-font-family);
            font-size: 12px;
        }
        .message code {
            font-family: var(--vscode-editor-font-family);
            background: var(--vscode-textCodeBlock-background);
            padding: 2px 4px;
            border-radius: 3px;
        }
        .code-actions {
            display: flex;
            gap: 4px;
            margin-top: 4px;
        }
        .code-actions button {
            font-size: 10px;
            padding: 2px 6px;
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .code-actions button:hover {
            background: var(--vscode-button-secondaryHoverBackground);
        }
        #typing {
            padding: 8px 12px;
            font-size: 11px;
            opacity: 0.6;
            display: none;
        }
        #typing.show {
            display: block;
        }
        #input-container {
            padding: 12px;
            border-top: 1px solid var(--vscode-panel-border);
            flex-shrink: 0;
        }
        #input-container textarea {
            width: 100%;
            min-height: 60px;
            max-height: 200px;
            padding: 8px;
            border: 1px solid var(--vscode-input-border);
            border-radius: 4px;
            background: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            resize: vertical;
        }
        #input-container textarea:focus {
            outline: 1px solid var(--vscode-focusBorder);
        }
        #input-container .hint {
            font-size: 10px;
            opacity: 0.6;
            margin-top: 4px;
        }
    </style>
</head>
<body>
    <div id="header">
        <h3>GentlyOS Chat</h3>
        <button onclick="clearChat()" title="Clear history">Clear</button>
    </div>
    <div id="messages"></div>
    <div id="typing">Thinking...</div>
    <div id="input-container">
        <textarea id="input" placeholder="Ask anything... (Ctrl+Enter to send)" rows="2"></textarea>
        <div class="hint">BONEBLOB optimizes your queries for token efficiency</div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        const messagesEl = document.getElementById('messages');
        const inputEl = document.getElementById('input');
        const typingEl = document.getElementById('typing');

        // Handle Enter key
        inputEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                sendMessage();
            }
        });

        function sendMessage() {
            const content = inputEl.value.trim();
            if (!content) return;

            vscode.postMessage({ type: 'send', content });
            inputEl.value = '';
        }

        function clearChat() {
            vscode.postMessage({ type: 'clear' });
        }

        function insertCode(code) {
            vscode.postMessage({ type: 'insert', code });
        }

        function copyCode(code) {
            vscode.postMessage({ type: 'copy', content: code });
        }

        // Handle messages from extension
        window.addEventListener('message', (event) => {
            const message = event.data;

            switch (message.type) {
                case 'userMessage':
                    addMessage('user', message.content);
                    break;

                case 'assistantMessage':
                    addMessage('assistant', message.content, {
                        tokensUsed: message.tokensUsed,
                        tokensSaved: message.tokensSaved,
                        provider: message.provider,
                        constraints: message.constraints
                    });
                    break;

                case 'error':
                    addMessage('error', message.message);
                    break;

                case 'warning':
                    addMessage('warning', message.message);
                    break;

                case 'typing':
                    typingEl.classList.toggle('show', message.show);
                    break;

                case 'cleared':
                    messagesEl.innerHTML = '';
                    break;
            }
        });

        function addMessage(type, content, meta) {
            const div = document.createElement('div');
            div.className = 'message ' + type;

            // Parse markdown-style code blocks
            const html = parseContent(content);
            div.innerHTML = html;

            // Add meta info for assistant messages
            if (meta && type === 'assistant') {
                const metaDiv = document.createElement('div');
                metaDiv.className = 'message-meta';

                if (meta.provider) {
                    metaDiv.innerHTML += '<span>Provider: ' + meta.provider + '</span>';
                }
                if (meta.tokensUsed) {
                    metaDiv.innerHTML += '<span>Tokens: ' + meta.tokensUsed + '</span>';
                }
                if (meta.tokensSaved) {
                    metaDiv.innerHTML += '<span class="saved">Saved: ' + meta.tokensSaved + '</span>';
                }
                if (meta.constraints && meta.constraints.length > 0) {
                    metaDiv.innerHTML += '<span>BONES: ' + meta.constraints.length + '</span>';
                }

                div.appendChild(metaDiv);
            }

            messagesEl.appendChild(div);
            messagesEl.scrollTop = messagesEl.scrollHeight;
        }

        function parseContent(content) {
            // Escape HTML
            let html = content
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');

            // Code blocks
            html = html.replace(/\`\`\`(\\w*)\\n([\\s\\S]*?)\`\`\`/g, (match, lang, code) => {
                const escapedCode = code.trim();
                const id = 'code-' + Math.random().toString(36).substr(2, 9);
                return '<pre id="' + id + '">' + escapedCode + '</pre>' +
                    '<div class="code-actions">' +
                    '<button onclick="insertCode(document.getElementById(\\'' + id + '\\').textContent)">Insert</button>' +
                    '<button onclick="copyCode(document.getElementById(\\'' + id + '\\').textContent)">Copy</button>' +
                    '</div>';
            });

            // Inline code
            html = html.replace(/\`([^\`]+)\`/g, '<code>$1</code>');

            // Line breaks
            html = html.replace(/\\n/g, '<br>');

            return html;
        }
    </script>
</body>
</html>`;
    }
}
