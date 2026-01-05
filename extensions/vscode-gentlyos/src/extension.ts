/**
 * GentlyOS VS Code Extension
 *
 * Main entry point providing:
 * - AI-powered code assistance with BONEBLOB optimization
 * - Token-secure communication via MCP
 * - Living Feed integration
 * - Alexandria knowledge graph
 */

import * as vscode from 'vscode';
import { McpClient } from './mcp/client';
import { ChatViewProvider } from './views/chatView';
import {
    getSecurityConfig,
    getSecurityLog,
    logSecurityEvent,
    detectLeakedCredentials,
    maskTokens
} from './utils/security';

let mcpClient: McpClient;
let statusBarItem: vscode.StatusBarItem;
let boneblobEnabled = true;

export async function activate(context: vscode.ExtensionContext) {
    console.log('GentlyOS extension activating...');

    // Initialize MCP client
    mcpClient = new McpClient(context);

    // Auto-start MCP if configured
    const config = vscode.workspace.getConfiguration('gentlyos');
    if (config.get('mcp.autoStart', true)) {
        try {
            await mcpClient.start();
        } catch (err) {
            vscode.window.showWarningMessage(
                `GentlyOS: Could not start MCP server. Make sure 'gently' is installed.`
            );
        }
    }

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    updateStatusBar();
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Register chat view provider
    const chatViewProvider = new ChatViewProvider(context, mcpClient);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('gentlyos.chat', chatViewProvider)
    );

    // Register commands
    registerCommands(context, chatViewProvider);

    // Register token watchdog for editor
    registerTokenWatchdog(context);

    // Configuration change listener
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('gentlyos')) {
                updateStatusBar();
            }
        })
    );

    // Add MCP client to subscriptions for disposal
    context.subscriptions.push({
        dispose: () => mcpClient.dispose()
    });

    console.log('GentlyOS extension activated');
}

function registerCommands(
    context: vscode.ExtensionContext,
    chatViewProvider: ChatViewProvider
) {
    // Chat command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.chat', () => {
            vscode.commands.executeCommand('gentlyos.chat.focus');
        })
    );

    // Explain code command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.explain', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                return;
            }

            const selection = editor.selection;
            const text = editor.document.getText(selection);

            if (!text) {
                vscode.window.showInformationMessage('Please select code to explain');
                return;
            }

            await chatViewProvider.sendMessage(
                `Explain this code:\n\n\`\`\`${editor.document.languageId}\n${text}\n\`\`\``
            );
        })
    );

    // Refactor command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.refactor', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                return;
            }

            const selection = editor.selection;
            const text = editor.document.getText(selection);

            if (!text) {
                vscode.window.showInformationMessage('Please select code to refactor');
                return;
            }

            await chatViewProvider.sendMessage(
                `Suggest refactoring for this code. Provide improved version with explanation:\n\n\`\`\`${editor.document.languageId}\n${text}\n\`\`\``
            );
        })
    );

    // Generate tests command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.test', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                return;
            }

            const selection = editor.selection;
            let text = editor.document.getText(selection);

            if (!text) {
                // If no selection, use the whole file
                text = editor.document.getText();
            }

            await chatViewProvider.sendMessage(
                `Generate unit tests for this code:\n\n\`\`\`${editor.document.languageId}\n${text}\n\`\`\``
            );
        })
    );

    // Toggle BONEBLOB command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.boneblob.toggle', async () => {
            boneblobEnabled = !boneblobEnabled;
            const config = vscode.workspace.getConfiguration('gentlyos');
            await config.update('boneblob.enabled', boneblobEnabled, true);
            updateStatusBar();
            vscode.window.showInformationMessage(
                `BONEBLOB ${boneblobEnabled ? 'enabled' : 'disabled'}`
            );
        })
    );

    // Show Living Feed command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.feed.show', async () => {
            try {
                const result = await mcpClient.executeTool('feed_list', { limit: 20 });
                const items = result as Array<{ name: string; heat: number; content: string }>;

                const quickPickItems = items.map((item) => ({
                    label: `${getHeatEmoji(item.heat)} ${item.name}`,
                    description: `Heat: ${item.heat.toFixed(2)}`,
                    detail: item.content.substring(0, 100)
                }));

                await vscode.window.showQuickPick(quickPickItems, {
                    placeHolder: 'Living Feed Items'
                });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to load feed: ${err}`);
            }
        })
    );

    // Search Alexandria command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.alexandria.search', async () => {
            const query = await vscode.window.showInputBox({
                prompt: 'Search Knowledge Graph',
                placeHolder: 'Enter search query...'
            });

            if (!query) {
                return;
            }

            try {
                const results = await mcpClient.searchAlexandria(query);

                const items = results.concepts.map((c) => ({
                    label: c.name,
                    description: `Relevance: ${(c.relevance * 100).toFixed(0)}%`,
                    detail: c.description
                }));

                await vscode.window.showQuickPick(items, {
                    placeHolder: `Found ${results.concepts.length} concepts`
                });
            } catch (err) {
                vscode.window.showErrorMessage(`Search failed: ${err}`);
            }
        })
    );

    // Security status command
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.security.status', async () => {
            try {
                const status = await mcpClient.getSecurityStatus();
                const localLog = getSecurityLog(10);

                const message = [
                    `FAFO Mode: ${status.fafo_mode}`,
                    `Strikes: ${status.strikes}`,
                    `Threats Blocked: ${status.threats_blocked}`,
                    `Token Leaks Detected: ${status.token_leaks_detected}`,
                    '',
                    `Recent Events (${localLog.length}):`,
                    ...localLog.slice(-5).map(e =>
                        `  [${e.severity}] ${e.message}`
                    )
                ].join('\n');

                vscode.window.showInformationMessage(message, { modal: true });
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to get security status: ${err}`);
            }
        })
    );

    // Status bar click - show menu
    context.subscriptions.push(
        vscode.commands.registerCommand('gentlyos.showMenu', async () => {
            const items = [
                { label: '$(comment-discussion) Open Chat', command: 'gentlyos.chat' },
                { label: '$(symbol-boolean) Toggle BONEBLOB', command: 'gentlyos.boneblob.toggle' },
                { label: '$(flame) Show Living Feed', command: 'gentlyos.feed.show' },
                { label: '$(search) Search Knowledge', command: 'gentlyos.alexandria.search' },
                { label: '$(shield) Security Status', command: 'gentlyos.security.status' }
            ];

            const selected = await vscode.window.showQuickPick(items, {
                placeHolder: 'GentlyOS Actions'
            });

            if (selected) {
                vscode.commands.executeCommand(selected.command);
            }
        })
    );

    statusBarItem.command = 'gentlyos.showMenu';
}

/**
 * Register token watchdog to detect credentials in editor
 */
function registerTokenWatchdog(context: vscode.ExtensionContext) {
    const securityConfig = getSecurityConfig();

    if (!securityConfig.tokenWatchdog) {
        return;
    }

    // Diagnostic collection for credential warnings
    const diagnostics = vscode.languages.createDiagnosticCollection('gentlyos-security');
    context.subscriptions.push(diagnostics);

    // Check on document change
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            checkDocumentForCredentials(event.document, diagnostics);
        })
    );

    // Check on document open
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((document) => {
            checkDocumentForCredentials(document, diagnostics);
        })
    );

    // Check all open documents
    vscode.workspace.textDocuments.forEach((document) => {
        checkDocumentForCredentials(document, diagnostics);
    });
}

function checkDocumentForCredentials(
    document: vscode.TextDocument,
    diagnostics: vscode.DiagnosticCollection
) {
    // Skip non-file schemes and certain file types
    if (document.uri.scheme !== 'file') {
        return;
    }

    const fileName = document.fileName.toLowerCase();
    if (fileName.endsWith('.env.example') || fileName.endsWith('.env.sample')) {
        return;
    }

    const text = document.getText();
    const leaked = detectLeakedCredentials(text);

    if (leaked.length === 0) {
        diagnostics.delete(document.uri);
        return;
    }

    // Find positions of leaked credentials
    const diags: vscode.Diagnostic[] = [];

    // Patterns for credential detection with positions
    const patterns: { name: string; pattern: RegExp }[] = [
        { name: 'Anthropic API key', pattern: /sk-ant-api\d{2}-[A-Za-z0-9_-]{95}/g },
        { name: 'OpenAI API key', pattern: /sk-[A-Za-z0-9]{48}/g },
        { name: 'GitHub token', pattern: /gh[po]_[A-Za-z0-9]{36}/g },
        { name: 'AWS access key', pattern: /AKIA[A-Z0-9]{16}/g },
    ];

    for (const { name, pattern } of patterns) {
        let match;
        while ((match = pattern.exec(text)) !== null) {
            const startPos = document.positionAt(match.index);
            const endPos = document.positionAt(match.index + match[0].length);
            const range = new vscode.Range(startPos, endPos);

            const diagnostic = new vscode.Diagnostic(
                range,
                `Potential ${name} detected. Consider using environment variables or gently vault.`,
                vscode.DiagnosticSeverity.Warning
            );
            diagnostic.source = 'GentlyOS Security';
            diagnostic.code = 'credential-leak';
            diags.push(diagnostic);
        }
    }

    if (diags.length > 0) {
        diagnostics.set(document.uri, diags);

        logSecurityEvent({
            type: 'credential_leak',
            severity: 'warning',
            message: `Found ${diags.length} potential credential(s) in ${document.fileName}`,
            details: { file: document.fileName, count: diags.length }
        });
    }
}

function updateStatusBar() {
    const config = vscode.workspace.getConfiguration('gentlyos');
    boneblobEnabled = config.get('boneblob.enabled', true);
    const provider = config.get('provider', 'claude');

    const boneblobIcon = boneblobEnabled ? '$(check)' : '$(x)';
    statusBarItem.text = `$(hubot) GentlyOS`;
    statusBarItem.tooltip = [
        `Provider: ${provider}`,
        `BONEBLOB: ${boneblobEnabled ? 'ON' : 'OFF'}`,
        '',
        'Click for menu'
    ].join('\n');
}

function getHeatEmoji(heat: number): string {
    if (heat >= 0.8) return '🔥';
    if (heat >= 0.6) return '🌡️';
    if (heat >= 0.4) return '☀️';
    if (heat >= 0.2) return '🌤️';
    return '❄️';
}

export function deactivate() {
    mcpClient?.dispose();
}
