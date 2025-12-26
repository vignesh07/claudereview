import type { ParsedSession, ParsedMessage, SessionMetadata } from './types.ts';
import { diffLines } from './diff.ts';
import { BROWSER_CRYPTO_CODE } from './crypto.ts';

/**
 * Render a parsed session to self-contained HTML
 */
export function renderSessionToHtml(session: ParsedSession, options?: RenderOptions): string {
  const {
    encrypted = false,
    encryptedBlob,
    iv,
    salt,
    theme = 'dark',
    embed = false,
  } = options || {};

  const sessionDataForViewer = encrypted
    ? { encrypted: true, encryptedBlob, iv, salt, metadata: session.metadata, title: session.title, id: session.id }
    : session;

  return `<!DOCTYPE html>
<html lang="en" data-theme="${theme}"${embed ? ' data-embed="true"' : ''}>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(session.title)} | claudereview</title>
  ${renderOgTags(session)}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>${CSS}${LIGHT_MODE_CSS}</style>
</head>
<body>
  <div id="app">
    <!-- Search overlay -->
    <div id="search-overlay" class="search-overlay hidden">
      <div class="search-box">
        <span class="search-icon">⌘F</span>
        <input type="text" id="search-input" placeholder="Search in session..." autocomplete="off">
        <span id="search-count" class="search-count"></span>
        <button id="search-prev" class="search-nav" title="Previous (↑)">↑</button>
        <button id="search-next" class="search-nav" title="Next (↓)">↓</button>
        <button id="search-close" class="search-close" title="Close (Esc)">×</button>
      </div>
    </div>

    <!-- Password prompt (only shown for encrypted private sessions) -->
    <div id="password-prompt" class="password-prompt ${encrypted && salt ? '' : 'hidden'}">
      <div class="prompt-container">
        <div class="terminal-window">
          <div class="terminal-header">
            <span class="terminal-dot red"></span>
            <span class="terminal-dot yellow"></span>
            <span class="terminal-dot green"></span>
            <span class="terminal-title">authenticate</span>
          </div>
          <div class="terminal-body">
            <div class="prompt-line">
              <span class="prompt-symbol">❯</span>
              <span class="prompt-text">This session is password protected</span>
            </div>
            <form id="password-form" class="password-form">
              <div class="input-line">
                <span class="prompt-symbol dimmed">password:</span>
                <input type="password" id="password-input" autocomplete="off" autofocus>
              </div>
              <div id="password-error" class="error-line hidden">
                <span class="error-symbol">✗</span>
                <span class="error-text">Incorrect password</span>
              </div>
              <button type="submit" class="submit-btn">unlock →</button>
            </form>
          </div>
        </div>
      </div>
    </div>

    <!-- Main viewer -->
    <div id="viewer" class="${encrypted && salt ? 'hidden' : ''}">
      ${renderHeader(session)}

      <div class="session-container">
        <main id="messages" class="messages">
          ${encrypted ? '' : renderMessages(session.messages)}
        </main>
      </div>

      <footer class="viewer-footer">
        <div class="footer-hint">
          <kbd>⌘</kbd><kbd>F</kbd> search
          <span class="sep">·</span>
          <kbd>J</kbd><kbd>K</kbd> navigate
          <span class="sep">·</span>
          <kbd>C</kbd> collapse all
        </div>
        <a href="https://claudereview.com" class="footer-brand" target="_blank">
          <span class="brand-icon">◈</span> claudereview
        </a>
      </footer>
    </div>
  </div>

  <script id="session-data" type="application/json">${escapeJsonForHtml(JSON.stringify(sessionDataForViewer))}</script>
  ${encrypted ? `<script>${BROWSER_CRYPTO_CODE}</script>` : ''}
  <script>${VIEWER_JS}</script>
</body>
</html>`;
}

interface RenderOptions {
  encrypted?: boolean;
  encryptedBlob?: string;
  iv?: string;
  salt?: string;
  theme?: 'dark' | 'light';
  embed?: boolean;
}

function renderOgTags(session: ParsedSession): string {
  const toolList = Object.entries(session.metadata.tools)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([name, count]) => `${name}×${count}`)
    .join(' ');

  const description = `${session.metadata.messageCount} messages · ${formatDuration(session.metadata.durationSeconds)}${toolList ? ` · ${toolList}` : ''}`;

  return `
  <meta property="og:type" content="website">
  <meta property="og:title" content="${escapeHtml(truncate(session.title, 60))}">
  <meta property="og:description" content="${escapeHtml(description)}">
  <meta property="og:site_name" content="claudereview">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="${escapeHtml(truncate(session.title, 60))}">
  <meta name="twitter:description" content="${escapeHtml(description)}">
  <meta name="theme-color" content="#0a0a0a">`;
}

function renderHeader(session: ParsedSession): string {
  // Clickable tool badges that jump to first instance
  const toolsSummary = Object.entries(session.metadata.tools)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => `<button class="tool-badge tool-nav" data-tool="${escapeHtml(name)}">${escapeHtml(name)}<span class="tool-count">${count}</span></button>`)
    .join('');

  // Token/cost estimate
  const tokens = session.metadata.estimatedTokens || 0;
  const costEstimate = tokens > 0 ? `~${Math.round(tokens / 1000)}K tokens` : '';

  // Key moments summary
  const keyMoments = renderKeyMoments(session.metadata);

  return `
  <header class="viewer-header">
    <div class="header-top">
      <a href="https://claudereview.com" class="logo" target="_blank">
        <span class="logo-icon">◈</span>
        <span class="logo-text">claudereview</span>
      </a>
      <div class="header-actions">
        <button id="theme-toggle" class="action-btn labeled" title="Toggle light/dark theme">
          <span class="action-icon theme-icon">◐</span>
          <span class="action-label">Theme</span>
        </button>
        <button id="collapse-all-btn" class="action-btn labeled" title="Collapse all tool outputs (C)">
          <span class="action-icon">−</span>
          <span class="action-label">Collapse</span>
        </button>
        <button id="expand-all-btn" class="action-btn labeled" title="Expand all tool outputs (E)">
          <span class="action-icon">+</span>
          <span class="action-label">Expand</span>
        </button>
        <button id="copy-link-btn" class="action-btn labeled" title="Copy shareable link">
          <span class="action-icon">⎘</span>
          <span class="action-label">Copy</span>
        </button>
      </div>
    </div>

    <div class="session-info">
      <div class="title-row">
        <h1 class="session-title" id="session-title" contenteditable="true" spellcheck="false">${escapeHtml(truncate(session.title, 120))}</h1>
        <button id="edit-title-btn" class="edit-title-btn" title="Edit title">✎</button>
      </div>
      ${renderGitContext(session.metadata)}
      <div class="session-meta">
        <span class="meta-item">
          <span class="meta-icon">💬</span>
          ${session.metadata.messageCount} messages
        </span>
        <span class="meta-item">
          <span class="meta-icon">⏱</span>
          ${formatDuration(session.metadata.durationSeconds)}
        </span>
        ${costEstimate ? `<span class="meta-item token-count" title="Estimated tokens"><span class="meta-icon">⚡</span>${costEstimate}</span>` : ''}
        <span class="meta-item session-id">
          ${session.id.slice(0, 8)}
        </span>
      </div>
      ${toolsSummary ? `<div class="tools-used">${toolsSummary}</div>` : ''}
    </div>
    ${keyMoments}
  </header>`;
}

function renderGitContext(metadata: SessionMetadata): string {
  const { gitRepo, gitBranch, gitCommit } = metadata;
  if (!gitRepo && !gitBranch && !gitCommit) return '';

  let parts: string[] = [];

  if (gitRepo) {
    // Try to make a clickable link
    const repoUrl = gitRepo.replace(/\.git$/, '').replace(/^git@github\.com:/, 'https://github.com/');
    const repoName = repoUrl.split('/').slice(-2).join('/');
    parts.push(`<a href="${repoUrl}" target="_blank" class="git-link">${escapeHtml(repoName)}</a>`);
  }

  if (gitBranch) {
    parts.push(`<span class="git-branch">${escapeHtml(gitBranch)}</span>`);
  }

  if (gitCommit) {
    const shortCommit = gitCommit.slice(0, 7);
    if (gitRepo) {
      const repoUrl = gitRepo.replace(/\.git$/, '').replace(/^git@github\.com:/, 'https://github.com/');
      parts.push(`<a href="${repoUrl}/commit/${gitCommit}" target="_blank" class="git-commit">${shortCommit}</a>`);
    } else {
      parts.push(`<span class="git-commit">${shortCommit}</span>`);
    }
  }

  return `<div class="git-context">${parts.join('<span class="git-sep">/</span>')}</div>`;
}

function renderKeyMoments(metadata: SessionMetadata): string {
  const { filesCreated, filesModified, commandsRun } = metadata;

  const hasKeyMoments = (filesCreated?.length || 0) + (filesModified?.length || 0) + (commandsRun?.length || 0) > 0;
  if (!hasKeyMoments) return '';

  let content = '<details class="key-moments"><summary class="key-moments-toggle"><span class="km-icon">▸</span> Key Moments</summary><div class="key-moments-content">';

  if (filesCreated && filesCreated.length > 0) {
    content += `<div class="km-section"><span class="km-label">Files Created:</span>`;
    content += filesCreated.slice(0, 10).map(f => `<span class="km-file created">${escapeHtml(basename(f))}</span>`).join('');
    if (filesCreated.length > 10) content += `<span class="km-more">+${filesCreated.length - 10} more</span>`;
    content += '</div>';
  }

  if (filesModified && filesModified.length > 0) {
    content += `<div class="km-section"><span class="km-label">Files Modified:</span>`;
    content += filesModified.slice(0, 10).map(f => `<span class="km-file modified">${escapeHtml(basename(f))}</span>`).join('');
    if (filesModified.length > 10) content += `<span class="km-more">+${filesModified.length - 10} more</span>`;
    content += '</div>';
  }

  if (commandsRun && commandsRun.length > 0) {
    content += `<div class="km-section"><span class="km-label">Commands:</span>`;
    content += commandsRun.slice(0, 5).map(c => `<code class="km-cmd">${escapeHtml(truncate(c, 50))}</code>`).join('');
    if (commandsRun.length > 5) content += `<span class="km-more">+${commandsRun.length - 5} more</span>`;
    content += '</div>';
  }

  content += '</div></details>';
  return content;
}

function basename(path: string): string {
  return path.split('/').pop() || path;
}

function renderMessages(messages: ParsedMessage[]): string {
  const groups = groupMessages(messages);
  return groups.map((group, idx) => renderMessageGroup(group, idx)).join('\n');
}

interface MessageGroup {
  type: 'human' | 'assistant';
  messages: ParsedMessage[];
}

function groupMessages(messages: ParsedMessage[]): MessageGroup[] {
  const groups: MessageGroup[] = [];
  let currentGroup: MessageGroup | null = null;

  for (const msg of messages) {
    const groupType = msg.type === 'human' ? 'human' : 'assistant';

    if (!currentGroup || currentGroup.type !== groupType) {
      if (currentGroup) groups.push(currentGroup);
      currentGroup = { type: groupType, messages: [] };
    }
    currentGroup.messages.push(msg);
  }

  if (currentGroup) groups.push(currentGroup);
  return groups;
}

function renderMessageGroup(group: MessageGroup, index: number): string {
  if (group.type === 'human') {
    return group.messages.map(msg => renderHumanMessage(msg)).join('\n');
  } else {
    return `
    <div class="assistant-group" data-group="${index}">
      <div class="assistant-indicator">
        <span class="indicator-icon">●</span>
        <span class="indicator-text">Claude</span>
      </div>
      <div class="assistant-content">
        ${group.messages.map(msg => renderAssistantItem(msg)).join('\n')}
      </div>
    </div>`;
  }
}

function renderHumanMessage(message: ParsedMessage): string {
  const content = message.content || '';
  const isLong = content.length > 500;

  return `
  <div class="message human-message" id="${message.id}">
    <div class="message-gutter">
      <span class="human-prompt">❯</span>
    </div>
    <div class="message-body">
      <div class="human-content ${isLong ? 'collapsible collapsed' : ''}" ${isLong ? 'data-full-height="auto"' : ''}>
        ${formatContent(content)}
      </div>
      ${isLong ? `<button class="expand-toggle" data-target="${message.id}">Show more ↓</button>` : ''}
      <div class="message-meta">
        <span class="meta-time">${formatTime(message.timestamp)}</span>
        <button class="copy-link-inline" data-id="${message.id}" title="Copy link">🔗</button>
      </div>
    </div>
  </div>`;
}

function renderAssistantItem(message: ParsedMessage): string {
  switch (message.type) {
    case 'assistant':
      return renderAssistantText(message);
    case 'tool_call':
      return renderToolCall(message);
    case 'tool_result':
      return renderToolResult(message);
    default:
      return '';
  }
}

function renderAssistantText(message: ParsedMessage): string {
  const content = message.content || '';
  if (!content.trim()) return '';

  return `
  <div class="assistant-text" id="${message.id}">
    ${formatContent(content)}
  </div>`;
}

function renderToolCall(message: ParsedMessage): string {
  const name = message.toolName || 'Tool';
  const icon = getToolIcon(name);
  const summary = formatToolSummary(name, message.toolInput);

  // For Edit tool, show diff inline
  let diffView = '';
  if (name === 'Edit' && message.toolInput) {
    const oldStr = String(message.toolInput.old_string || '');
    const newStr = String(message.toolInput.new_string || '');
    if (oldStr && newStr && oldStr !== newStr) {
      diffView = `<div class="edit-diff">${formatDiffHtml(oldStr, newStr)}</div>`;
    }
  }

  return `
  <div class="tool-call" id="${message.id}" data-tool-name="${escapeHtml(name)}">
    <div class="tool-header">
      <span class="tool-icon">${icon}</span>
      <span class="tool-name">${escapeHtml(name)}</span>
      <span class="tool-summary">${escapeHtml(summary)}</span>
    </div>
    ${diffView}
  </div>`;
}

function formatDiffHtml(oldStr: string, newStr: string): string {
  const lines = diffLines(oldStr, newStr);
  let html = '<div class="diff-view">';

  for (const line of lines) {
    const prefix = line.type === 'add' ? '+' : line.type === 'remove' ? '-' : ' ';
    const className = `diff-line diff-${line.type}`;
    const escapedContent = escapeHtml(line.content);
    html += `<div class="${className}"><span class="diff-prefix">${prefix}</span><span class="diff-content">${escapedContent}</span></div>`;
  }

  html += '</div>';
  return html;
}

function renderToolResult(message: ParsedMessage): string {
  const output = message.toolOutput || message.content || '';
  const lines = output.split('\n');
  const lineCount = lines.length;
  const isLong = lineCount > 15;
  const isError = message.isError;

  // Detect language for syntax highlighting
  const language = detectLanguage(output);

  const preview = isLong ? lines.slice(0, 10).join('\n') : output;

  return `
  <div class="tool-result ${isError ? 'error' : ''} ${isLong ? 'collapsible collapsed' : ''}" id="${message.id}">
    <div class="result-content">
      <pre class="output-pre"><code class="language-${language}">${escapeHtml(isLong ? preview : output)}</code></pre>
    </div>
    ${isLong ? `
    <div class="result-expand" data-full="${escapeAttr(output)}">
      <button class="expand-btn">↓ ${lineCount - 10} more lines</button>
    </div>
    ` : ''}
  </div>`;
}

function formatToolSummary(name: string, input?: Record<string, unknown>): string {
  if (!input) return '';

  switch (name) {
    case 'Bash':
      const cmd = String(input.command || '');
      return cmd.length > 80 ? cmd.slice(0, 80) + '...' : cmd;
    case 'Read':
      return String(input.file_path || '');
    case 'Write':
      return String(input.file_path || '');
    case 'Edit':
      return String(input.file_path || '');
    case 'Glob':
      return String(input.pattern || '');
    case 'Grep':
      return String(input.pattern || '');
    case 'Task':
      return String(input.description || '').slice(0, 60);
    default:
      const str = JSON.stringify(input);
      return str.length > 60 ? str.slice(0, 60) + '...' : str;
  }
}

function getToolIcon(name: string): string {
  const icons: Record<string, string> = {
    'Bash': '$',
    'Read': '◇',
    'Write': '◆',
    'Edit': '✎',
    'Glob': '⊛',
    'Grep': '⊙',
    'Task': '⊳',
    'WebFetch': '↗',
    'WebSearch': '◎',
    'TodoWrite': '☑',
  };
  return icons[name] || '⊡';
}

function detectLanguage(content: string): string {
  // Simple heuristics for syntax highlighting
  if (content.includes('function ') || content.includes('const ') || content.includes('let ')) return 'javascript';
  if (content.includes('def ') || content.includes('import ') && content.includes(':')) return 'python';
  if (content.includes('package ') || content.includes('func ')) return 'go';
  if (content.includes('fn ') || content.includes('let mut')) return 'rust';
  if (content.startsWith('{') || content.startsWith('[')) return 'json';
  if (content.includes('<!DOCTYPE') || content.includes('<html')) return 'html';
  if (content.includes('SELECT ') || content.includes('CREATE TABLE')) return 'sql';
  return 'plaintext';
}

function formatContent(content: string): string {
  if (!content) return '';

  // First escape all HTML to prevent injection
  let escaped = escapeHtml(content);

  // Replace code blocks (``` blocks) - these were escaped, so match escaped backticks
  // Actually, since we escaped first, we need to work with the escaped version
  // Let's do this differently - process before escaping for code blocks

  // Start over with a safer approach
  let result = '';
  let remaining = content;

  // Extract code blocks first
  const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
  let lastIndex = 0;
  let match;

  while ((match = codeBlockRegex.exec(content)) !== null) {
    // Add text before this code block (escaped)
    const textBefore = content.slice(lastIndex, match.index);
    result += formatTextContent(textBefore);

    // Add the code block
    const language = match[1] || 'plaintext';
    const code = match[2] || '';
    result += `<pre class="code-block"><code class="language-${language}">${escapeHtml(code.trim())}</code></pre>`;

    lastIndex = match.index + match[0].length;
  }

  // Add remaining text after last code block
  result += formatTextContent(content.slice(lastIndex));

  return result;
}

function formatTextContent(text: string): string {
  if (!text) return '';

  let escaped = escapeHtml(text);

  // Replace inline code (single backticks) - backticks are not escaped by escapeHtml
  escaped = escaped.replace(/`([^`]+)`/g, (_, code) => {
    return `<code class="inline-code">${code}</code>`;
  });

  // Split into paragraphs and add breaks
  return escaped
    .split('\n\n')
    .map(para => {
      if (!para.trim()) return '';
      return `<p>${para.replace(/\n/g, '<br>')}</p>`;
    })
    .filter(p => p)
    .join('\n');
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.round((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

function formatTime(timestamp: string): string {
  try {
    return new Date(timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  } catch {
    return '';
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeAttr(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '&#10;');
}

function truncate(str: string, max: number): string {
  if (str.length <= max) return str;
  return str.slice(0, max - 1) + '…';
}

function escapeJsonForHtml(jsonStr: string): string {
  // Escape sequences that could break out of script tags
  return jsonStr
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
}

// ============================================================================
// CSS - Terminal/IDE Aesthetic
// ============================================================================

const CSS = `
/* ========== CSS Variables ========== */
:root {
  /* Base colors - true terminal dark */
  --bg-primary: #0a0a0a;
  --bg-secondary: #111111;
  --bg-tertiary: #1a1a1a;
  --bg-elevated: #222222;

  /* Text hierarchy */
  --text-primary: #e0e0e0;
  --text-secondary: #888888;
  --text-muted: #555555;
  --text-bright: #ffffff;

  /* Accent colors - ANSI-inspired */
  --accent-green: #4ec970;
  --accent-blue: #5c9fd7;
  --accent-purple: #b38bff;
  --accent-yellow: #e6c07b;
  --accent-red: #e06c75;
  --accent-cyan: #56c8d8;
  --accent-orange: #d19a66;

  /* Semantic */
  --human-accent: var(--accent-green);
  --claude-accent: var(--accent-purple);
  --tool-accent: var(--accent-blue);
  --error-accent: var(--accent-red);

  /* Borders */
  --border-subtle: #2a2a2a;
  --border-medium: #3a3a3a;

  /* Fonts */
  --font-mono: 'JetBrains Mono', 'IBM Plex Mono', 'SF Mono', Menlo, monospace;
  --font-size-xs: 11px;
  --font-size-sm: 12px;
  --font-size-base: 13px;
  --font-size-lg: 14px;

  /* Spacing */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;
  --space-6: 32px;

  /* Misc */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --transition-fast: 0.15s ease;
}

/* ========== Reset & Base ========== */
*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  font-size: 16px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  font-family: var(--font-mono);
  font-size: var(--font-size-base);
  line-height: 1.6;
  color: var(--text-primary);
  background: var(--bg-primary);
  min-height: 100vh;
}

#app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.hidden {
  display: none !important;
}

/* ========== Search Overlay ========== */
.search-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 1000;
  padding: var(--space-4);
  background: linear-gradient(to bottom, var(--bg-primary) 0%, transparent 100%);
  animation: slideDown 0.2s ease;
}

@keyframes slideDown {
  from { transform: translateY(-100%); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

.search-box {
  max-width: 600px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  gap: var(--space-2);
  background: var(--bg-tertiary);
  border: 1px solid var(--border-medium);
  border-radius: var(--radius-md);
  padding: var(--space-2) var(--space-3);
}

.search-icon {
  color: var(--text-muted);
  font-size: var(--font-size-xs);
  background: var(--bg-secondary);
  padding: 2px 6px;
  border-radius: 3px;
}

.search-box input {
  flex: 1;
  background: transparent;
  border: none;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--font-size-base);
  outline: none;
}

.search-box input::placeholder {
  color: var(--text-muted);
}

.search-count {
  color: var(--text-secondary);
  font-size: var(--font-size-xs);
}

.search-nav, .search-close {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  padding: var(--space-1);
  font-family: var(--font-mono);
  font-size: var(--font-size-sm);
  transition: color var(--transition-fast);
}

.search-nav:hover, .search-close:hover {
  color: var(--text-primary);
}

/* ========== Password Prompt ========== */
.password-prompt {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-primary);
  z-index: 100;
}

.prompt-container {
  width: 100%;
  max-width: 420px;
  padding: var(--space-4);
}

.terminal-window {
  background: var(--bg-secondary);
  border: 1px solid var(--border-medium);
  border-radius: var(--radius-lg);
  overflow: hidden;
  box-shadow: 0 20px 60px rgba(0,0,0,0.5);
}

.terminal-header {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-3) var(--space-4);
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border-subtle);
}

.terminal-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.terminal-dot.red { background: #ff5f57; }
.terminal-dot.yellow { background: #febc2e; }
.terminal-dot.green { background: #28c840; }

.terminal-title {
  margin-left: auto;
  color: var(--text-muted);
  font-size: var(--font-size-xs);
}

.terminal-body {
  padding: var(--space-5);
}

.prompt-line {
  display: flex;
  gap: var(--space-2);
  margin-bottom: var(--space-4);
}

.prompt-symbol {
  color: var(--human-accent);
  font-weight: 600;
}

.prompt-symbol.dimmed {
  color: var(--text-muted);
}

.prompt-text {
  color: var(--text-primary);
}

.password-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.input-line {
  display: flex;
  align-items: center;
  gap: var(--space-2);
}

.password-form input {
  flex: 1;
  background: var(--bg-primary);
  border: 1px solid var(--border-medium);
  border-radius: var(--radius-sm);
  padding: var(--space-2) var(--space-3);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--font-size-base);
  outline: none;
  transition: border-color var(--transition-fast);
}

.password-form input:focus {
  border-color: var(--accent-green);
}

.error-line {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  color: var(--error-accent);
  font-size: var(--font-size-sm);
}

.error-symbol {
  font-weight: bold;
}

.submit-btn {
  align-self: flex-start;
  background: var(--accent-green);
  color: var(--bg-primary);
  border: none;
  border-radius: var(--radius-sm);
  padding: var(--space-2) var(--space-4);
  font-family: var(--font-mono);
  font-size: var(--font-size-sm);
  font-weight: 600;
  cursor: pointer;
  transition: opacity var(--transition-fast);
}

.submit-btn:hover {
  opacity: 0.9;
}

/* ========== Header ========== */
.viewer-header {
  position: sticky;
  top: 0;
  z-index: 50;
  background: var(--bg-primary);
  border-bottom: 1px solid var(--border-subtle);
  padding: var(--space-4) var(--space-5);
}

.header-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--space-3);
}

.logo {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  text-decoration: none;
  color: var(--text-secondary);
  transition: color var(--transition-fast);
}

.logo:hover {
  color: var(--text-primary);
}

.logo-icon {
  color: var(--accent-purple);
  font-size: 18px;
}

.logo-text {
  font-size: var(--font-size-sm);
  font-weight: 500;
}

.header-actions {
  display: flex;
  gap: var(--space-2);
}

.action-btn {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  padding: var(--space-1) var(--space-2);
  color: var(--text-secondary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  transition: all var(--transition-fast);
}

.action-btn:hover {
  background: var(--bg-elevated);
  color: var(--text-primary);
  border-color: var(--border-medium);
}

.session-info {
  max-width: 800px;
}

.session-title {
  font-size: var(--font-size-lg);
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: var(--space-2);
  line-height: 1.4;
}

.session-meta {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  font-size: var(--font-size-xs);
  color: var(--text-secondary);
}

.meta-item {
  display: flex;
  align-items: center;
  gap: var(--space-1);
}

.meta-icon {
  opacity: 0.7;
}

.session-id {
  font-family: var(--font-mono);
  background: var(--bg-tertiary);
  padding: 2px 6px;
  border-radius: 3px;
  color: var(--text-muted);
}

.tools-used {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin-top: var(--space-3);
}

.tool-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  background: var(--bg-tertiary);
  padding: 6px 12px;
  border-radius: var(--radius-sm);
  font-size: var(--font-size-sm);
  font-weight: 500;
  color: var(--tool-accent);
}

.tool-count {
  color: var(--text-muted);
  margin-left: 3px;
  font-weight: 600;
}

/* ========== Messages Container ========== */
.session-container {
  flex: 1;
  padding: var(--space-5);
  max-width: 900px;
  margin: 0 auto;
  width: 100%;
}

.messages {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}

/* ========== Human Messages ========== */
.human-message {
  display: flex;
  gap: var(--space-3);
}

.message-gutter {
  flex-shrink: 0;
  width: 20px;
  padding-top: 2px;
}

.human-prompt {
  color: var(--human-accent);
  font-weight: 700;
  font-size: 16px;
}

.message-body {
  flex: 1;
  min-width: 0;
}

.human-content {
  color: var(--text-bright);
  font-weight: 500;
}

.human-content.collapsed {
  max-height: 200px;
  overflow: hidden;
  position: relative;
}

.human-content.collapsed::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 60px;
  background: linear-gradient(transparent, var(--bg-primary));
}

.expand-toggle {
  background: transparent;
  border: none;
  color: var(--accent-blue);
  font-family: var(--font-mono);
  font-size: var(--font-size-xs);
  cursor: pointer;
  padding: var(--space-2) 0;
}

.expand-toggle:hover {
  text-decoration: underline;
}

.message-meta {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  margin-top: var(--space-2);
}

.meta-time {
  font-size: var(--font-size-xs);
  color: var(--text-muted);
}

.copy-link-inline {
  background: transparent;
  border: none;
  cursor: pointer;
  font-size: var(--font-size-xs);
  opacity: 0;
  transition: opacity var(--transition-fast);
}

.human-message:hover .copy-link-inline {
  opacity: 0.5;
}

.copy-link-inline:hover {
  opacity: 1 !important;
}

/* ========== Assistant Group ========== */
.assistant-group {
  display: flex;
  gap: var(--space-3);
}

.assistant-indicator {
  flex-shrink: 0;
  width: 20px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-1);
  padding-top: 4px;
}

.indicator-icon {
  color: var(--claude-accent);
  font-size: 8px;
}

.indicator-text {
  writing-mode: vertical-rl;
  text-orientation: mixed;
  font-size: 9px;
  color: var(--text-muted);
  letter-spacing: 1px;
  text-transform: uppercase;
}

.assistant-content {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  padding-left: var(--space-3);
  border-left: 1px solid var(--border-subtle);
}

/* ========== Assistant Text ========== */
.assistant-text {
  color: var(--text-primary);
  line-height: 1.7;
}

.assistant-text p {
  margin-bottom: var(--space-3);
}

.assistant-text p:last-child {
  margin-bottom: 0;
}

.assistant-text .code-block {
  background: var(--bg-secondary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  padding: var(--space-3);
  margin: var(--space-3) 0;
  overflow-x: auto;
  font-size: var(--font-size-sm);
}

.assistant-text .code-block code {
  color: var(--text-primary);
}

.assistant-text .inline-code {
  background: var(--bg-tertiary);
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 0.9em;
  color: var(--accent-orange);
}

/* ========== Tool Call ========== */
.tool-call {
  display: flex;
  align-items: baseline;
  gap: var(--space-2);
  padding: var(--space-2) 0;
}

.tool-icon {
  color: var(--tool-accent);
  font-weight: 700;
  font-size: 14px;
}

.tool-name {
  color: var(--tool-accent);
  font-weight: 600;
  font-size: var(--font-size-sm);
}

.tool-summary {
  color: var(--text-secondary);
  font-size: var(--font-size-sm);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ========== Tool Result ========== */
.tool-result {
  background: var(--bg-secondary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.tool-result.error {
  border-color: rgba(224, 108, 117, 0.3);
}

.tool-result.error .output-pre {
  color: var(--error-accent);
}

.result-content {
  max-height: 400px;
  overflow: auto;
}

.tool-result.collapsed .result-content {
  max-height: 60px;
  overflow: hidden;
  position: relative;
}

.tool-result.collapsed .result-content::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 40px;
  background: linear-gradient(transparent, var(--bg-secondary));
  pointer-events: none;
}

.output-pre {
  margin: 0;
  padding: var(--space-3);
  font-size: var(--font-size-sm);
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-secondary);
}

.result-expand {
  border-top: 1px solid var(--border-subtle);
  padding: var(--space-2);
  text-align: center;
}

.expand-btn {
  background: transparent;
  border: none;
  color: var(--accent-blue);
  font-family: var(--font-mono);
  font-size: var(--font-size-xs);
  cursor: pointer;
}

.expand-btn:hover {
  text-decoration: underline;
}

/* ========== Footer ========== */
.viewer-footer {
  position: sticky;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--space-3) var(--space-5);
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-subtle);
  font-size: var(--font-size-xs);
  color: var(--text-muted);
}

.footer-hint {
  display: flex;
  align-items: center;
  gap: var(--space-2);
}

.footer-hint kbd {
  background: var(--bg-tertiary);
  padding: 2px 5px;
  border-radius: 3px;
  font-size: 10px;
}

.footer-hint .sep {
  opacity: 0.3;
}

.footer-brand {
  display: flex;
  align-items: center;
  gap: var(--space-1);
  color: var(--text-muted);
  text-decoration: none;
  transition: color var(--transition-fast);
}

.footer-brand:hover {
  color: var(--text-secondary);
}

.brand-icon {
  color: var(--accent-purple);
}

/* ========== Search Highlight ========== */
.search-match {
  background: rgba(230, 192, 123, 0.3);
  border-radius: 2px;
}

.search-match.current {
  background: rgba(230, 192, 123, 0.6);
}

/* ========== Deep Link Highlight ========== */
.message:target,
.tool-call:target,
.tool-result:target {
  animation: highlight 2s ease;
}

@keyframes highlight {
  0%, 30% { background: rgba(94, 159, 215, 0.15); }
  100% { background: transparent; }
}

/* ========== Scrollbar ========== */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: var(--bg-secondary);
}

::-webkit-scrollbar-thumb {
  background: var(--border-medium);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: var(--text-muted);
}

/* ========== Responsive ========== */
@media (max-width: 640px) {
  .viewer-header {
    padding: var(--space-3);
  }

  .session-container {
    padding: var(--space-3);
  }

  .session-title {
    font-size: var(--font-size-base);
  }

  .footer-hint {
    display: none;
  }

  .assistant-indicator {
    display: none;
  }

  .assistant-content {
    padding-left: 0;
    border-left: none;
  }
}

/* ========== Syntax Highlighting (Basic) ========== */
.language-javascript .keyword,
.language-typescript .keyword { color: var(--accent-purple); }
.language-javascript .string,
.language-typescript .string { color: var(--accent-green); }
.language-javascript .number,
.language-typescript .number { color: var(--accent-orange); }
.language-javascript .comment,
.language-typescript .comment { color: var(--text-muted); }

/* ========== Key Moments Summary ========== */
.key-moments {
  margin-top: var(--space-4);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-secondary);
}

.key-moments-toggle {
  padding: var(--space-3);
  cursor: pointer;
  font-size: var(--font-size-sm);
  color: var(--text-secondary);
  list-style: none;
}

.key-moments-toggle::-webkit-details-marker { display: none; }

.key-moments[open] .key-moments-toggle {
  border-bottom: 1px solid var(--border-subtle);
}

.key-moments-content {
  padding: var(--space-3);
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.km-section {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-2);
}

.km-label {
  font-size: var(--font-size-xs);
  color: var(--text-muted);
  min-width: 100px;
}

.km-file {
  font-size: var(--font-size-xs);
  padding: 2px 6px;
  border-radius: 3px;
  font-family: var(--font-mono);
}

.km-file.created {
  background: rgba(78, 201, 112, 0.15);
  color: var(--accent-green);
}

.km-file.modified {
  background: rgba(230, 192, 123, 0.15);
  color: var(--accent-yellow);
}

.km-cmd {
  font-size: var(--font-size-xs);
  background: var(--bg-tertiary);
  padding: 2px 6px;
  border-radius: 3px;
  color: var(--tool-accent);
}

.km-more {
  font-size: var(--font-size-xs);
  color: var(--text-muted);
}

.km-icon {
  display: inline-block;
  transition: transform 0.2s;
}

.key-moments[open] .km-icon {
  transform: rotate(90deg);
}

/* ========== Action Button Labels ========== */
.action-btn.labeled {
  display: flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-1) var(--space-2);
}

.action-label {
  font-size: var(--font-size-xs);
}

@media (max-width: 640px) {
  .action-label {
    display: none;
  }
}

/* ========== Editable Title ========== */
.title-row {
  display: flex;
  align-items: flex-start;
  gap: var(--space-2);
}

.session-title {
  outline: none;
  border-radius: var(--radius-sm);
  padding: 2px 4px;
  margin: -2px -4px;
  transition: background var(--transition-fast);
}

.session-title:hover {
  background: var(--bg-tertiary);
}

.session-title:focus {
  background: var(--bg-secondary);
  box-shadow: 0 0 0 2px var(--accent-blue);
}

.edit-title-btn {
  background: transparent;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  padding: var(--space-1);
  opacity: 0;
  transition: opacity var(--transition-fast);
}

.title-row:hover .edit-title-btn {
  opacity: 1;
}

.edit-title-btn:hover {
  color: var(--text-primary);
}

/* ========== Git Context ========== */
.git-context {
  display: flex;
  align-items: center;
  gap: var(--space-1);
  font-size: var(--font-size-xs);
  margin-bottom: var(--space-2);
}

.git-link {
  color: var(--accent-blue);
  text-decoration: none;
}

.git-link:hover {
  text-decoration: underline;
}

.git-branch {
  background: var(--bg-tertiary);
  padding: 2px 6px;
  border-radius: 3px;
  color: var(--accent-purple);
}

.git-commit {
  font-family: var(--font-mono);
  color: var(--accent-yellow);
  text-decoration: none;
}

a.git-commit:hover {
  text-decoration: underline;
}

.git-sep {
  color: var(--text-muted);
  margin: 0 2px;
}

/* ========== Diff View ========== */
.diff-view {
  font-size: var(--font-size-sm);
  line-height: 1.5;
  overflow-x: auto;
}

.diff-line {
  display: flex;
  white-space: pre;
  font-family: var(--font-mono);
}

.diff-prefix {
  width: 20px;
  flex-shrink: 0;
  text-align: center;
  user-select: none;
}

.diff-content {
  flex: 1;
  padding-right: var(--space-2);
}

.diff-add {
  background: rgba(78, 201, 112, 0.15);
  color: var(--accent-green);
}

.diff-add .diff-prefix {
  color: var(--accent-green);
}

.diff-remove {
  background: rgba(224, 108, 117, 0.15);
  color: var(--error-accent);
}

.diff-remove .diff-prefix {
  color: var(--error-accent);
}

.diff-unchanged {
  color: var(--text-muted);
}

.diff-collapse {
  color: var(--text-muted);
  font-style: italic;
  padding-left: 20px;
  background: var(--bg-tertiary);
}

/* ========== Embed Mode ========== */
[data-embed="true"] .viewer-header {
  position: static;
  padding: var(--space-2) var(--space-3);
}

[data-embed="true"] .header-top {
  display: none;
}

[data-embed="true"] .session-title {
  font-size: var(--font-size-sm);
}

[data-embed="true"] .viewer-footer {
  display: none;
}

[data-embed="true"] .session-container {
  padding: var(--space-2);
}

/* ========== Tool Navigation ========== */
.tool-badge.tool-nav {
  cursor: pointer;
  border: 1px dashed transparent;
  font-family: var(--font-mono);
  transition: all var(--transition-fast);
  position: relative;
}

.tool-badge.tool-nav::after {
  content: '↗';
  font-size: 8px;
  margin-left: 2px;
  opacity: 0.5;
  vertical-align: super;
}

.tool-badge.tool-nav:hover {
  background: var(--bg-elevated);
  transform: scale(1.05);
  border-color: var(--border-medium);
}

.tool-badge.tool-nav:hover::after {
  opacity: 1;
}

.tool-nav-indicator {
  position: fixed;
  bottom: 80px;
  right: 20px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-medium);
  border-radius: var(--radius-md);
  padding: var(--space-2) var(--space-3);
  display: none;
  align-items: center;
  gap: var(--space-2);
  font-size: var(--font-size-xs);
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  z-index: 100;
}

.tool-nav-indicator.visible {
  display: flex;
}

.tool-nav-indicator button {
  background: var(--bg-tertiary);
  border: none;
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  cursor: pointer;
  font-family: var(--font-mono);
}

.tool-nav-indicator button:hover {
  color: var(--text-primary);
  background: var(--bg-elevated);
}

/* ========== Highlight Flash Animation ========== */
.highlight-flash {
  animation: flashHighlight 1.5s ease;
}

@keyframes flashHighlight {
  0%, 30% { background: rgba(94, 159, 215, 0.2); }
  100% { background: transparent; }
}

/* ========== Edit Diff ========== */
.edit-diff {
  margin-top: var(--space-2);
  background: var(--bg-secondary);
  border-radius: var(--radius-sm);
  padding: var(--space-2);
  max-height: 300px;
  overflow: auto;
}
`;

// ============================================================================
// Light Mode CSS
// ============================================================================

const LIGHT_MODE_CSS = `
/* ========== Light Mode ========== */
[data-theme="light"] {
  --bg-primary: #ffffff;
  --bg-secondary: #f8f9fa;
  --bg-tertiary: #f1f3f4;
  --bg-elevated: #e8eaed;

  --text-primary: #1f2937;
  --text-secondary: #4b5563;
  --text-muted: #9ca3af;
  --text-bright: #111827;

  --accent-green: #059669;
  --accent-blue: #2563eb;
  --accent-purple: #7c3aed;
  --accent-yellow: #d97706;
  --accent-red: #dc2626;
  --accent-cyan: #0891b2;
  --accent-orange: #ea580c;

  --border-subtle: #e5e7eb;
  --border-medium: #d1d5db;
}

[data-theme="light"] .terminal-window {
  box-shadow: 0 20px 60px rgba(0,0,0,0.1);
}

[data-theme="light"] ::-webkit-scrollbar-track {
  background: var(--bg-secondary);
}

[data-theme="light"] ::-webkit-scrollbar-thumb {
  background: var(--border-medium);
}

[data-theme="light"] .human-content.collapsed::after {
  background: linear-gradient(transparent, var(--bg-primary));
}
`;

// ============================================================================
// Viewer JavaScript
// ============================================================================

const VIEWER_JS = `
(function() {
  const sessionData = JSON.parse(document.getElementById('session-data').textContent);

  // Handle encrypted sessions
  if (sessionData.encrypted) {
    initEncryptedViewer(sessionData);
  } else {
    initViewer();
  }

  function initEncryptedViewer(data) {
    const passwordPrompt = document.getElementById('password-prompt');
    const viewer = document.getElementById('viewer');
    const hash = window.location.hash;

    // Check for key in URL fragment (public session)
    const keyMatch = hash.match(/key=([^&]+)/);

    if (keyMatch && !data.salt) {
      // Public session with key in URL
      decryptAndRender(keyMatch[1], data);
    } else if (data.salt) {
      // Private session - password form is already visible
      document.getElementById('password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('password-input').value;
        const errorEl = document.getElementById('password-error');

        try {
          await decryptAndRender(password, data);
        } catch (err) {
          errorEl.classList.remove('hidden');
          document.getElementById('password-input').value = '';
          document.getElementById('password-input').focus();
        }
      });
    }
  }

  async function decryptAndRender(keyOrPassword, data) {
    const session = await decryptSession(
      data.encryptedBlob,
      data.iv,
      keyOrPassword,
      data.salt
    );

    document.getElementById('password-prompt').classList.add('hidden');
    document.getElementById('viewer').classList.remove('hidden');

    // Render messages
    document.getElementById('messages').innerHTML = renderMessages(session.messages);
    initViewer();
  }

  function renderMessages(messages) {
    const groups = groupMessages(messages);
    return groups.map((group, idx) => renderGroup(group, idx)).join('');
  }

  function groupMessages(messages) {
    const groups = [];
    let current = null;

    for (const msg of messages) {
      const type = msg.type === 'human' ? 'human' : 'assistant';
      if (!current || current.type !== type) {
        if (current) groups.push(current);
        current = { type, messages: [] };
      }
      current.messages.push(msg);
    }
    if (current) groups.push(current);
    return groups;
  }

  function renderGroup(group, idx) {
    if (group.type === 'human') {
      return group.messages.map(renderHuman).join('');
    }
    return \`
      <div class="assistant-group" data-group="\${idx}">
        <div class="assistant-indicator">
          <span class="indicator-icon">●</span>
          <span class="indicator-text">Claude</span>
        </div>
        <div class="assistant-content">
          \${group.messages.map(renderAssistantItem).join('')}
        </div>
      </div>\`;
  }

  function renderHuman(msg) {
    return \`
      <div class="message human-message" id="\${msg.id}">
        <div class="message-gutter"><span class="human-prompt">❯</span></div>
        <div class="message-body">
          <div class="human-content">\${formatText(msg.content)}</div>
        </div>
      </div>\`;
  }

  function renderAssistantItem(msg) {
    if (msg.type === 'assistant') {
      return \`<div class="assistant-text" id="\${msg.id}">\${formatText(msg.content)}</div>\`;
    }
    if (msg.type === 'tool_call') {
      return \`
        <div class="tool-call" id="\${msg.id}">
          <span class="tool-icon">\${getToolIcon(msg.toolName)}</span>
          <span class="tool-name">\${esc(msg.toolName || 'Tool')}</span>
          <span class="tool-summary">\${esc(msg.content || '')}</span>
        </div>\`;
    }
    if (msg.type === 'tool_result') {
      return \`
        <div class="tool-result" id="\${msg.id}">
          <div class="result-content">
            <pre class="output-pre"><code>\${esc(msg.toolOutput || msg.content || '')}</code></pre>
          </div>
        </div>\`;
    }
    return '';
  }

  function formatText(text) {
    if (!text) return '';
    return esc(text).split('\\n\\n').map(p => '<p>' + p.replace(/\\n/g, '<br>') + '</p>').join('');
  }

  function getToolIcon(name) {
    const icons = { Bash: '$', Read: '◇', Write: '◆', Edit: '✎', Glob: '⊛', Grep: '⊙', Task: '⊳' };
    return icons[name] || '⊡';
  }

  function esc(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  function initViewer() {
    // Theme toggle
    document.getElementById('theme-toggle')?.addEventListener('click', () => {
      const html = document.documentElement;
      const current = html.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      localStorage.setItem('ccshare-theme', next);
    });

    // Restore saved theme
    const savedTheme = localStorage.getItem('ccshare-theme');
    if (savedTheme) {
      document.documentElement.setAttribute('data-theme', savedTheme);
    }

    // Check URL for embed mode
    if (new URLSearchParams(window.location.search).get('embed') === 'true') {
      document.documentElement.setAttribute('data-embed', 'true');
    }

    // Tool navigation - click badge to jump to tool instances
    let toolNavState = { tool: null, instances: [], currentIndex: -1 };

    document.querySelectorAll('.tool-nav').forEach(badge => {
      badge.addEventListener('click', () => {
        const toolName = badge.dataset.tool;
        const instances = Array.from(document.querySelectorAll(\`[data-tool-name="\${toolName}"]\`));

        if (instances.length === 0) return;

        if (toolNavState.tool === toolName && toolNavState.currentIndex < instances.length - 1) {
          toolNavState.currentIndex++;
        } else {
          toolNavState.tool = toolName;
          toolNavState.instances = instances;
          toolNavState.currentIndex = 0;
        }

        const target = instances[toolNavState.currentIndex];
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.classList.add('highlight-flash');
        setTimeout(() => target.classList.remove('highlight-flash'), 1500);

        updateToolNavIndicator(toolName, toolNavState.currentIndex + 1, instances.length);
      });
    });

    function updateToolNavIndicator(tool, current, total) {
      let indicator = document.getElementById('tool-nav-indicator');
      if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'tool-nav-indicator';
        indicator.className = 'tool-nav-indicator';
        indicator.innerHTML = \`
          <span class="nav-info"></span>
          <button class="nav-prev">←</button>
          <button class="nav-next">→</button>
          <button class="nav-close">×</button>
        \`;
        document.body.appendChild(indicator);

        indicator.querySelector('.nav-prev').addEventListener('click', () => navToolPrev());
        indicator.querySelector('.nav-next').addEventListener('click', () => navToolNext());
        indicator.querySelector('.nav-close').addEventListener('click', () => {
          indicator.classList.remove('visible');
          toolNavState = { tool: null, instances: [], currentIndex: -1 };
        });
      }

      indicator.querySelector('.nav-info').textContent = \`\${tool} \${current}/\${total}\`;
      indicator.classList.add('visible');
    }

    function navToolPrev() {
      if (toolNavState.currentIndex > 0) {
        toolNavState.currentIndex--;
        const target = toolNavState.instances[toolNavState.currentIndex];
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        updateToolNavIndicator(toolNavState.tool, toolNavState.currentIndex + 1, toolNavState.instances.length);
      }
    }

    function navToolNext() {
      if (toolNavState.currentIndex < toolNavState.instances.length - 1) {
        toolNavState.currentIndex++;
        const target = toolNavState.instances[toolNavState.currentIndex];
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        updateToolNavIndicator(toolNavState.tool, toolNavState.currentIndex + 1, toolNavState.instances.length);
      }
    }

    // Collapse/expand buttons
    document.getElementById('collapse-all-btn')?.addEventListener('click', () => {
      document.querySelectorAll('.tool-result').forEach(el => el.classList.add('collapsed'));
    });

    document.getElementById('expand-all-btn')?.addEventListener('click', () => {
      document.querySelectorAll('.tool-result').forEach(el => el.classList.remove('collapsed'));
    });

    // Expand buttons for tool results
    document.querySelectorAll('.expand-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const result = btn.closest('.tool-result');
        result.classList.remove('collapsed');
        const fullContent = btn.closest('.result-expand').dataset.full;
        if (fullContent) {
          result.querySelector('code').textContent = fullContent;
        }
        btn.closest('.result-expand').remove();
      });
    });

    // Expand toggle for human messages
    document.querySelectorAll('.expand-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const messageBody = btn.closest('.message-body');
        const content = messageBody?.querySelector('.human-content');
        if (content && content.classList.contains('collapsed')) {
          content.classList.remove('collapsed');
          btn.textContent = 'Show less ↑';
        } else if (content) {
          content.classList.add('collapsed');
          btn.textContent = 'Show more ↓';
        }
      });
    });

    // Copy link button
    document.getElementById('copy-link-btn')?.addEventListener('click', () => {
      navigator.clipboard.writeText(window.location.href);
      const btn = document.getElementById('copy-link-btn');
      const label = btn?.querySelector('.action-label');
      if (label) {
        label.textContent = 'Copied!';
        setTimeout(() => label.textContent = 'Copy', 1500);
      }
    });

    // Edit title button
    const titleEl = document.getElementById('session-title');
    const editTitleBtn = document.getElementById('edit-title-btn');

    editTitleBtn?.addEventListener('click', () => {
      titleEl?.focus();
      // Select all text
      const range = document.createRange();
      range.selectNodeContents(titleEl);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
    });

    titleEl?.addEventListener('blur', () => {
      // Title editing finished - could save to localStorage
      const newTitle = titleEl.textContent?.trim();
      if (newTitle) {
        localStorage.setItem('ccshare-title-' + sessionData.id, newTitle);
      }
    });

    titleEl?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        titleEl.blur();
      }
      if (e.key === 'Escape') {
        // Restore original title
        const original = titleEl.dataset.original;
        if (original) titleEl.textContent = original;
        titleEl.blur();
      }
    });

    // Store original title for escape
    if (titleEl) {
      titleEl.dataset.original = titleEl.textContent;
      // Restore custom title if saved
      const savedTitle = localStorage.getItem('ccshare-title-' + sessionData.id);
      if (savedTitle) titleEl.textContent = savedTitle;
    }

    // Inline copy link buttons
    document.querySelectorAll('.copy-link-inline').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.id;
        const url = window.location.href.split('#')[0] + '#' + id;
        navigator.clipboard.writeText(url);
        btn.textContent = '✓';
        setTimeout(() => btn.textContent = '🔗', 1500);
      });
    });

    // Search
    const searchOverlay = document.getElementById('search-overlay');
    const searchInput = document.getElementById('search-input');
    let searchMatches = [];
    let currentMatch = -1;

    document.addEventListener('keydown', (e) => {
      // Cmd/Ctrl + F
      if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
        e.preventDefault();
        searchOverlay.classList.remove('hidden');
        searchInput.focus();
        searchInput.select();
      }
      // Escape
      if (e.key === 'Escape') {
        searchOverlay.classList.add('hidden');
        clearSearch();
      }
      // C to collapse all
      if (e.key === 'c' && !e.metaKey && !e.ctrlKey && document.activeElement.tagName !== 'INPUT') {
        document.querySelectorAll('.tool-result').forEach(el => el.classList.add('collapsed'));
      }
      // E to expand all
      if (e.key === 'e' && !e.metaKey && !e.ctrlKey && document.activeElement.tagName !== 'INPUT') {
        document.querySelectorAll('.tool-result').forEach(el => el.classList.remove('collapsed'));
      }
    });

    searchInput?.addEventListener('input', () => {
      performSearch(searchInput.value);
    });

    document.getElementById('search-close')?.addEventListener('click', () => {
      searchOverlay.classList.add('hidden');
      clearSearch();
    });

    document.getElementById('search-next')?.addEventListener('click', () => navigateSearch(1));
    document.getElementById('search-prev')?.addEventListener('click', () => navigateSearch(-1));

    function performSearch(query) {
      clearSearch();
      if (!query || query.length < 2) {
        document.getElementById('search-count').textContent = '';
        return;
      }

      const regex = new RegExp('(' + query.replace(/[.*+?^\${}()|[\\]\\\\]/g, '\\\\$&') + ')', 'gi');
      const walker = document.createTreeWalker(
        document.getElementById('messages'),
        NodeFilter.SHOW_TEXT,
        null,
        false
      );

      const matches = [];
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (node.textContent.match(regex)) {
          const span = document.createElement('span');
          span.innerHTML = node.textContent.replace(regex, '<mark class="search-match">$1</mark>');
          node.parentNode.replaceChild(span, node);
          span.querySelectorAll('.search-match').forEach(m => matches.push(m));
        }
      }

      searchMatches = matches;
      currentMatch = -1;
      document.getElementById('search-count').textContent = matches.length + ' found';
      if (matches.length) navigateSearch(1);
    }

    function navigateSearch(dir) {
      if (!searchMatches.length) return;
      if (currentMatch >= 0) searchMatches[currentMatch].classList.remove('current');
      currentMatch = (currentMatch + dir + searchMatches.length) % searchMatches.length;
      searchMatches[currentMatch].classList.add('current');
      searchMatches[currentMatch].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function clearSearch() {
      document.querySelectorAll('.search-match').forEach(el => {
        const text = el.textContent;
        el.replaceWith(text);
      });
      searchMatches = [];
      currentMatch = -1;
    }

    // Handle deep link on load
    if (window.location.hash && !window.location.hash.includes('key=')) {
      const target = document.querySelector(window.location.hash);
      if (target) {
        setTimeout(() => target.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100);
      }
    }
  }
})();
`;
