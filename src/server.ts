import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { nanoid } from 'nanoid';
import { z } from 'zod';
import { db, sessions, users, apiKeys, type NewSession, type Session } from './db/index.ts';
import { eq } from 'drizzle-orm';

const app = new Hono();

// Middleware
app.use('*', logger());
app.use('/api/*', cors());

// Health check
app.get('/health', (c) => c.json({ status: 'ok' }));

// Upload schema
const uploadSchema = z.object({
  encryptedBlob: z.string(),
  iv: z.string(),
  salt: z.string().optional(),
  visibility: z.enum(['public', 'private']),
  metadata: z.object({
    title: z.string(),
    messageCount: z.number(),
    toolCount: z.number(),
    durationSeconds: z.number(),
  }),
});

// API: Upload session
app.post('/api/upload', async (c) => {
  try {
    const body = await c.req.json();
    const parsed = uploadSchema.parse(body);

    // Generate short ID for URL
    const id = nanoid(10);

    // Get user from auth header if present
    let userId: string | null = null;
    const authHeader = c.req.header('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      // TODO: Validate API key and get user ID
      // For now, allow anonymous uploads
    }

    if (!db) {
      // Development mode without database - just return mock response
      const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
      return c.json({
        id,
        url: `${baseUrl}/s/${id}`,
      });
    }

    // Store in database
    const session: NewSession = {
      id,
      userId,
      title: parsed.metadata.title.slice(0, 200), // Truncate title
      messageCount: parsed.metadata.messageCount,
      toolCount: parsed.metadata.toolCount,
      durationSeconds: parsed.metadata.durationSeconds,
      visibility: parsed.visibility,
      encryptedBlob: parsed.encryptedBlob,
      iv: parsed.iv,
      salt: parsed.salt || null,
    };

    await db.insert(sessions).values(session);

    const baseUrl = process.env.BASE_URL || 'https://claudereview.com';
    return c.json({
      id,
      url: `${baseUrl}/s/${id}`,
    });
  } catch (error) {
    console.error('Upload error:', error);
    if (error instanceof z.ZodError) {
      return c.json({ error: 'Invalid request body', details: error.issues }, 400);
    }
    return c.json({ error: 'Upload failed' }, 500);
  }
});

// API: Get session data (for viewer)
app.get('/api/session/:id', async (c) => {
  const id = c.req.param('id');

  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  try {
    const [session] = await db.select().from(sessions).where(eq(sessions.id, id)).limit(1);

    if (!session) {
      return c.json({ error: 'Session not found' }, 404);
    }

    // Increment view count
    await db.update(sessions)
      .set({ viewCount: session.viewCount + 1 })
      .where(eq(sessions.id, id));

    return c.json({
      id: session.id,
      encryptedBlob: session.encryptedBlob,
      iv: session.iv,
      visibility: session.visibility,
      salt: session.salt,
      metadata: {
        title: session.title,
        messageCount: session.messageCount,
        toolCount: session.toolCount,
        durationSeconds: session.durationSeconds,
        createdAt: session.createdAt.toISOString(),
      },
    });
  } catch (error) {
    console.error('Get session error:', error);
    return c.json({ error: 'Failed to get session' }, 500);
  }
});

// Viewer page - serves the session viewer HTML
app.get('/s/:id', async (c) => {
  const id = c.req.param('id');

  if (!db) {
    return c.html(generateViewerHtml(null, id));
  }

  try {
    const [session] = await db.select().from(sessions).where(eq(sessions.id, id)).limit(1);

    if (!session) {
      return c.html(generate404Html(), 404);
    }

    return c.html(generateViewerHtml(session, id));
  } catch (error) {
    console.error('Viewer error:', error);
    return c.html(generate500Html(), 500);
  }
});

// Landing page
app.get('/', (c) => {
  return c.html(generateLandingHtml());
});

// Generate viewer HTML that fetches and decrypts on client side
function generateViewerHtml(session: Session | null, id: string): string {
  const title = session?.title || 'Claude Code Session';
  const description = session
    ? `${session.messageCount} messages · ${formatDuration(session.durationSeconds)}`
    : 'View Claude Code session';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - claudereview</title>
  <meta property="og:type" content="website">
  <meta property="og:title" content="Claude Session: ${escapeHtml(title)}">
  <meta property="og:description" content="${escapeHtml(description)}">
  <meta property="og:site_name" content="claudereview.com">
  <meta name="twitter:card" content="summary">
  <style>${VIEWER_CSS}</style>
</head>
<body>
  <div id="app">
    <div id="loading" class="loading">
      <div class="spinner"></div>
      <p>Loading session...</p>
    </div>
    <div id="password-prompt" class="password-prompt hidden">
      <div class="prompt-box">
        <div class="prompt-icon">🔐</div>
        <h2>This session is password protected</h2>
        <p>Enter the password to view this session</p>
        <form id="password-form">
          <input type="password" id="password-input" placeholder="Password" autocomplete="off">
          <button type="submit">Unlock</button>
        </form>
        <div id="password-error" class="error hidden"></div>
      </div>
    </div>
    <div id="viewer" class="hidden">
      <header id="header"></header>
      <main id="messages"></main>
    </div>
    <div id="error-container" class="hidden"></div>
  </div>
  <script>
    const SESSION_ID = '${id}';
    ${BROWSER_CRYPTO}
    ${VIEWER_SCRIPT}
  </script>
</body>
</html>`;
}

function generate404Html(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Session Not Found - claudereview</title>
  <style>${VIEWER_CSS}</style>
</head>
<body>
  <div id="app">
    <div class="error-page">
      <h1>404</h1>
      <p>Session not found</p>
      <a href="/">← Back to home</a>
    </div>
  </div>
</body>
</html>`;
}

function generate500Html(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Error - claudereview</title>
  <style>${VIEWER_CSS}</style>
</head>
<body>
  <div id="app">
    <div class="error-page">
      <h1>500</h1>
      <p>Something went wrong</p>
      <a href="/">← Back to home</a>
    </div>
  </div>
</body>
</html>`;
}

function generateLandingHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>claudereview - Share Claude Code Sessions</title>
  <meta name="description" content="Share your Claude Code sessions for code review. End-to-end encrypted, beautiful TUI-style viewer.">
  <style>${LANDING_CSS}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <span class="logo-icon">◈</span>
        <span class="logo-text">claude<span class="accent">review</span></span>
      </div>
    </header>

    <main>
      <h1>Share Claude Code sessions<br>for code review</h1>
      <p class="subtitle">
        Drop a link in your PR so reviewers can see <em>how</em> the code was built,<br>
        not just the final diff. End-to-end encrypted.
      </p>

      <div class="install">
        <pre><code>bun add -g claudereview</code></pre>
        <p class="hint">or: npm install -g claudereview</p>
      </div>

      <div class="usage">
        <pre><code><span class="dim"># List your sessions</span>
ccshare list

<span class="dim"># Share the last session</span>
ccshare share --last

<span class="dim"># Share with password protection</span>
ccshare share --last --private "secret"

<span class="dim"># Preview locally</span>
ccshare preview --last</code></pre>
      </div>

      <div class="features">
        <div class="feature">
          <span class="icon">🔐</span>
          <h3>E2E Encrypted</h3>
          <p>We can't read your sessions. Keys never touch our servers.</p>
        </div>
        <div class="feature">
          <span class="icon">🔗</span>
          <h3>Deep Links</h3>
          <p>Link to specific messages. Perfect for code review comments.</p>
        </div>
        <div class="feature">
          <span class="icon">⚡</span>
          <h3>Fast</h3>
          <p>Instant parsing, instant sharing. Built with Bun.</p>
        </div>
      </div>
    </main>

    <footer>
      <a href="https://github.com/vignesh07/claudereview">GitHub</a>
      <span class="sep">·</span>
      <span class="dim">Built for developers who use Claude Code</span>
    </footer>
  </div>
</body>
</html>`;
}

// Helper functions
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}min`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.round((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

// CSS and JS constants
const VIEWER_CSS = `
:root {
  --bg: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
  --green: #3fb950;
  --yellow: #d29922;
  --red: #f85149;
  --purple: #a371f7;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', Menlo, monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}

#app { max-width: 900px; margin: 0 auto; padding: 2rem; }
.hidden { display: none !important; }

.loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 50vh;
  color: var(--text-muted);
}

.spinner {
  width: 24px;
  height: 24px;
  border: 2px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 1rem;
}

@keyframes spin { to { transform: rotate(360deg); } }

.error-page {
  text-align: center;
  padding: 4rem 2rem;
}
.error-page h1 { font-size: 4rem; color: var(--text-muted); }
.error-page p { color: var(--text-muted); margin: 1rem 0; }
.error-page a { color: var(--accent); }

header {
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}

.header-main {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.logo-icon { color: var(--accent); font-size: 1.25rem; }
.logo-text { font-size: 1rem; font-weight: 500; color: var(--text-muted); }
.logo-accent, .accent { color: var(--accent); }

.session-id {
  font-size: 0.875rem;
  color: var(--text-muted);
  background: var(--bg-secondary);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.session-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
  font-family: var(--font-sans);
}

.session-meta {
  display: flex;
  gap: 0.5rem;
  color: var(--text-muted);
  font-size: 0.875rem;
}

#messages { display: flex; flex-direction: column; gap: 1rem; }

.message.human {
  background: var(--bg-secondary);
  border-left: 3px solid var(--accent);
  padding: 1rem;
  border-radius: 0 8px 8px 0;
}

.message.human .message-content { color: var(--text-bright); white-space: pre-wrap; }

.message.assistant {
  padding: 0.5rem 0 0.5rem 1rem;
  border-left: 1px solid var(--border);
}

.tool-box {
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 6px;
  margin: 0.5rem 0;
}

.tool-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--bg-secondary);
}

.tool-name { color: var(--purple); font-weight: 500; }
.tool-summary { padding: 0.5rem 0.75rem; font-size: 0.875rem; }

.tool-output {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  margin-left: 1rem;
}

.output-content {
  padding: 0.75rem;
  font-size: 0.8125rem;
  white-space: pre-wrap;
  color: var(--text-muted);
  max-height: 400px;
  overflow-y: auto;
}

.password-prompt {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
}

.prompt-box {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 2rem;
  text-align: center;
  max-width: 400px;
}

.prompt-icon { font-size: 3rem; margin-bottom: 1rem; }
.prompt-box h2 { font-family: var(--font-sans); color: var(--text-bright); margin-bottom: 0.5rem; }
.prompt-box p { color: var(--text-muted); margin-bottom: 1.5rem; }
.prompt-box form { display: flex; flex-direction: column; gap: 1rem; }

.prompt-box input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  font-family: var(--font-mono);
  color: var(--text);
}

.prompt-box input:focus { outline: none; border-color: var(--accent); }

.prompt-box button {
  background: var(--accent);
  border: none;
  border-radius: 6px;
  padding: 0.75rem;
  font-weight: 500;
  color: white;
  cursor: pointer;
}

.error { color: var(--red); font-size: 0.875rem; margin-top: 1rem; }
`;

const LANDING_CSS = `
:root {
  --bg: #0d1117;
  --bg-secondary: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', Menlo, monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-mono);
  min-height: 100vh;
}

.container {
  max-width: 800px;
  margin: 0 auto;
  padding: 4rem 2rem;
}

header {
  margin-bottom: 4rem;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.logo-icon { color: var(--accent); font-size: 1.5rem; }
.logo-text { font-size: 1.25rem; color: var(--text-muted); }
.accent { color: var(--accent); }

main h1 {
  font-family: var(--font-sans);
  font-size: 2.5rem;
  color: var(--text-bright);
  line-height: 1.2;
  margin-bottom: 1rem;
}

.subtitle {
  color: var(--text-muted);
  font-size: 1.1rem;
  line-height: 1.6;
  margin-bottom: 3rem;
}

.subtitle em { color: var(--accent); font-style: normal; }

.install {
  margin-bottom: 2rem;
}

.install pre {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.5rem;
  font-size: 1rem;
}

.install code { color: var(--text-bright); }
.hint { color: var(--text-muted); font-size: 0.875rem; margin-top: 0.5rem; }

.usage {
  margin-bottom: 3rem;
}

.usage pre {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  font-size: 0.9rem;
  line-height: 1.8;
  overflow-x: auto;
}

.usage .dim { color: var(--text-muted); }

.features {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2rem;
  margin-bottom: 4rem;
}

.feature {
  text-align: center;
}

.feature .icon { font-size: 2rem; margin-bottom: 0.5rem; display: block; }
.feature h3 { font-family: var(--font-sans); color: var(--text-bright); margin-bottom: 0.5rem; }
.feature p { color: var(--text-muted); font-size: 0.875rem; }

footer {
  color: var(--text-muted);
  font-size: 0.875rem;
}

footer a { color: var(--accent); text-decoration: none; }
footer a:hover { text-decoration: underline; }
.sep { margin: 0 0.5rem; }
.dim { opacity: 0.7; }

@media (max-width: 640px) {
  main h1 { font-size: 1.75rem; }
  .features { grid-template-columns: 1fr; gap: 1.5rem; }
}
`;

const BROWSER_CRYPTO = `
async function deriveKeyBrowser(password, saltBase64) {
  const salt = base64UrlDecode(saltBase64);
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, ['decrypt']
  );
}

async function importKey(keyBase64) {
  const keyData = base64UrlDecode(keyBase64);
  return crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, false, ['decrypt']);
}

async function decryptData(ciphertextBase64, ivBase64, key) {
  const iv = base64UrlDecode(ivBase64);
  const combined = base64UrlDecode(ciphertextBase64);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined);
  return new TextDecoder().decode(decrypted);
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding) base64 += '='.repeat(4 - padding);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function decryptSession(encryptedBlob, iv, keyOrPassword, salt) {
  let key;
  if (salt) {
    key = await deriveKeyBrowser(keyOrPassword, salt);
  } else {
    key = await importKey(keyOrPassword);
  }
  const decrypted = await decryptData(encryptedBlob, iv, key);
  return JSON.parse(decrypted);
}
`;

const VIEWER_SCRIPT = `
(async function() {
  const loading = document.getElementById('loading');
  const passwordPrompt = document.getElementById('password-prompt');
  const viewer = document.getElementById('viewer');
  const errorContainer = document.getElementById('error-container');

  try {
    // Fetch session data
    const response = await fetch('/api/session/' + SESSION_ID);
    if (!response.ok) throw new Error('Session not found');

    const sessionData = await response.json();
    loading.classList.add('hidden');

    // Check for key in URL fragment
    const hash = window.location.hash;
    const keyMatch = hash.match(/key=([^&]+)/);

    if (keyMatch && !sessionData.salt) {
      // Public session with key in URL
      await decryptAndRender(sessionData, keyMatch[1]);
    } else if (sessionData.salt) {
      // Private session - show password prompt
      passwordPrompt.classList.remove('hidden');

      document.getElementById('password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('password-input').value;
        const errorEl = document.getElementById('password-error');
        errorEl.classList.add('hidden');

        try {
          await decryptAndRender(sessionData, password);
        } catch {
          errorEl.textContent = 'Incorrect password';
          errorEl.classList.remove('hidden');
        }
      });
    } else {
      throw new Error('Missing decryption key');
    }
  } catch (error) {
    loading.classList.add('hidden');
    errorContainer.innerHTML = '<div class="error-page"><h1>Error</h1><p>' + error.message + '</p><a href="/">← Back</a></div>';
    errorContainer.classList.remove('hidden');
  }

  async function decryptAndRender(sessionData, keyOrPassword) {
    const session = await decryptSession(
      sessionData.encryptedBlob,
      sessionData.iv,
      keyOrPassword,
      sessionData.salt
    );

    passwordPrompt.classList.add('hidden');
    viewer.classList.remove('hidden');

    // Render header
    document.getElementById('header').innerHTML = \`
      <div class="header-main">
        <div class="logo">
          <span class="logo-icon">◈</span>
          <span class="logo-text">claude<span class="accent">review</span></span>
        </div>
        <div class="session-id">\${session.id.slice(0, 8)}</div>
      </div>
      <h1 class="session-title">\${escapeHtml(session.title)}</h1>
      <div class="session-meta">
        <span>\${session.metadata.messageCount} messages</span>
        <span>·</span>
        <span>\${formatDuration(session.metadata.durationSeconds)}</span>
      </div>
    \`;

    // Render messages
    document.getElementById('messages').innerHTML = session.messages.map(renderMessage).join('');
  }

  function renderMessage(msg) {
    switch (msg.type) {
      case 'human':
        return '<div class="message human"><div class="message-content">' + escapeHtml(msg.content) + '</div></div>';
      case 'assistant':
        return '<div class="message assistant"><div class="message-content">' + formatContent(msg.content) + '</div></div>';
      case 'tool_call':
        return '<div class="tool-box"><div class="tool-header"><span class="tool-name">' + (msg.toolName || 'Tool') + '</span></div><div class="tool-summary">' + escapeHtml(msg.content) + '</div></div>';
      case 'tool_result':
        return '<div class="tool-output"><pre class="output-content">' + escapeHtml(msg.toolOutput || msg.content) + '</pre></div>';
      default:
        return '';
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  function formatContent(content) {
    return (content || '').split('\\n\\n').map(p => '<p>' + escapeHtml(p) + '</p>').join('');
  }

  function formatDuration(seconds) {
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.round(seconds / 60) + 'min';
    return Math.floor(seconds / 3600) + 'h ' + Math.round((seconds % 3600) / 60) + 'm';
  }
})();
`;

// Start server
const port = parseInt(process.env.PORT || '3000', 10);
console.log(`Server starting on port ${port}...`);

export default {
  port,
  fetch: app.fetch,
};
