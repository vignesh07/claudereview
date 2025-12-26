import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { setCookie, getCookie, deleteCookie } from 'hono/cookie';
import { nanoid } from 'nanoid';
import { z } from 'zod';
import { db, sessions, users, apiKeys, type NewSession, type Session, type User } from './db/index.ts';
import { eq, sql, desc, count, and } from 'drizzle-orm';
import { decrypt, encrypt, encryptForPublic, encryptForPrivate, generateKey, deriveKey, generateSalt } from './crypto.ts';

const app = new Hono();

// Environment
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-in-production';

// Simple session store (in production, use Redis or database)
const sessionStore = new Map<string, { userId: string; expiresAt: number }>();

// Middleware
app.use('*', logger());
app.use('/api/*', cors());

// Auth helper
async function getCurrentUser(c: any): Promise<User | null> {
  const sessionId = getCookie(c, 'session');
  if (!sessionId) return null;

  const session = sessionStore.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessionStore.delete(sessionId);
    return null;
  }

  if (!db) return null;

  const [user] = await db.select().from(users).where(eq(users.id, session.userId)).limit(1);
  return user || null;
}

// Health check
app.get('/health', (c) => c.json({ status: 'ok' }));

// ============================================================================
// GitHub OAuth
// ============================================================================

app.get('/auth/github', (c) => {
  if (!GITHUB_CLIENT_ID) {
    return c.json({ error: 'GitHub OAuth not configured' }, 500);
  }

  const state = nanoid(16);
  setCookie(c, 'oauth_state', state, {
    httpOnly: true,
    secure: BASE_URL.startsWith('https'),
    sameSite: 'Lax',
    maxAge: 600, // 10 minutes
  });

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/github/callback`,
    scope: 'read:user',
    state,
  });

  return c.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

app.get('/auth/github/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const storedState = getCookie(c, 'oauth_state');

  deleteCookie(c, 'oauth_state');

  if (!code || !state || state !== storedState) {
    return c.redirect('/?error=invalid_state');
  }

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    return c.redirect('/?error=oauth_not_configured');
  }

  try {
    // Exchange code for token
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    const tokenData = await tokenRes.json() as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      return c.redirect('/?error=token_failed');
    }

    // Get user info
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/json',
      },
    });

    const githubUser = await userRes.json() as {
      id: number;
      login: string;
      avatar_url: string;
    };

    if (!db) {
      return c.redirect('/?error=db_not_configured');
    }

    // Find or create user
    let [user] = await db.select().from(users).where(eq(users.githubId, String(githubUser.id))).limit(1);

    if (!user) {
      const userId = nanoid(12);
      await db.insert(users).values({
        id: userId,
        githubId: String(githubUser.id),
        githubUsername: githubUser.login,
        githubAvatarUrl: githubUser.avatar_url,
      });
      [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    } else {
      // Update username/avatar if changed
      await db.update(users)
        .set({
          githubUsername: githubUser.login,
          githubAvatarUrl: githubUser.avatar_url,
        })
        .where(eq(users.id, user.id));
    }

    // Create session
    const sessionId = nanoid(32);
    sessionStore.set(sessionId, {
      userId: user!.id,
      expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    setCookie(c, 'session', sessionId, {
      httpOnly: true,
      secure: BASE_URL.startsWith('https'),
      sameSite: 'Lax',
      maxAge: 30 * 24 * 60 * 60, // 30 days
      path: '/',
    });

    return c.redirect('/dashboard');
  } catch (error) {
    console.error('OAuth error:', error);
    return c.redirect('/?error=oauth_failed');
  }
});

app.get('/auth/logout', (c) => {
  const sessionId = getCookie(c, 'session');
  if (sessionId) {
    sessionStore.delete(sessionId);
    deleteCookie(c, 'session');
  }
  return c.redirect('/');
});

// ============================================================================
// User API
// ============================================================================

app.get('/api/me', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.json({ error: 'Not authenticated' }, 401);
  }
  return c.json({
    id: user.id,
    username: user.githubUsername,
    avatarUrl: user.githubAvatarUrl,
  });
});

app.get('/api/my-sessions', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.json({ error: 'Not authenticated' }, 401);
  }

  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  const userSessions = await db.select({
    id: sessions.id,
    title: sessions.title,
    messageCount: sessions.messageCount,
    toolCount: sessions.toolCount,
    durationSeconds: sessions.durationSeconds,
    visibility: sessions.visibility,
    viewCount: sessions.viewCount,
    createdAt: sessions.createdAt,
    ownerKey: sessions.ownerKey, // Include key for public session links
  })
    .from(sessions)
    .where(eq(sessions.userId, user.id))
    .orderBy(desc(sessions.createdAt));

  return c.json({ sessions: userSessions });
});

app.delete('/api/sessions/:id', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.json({ error: 'Not authenticated' }, 401);
  }

  const sessionId = c.req.param('id');
  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  // Verify ownership
  const [session] = await db.select().from(sessions).where(
    and(eq(sessions.id, sessionId), eq(sessions.userId, user.id))
  ).limit(1);

  if (!session) {
    return c.json({ error: 'Session not found or not owned by you' }, 404);
  }

  await db.delete(sessions).where(eq(sessions.id, sessionId));
  return c.json({ success: true });
});

app.patch('/api/sessions/:id', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.json({ error: 'Not authenticated' }, 401);
  }

  const sessionId = c.req.param('id');
  const body = await c.req.json() as {
    title?: string;
    visibility?: 'public' | 'private';
    password?: string;
    currentPassword?: string;
  };

  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  // Verify ownership
  const [session] = await db.select().from(sessions).where(
    and(eq(sessions.id, sessionId), eq(sessions.userId, user.id))
  ).limit(1);

  if (!session) {
    return c.json({ error: 'Session not found or not owned by you' }, 404);
  }

  const updates: Partial<Session> = {};
  let newKey: string | undefined;

  // Handle title update
  if (body.title) {
    updates.title = body.title.slice(0, 200);
  }

  // Handle visibility change (requires re-encryption)
  if (body.visibility && body.visibility !== session.visibility) {
    let decryptedData: string;

    try {
      // Decrypt based on current session type
      if (session.visibility === 'private' && session.salt) {
        // Private session: need current password to decrypt
        if (!body.currentPassword) {
          return c.json({ error: 'Current password required to change private session' }, 400);
        }
        const derivedKey = deriveKey(body.currentPassword, session.salt);
        decryptedData = decrypt(session.encryptedBlob, session.iv, derivedKey);
      } else if (session.ownerKey) {
        // Public session with ownerKey
        decryptedData = decrypt(session.encryptedBlob, session.iv, session.ownerKey);
      } else {
        return c.json({ error: 'Cannot change visibility: encryption key not available' }, 400);
      }

      if (body.visibility === 'private') {
        // Changing to private: encrypt with password
        if (!body.password) {
          return c.json({ error: 'Password required for private sessions' }, 400);
        }

        const encrypted = encryptForPrivate(decryptedData, body.password);
        updates.encryptedBlob = encrypted.ciphertext;
        updates.iv = encrypted.iv;
        updates.salt = encrypted.salt;
        updates.ownerKey = null; // No key storage for password-protected sessions
        updates.visibility = 'private';
      } else {
        // Changing to public: encrypt with random key
        const encrypted = encryptForPublic(decryptedData);
        updates.encryptedBlob = encrypted.ciphertext;
        updates.iv = encrypted.iv;
        updates.salt = null;
        updates.ownerKey = encrypted.key; // Store key for owner access
        updates.visibility = 'public';
        newKey = encrypted.key; // Return to client for URL
      }
    } catch (err) {
      console.error('Re-encryption failed:', err);
      return c.json({ error: 'Failed to change visibility. Wrong password?' }, 500);
    }
  }

  if (Object.keys(updates).length > 0) {
    await db.update(sessions).set(updates).where(eq(sessions.id, sessionId));
  }

  return c.json({ success: true, newKey });
});

// ============================================================================
// API Keys Management
// ============================================================================

// Hash function for API keys
async function hashApiKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Create API key
app.post('/api/keys', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.json({ error: 'Not authenticated' }, 401);
  }

  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  const body = await c.req.json() as { name?: string };
  const name = body.name || 'CLI Key';

  // Generate a random API key
  const rawKey = `cr_${nanoid(32)}`;
  const keyHash = await hashApiKey(rawKey);
  const keyId = nanoid(12);

  await db.insert(apiKeys).values({
    id: keyId,
    userId: user.id,
    keyHash,
    name: name.slice(0, 50),
  });

  // Return the raw key only once - we only store the hash
  return c.json({
    id: keyId,
    key: rawKey,
    name,
    createdAt: new Date().toISOString(),
  });
});

// List API keys
app.get('/api/keys', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.json({ error: 'Not authenticated' }, 401);
  }

  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  const keys = await db.select({
    id: apiKeys.id,
    name: apiKeys.name,
    createdAt: apiKeys.createdAt,
    lastUsedAt: apiKeys.lastUsedAt,
  })
    .from(apiKeys)
    .where(eq(apiKeys.userId, user.id))
    .orderBy(desc(apiKeys.createdAt));

  return c.json({ keys });
});

// Delete API key
app.delete('/api/keys/:id', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.json({ error: 'Not authenticated' }, 401);
  }

  const keyId = c.req.param('id');
  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  // Verify ownership
  const [key] = await db.select().from(apiKeys).where(
    and(eq(apiKeys.id, keyId), eq(apiKeys.userId, user.id))
  ).limit(1);

  if (!key) {
    return c.json({ error: 'API key not found' }, 404);
  }

  await db.delete(apiKeys).where(eq(apiKeys.id, keyId));
  return c.json({ success: true });
});

// Upload schema
const uploadSchema = z.object({
  encryptedBlob: z.string(),
  iv: z.string(),
  salt: z.string().optional(),
  ownerKey: z.string().optional(), // encryption key for owner to view later
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

    // Get user from session cookie (if logged in via web)
    const user = await getCurrentUser(c);
    let userId: string | null = user?.id || null;

    // Also check API key auth header (for CLI)
    if (!userId) {
      const authHeader = c.req.header('Authorization');
      if (authHeader?.startsWith('Bearer ') && db) {
        const token = authHeader.slice(7);
        // Hash the token and lookup API key
        const tokenHash = await hashApiKey(token);
        const [apiKeyRecord] = await db.select()
          .from(apiKeys)
          .where(eq(apiKeys.keyHash, tokenHash))
          .limit(1);
        if (apiKeyRecord) {
          userId = apiKeyRecord.userId;
          // Update last used
          await db.update(apiKeys)
            .set({ lastUsedAt: new Date() })
            .where(eq(apiKeys.id, apiKeyRecord.id));
        }
      }
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
      ownerKey: userId && parsed.ownerKey ? parsed.ownerKey : null, // Only store key if authenticated
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

    // Check if requester is the owner
    const user = await getCurrentUser(c);
    const isOwner = user && session.userId === user.id;

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
      ownerKey: isOwner ? session.ownerKey : undefined, // Only include key for owner
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
app.get('/', async (c) => {
  const user = await getCurrentUser(c);
  return c.html(generateLandingHtml(user));
});

// Admin middleware (for API only)
const requireAdminApi = async (c: any, next: any) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) {
    return c.json({ error: 'Admin not configured' }, 500);
  }

  const authHeader = c.req.header('Authorization');
  const providedKey = authHeader?.replace('Bearer ', '');

  if (providedKey !== adminKey) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  await next();
};

// Admin API: Get analytics
app.get('/api/admin/stats', requireAdminApi, async (c) => {
  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  try {
    // Total sessions
    const [totalResult] = await db.select({ count: count() }).from(sessions);
    const totalSessions = totalResult?.count || 0;

    // Total views
    const [viewsResult] = await db.select({
      total: sql<number>`COALESCE(SUM(${sessions.viewCount}), 0)`
    }).from(sessions);
    const totalViews = viewsResult?.total || 0;

    // Public vs private
    const visibilityStats = await db.select({
      visibility: sessions.visibility,
      count: count(),
    }).from(sessions).groupBy(sessions.visibility);

    // Recent sessions (last 20)
    const recentSessions = await db.select({
      id: sessions.id,
      title: sessions.title,
      visibility: sessions.visibility,
      viewCount: sessions.viewCount,
      createdAt: sessions.createdAt,
    }).from(sessions).orderBy(desc(sessions.createdAt)).limit(20);

    // Sessions per day (last 30 days)
    const sessionsPerDay = await db.select({
      date: sql<string>`DATE(${sessions.createdAt})`,
      count: count(),
    }).from(sessions)
      .where(sql`${sessions.createdAt} > NOW() - INTERVAL '30 days'`)
      .groupBy(sql`DATE(${sessions.createdAt})`)
      .orderBy(sql`DATE(${sessions.createdAt})`);

    // Top viewed sessions
    const topViewed = await db.select({
      id: sessions.id,
      title: sessions.title,
      viewCount: sessions.viewCount,
    }).from(sessions).orderBy(desc(sessions.viewCount)).limit(10);

    return c.json({
      totalSessions,
      totalViews,
      visibilityStats,
      recentSessions,
      sessionsPerDay,
      topViewed,
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    return c.json({ error: 'Failed to get stats' }, 500);
  }
});

// User dashboard
app.get('/dashboard', async (c) => {
  const user = await getCurrentUser(c);
  if (!user) {
    return c.redirect('/auth/github');
  }
  return c.html(generateDashboardHtml(user));
});

// Admin dashboard page (auth handled client-side)
app.get('/admin', async (c) => {
  return c.html(generateAdminHtml());
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

function generateLandingHtml(user: User | null): string {
  const headerRight = user
    ? `<a href="/dashboard" class="user-link">
        <img src="${escapeHtml(user.githubAvatarUrl || '')}" alt="" class="avatar">
        <span class="username">${escapeHtml(user.githubUsername)}</span>
      </a>`
    : `<a href="/auth/github" class="login-btn">Sign in with GitHub</a>`;

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
      ${headerRight}
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

function generateDashboardHtml(user: User): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>My Sessions - claudereview</title>
  <style>${DASHBOARD_CSS}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <span class="logo-icon">◈</span>
        <a href="/" class="logo-text">claude<span class="accent">review</span></a>
      </div>
      <div class="user-info">
        <img src="${escapeHtml(user.githubAvatarUrl || '')}" alt="" class="avatar">
        <span class="username">${escapeHtml(user.githubUsername)}</span>
        <a href="/auth/logout" class="logout-link">Logout</a>
      </div>
    </header>

    <main>
      <h1>My Sessions</h1>
      <p class="subtitle">Manage your shared Claude Code sessions</p>

      <div id="sessions-list" class="sessions-list">
        <div class="loading">Loading sessions...</div>
      </div>

      <div id="empty-state" class="empty-state hidden">
        <div class="empty-icon">📭</div>
        <h2>No sessions yet</h2>
        <p>Share your first Claude Code session using the CLI or MCP server.</p>
        <pre><code>ccshare share --last</code></pre>
      </div>

      <section class="api-keys-section">
        <h2>API Keys</h2>
        <p class="subtitle">Use API keys to link CLI sessions to your account</p>

        <div id="api-keys-list" class="api-keys-list">
          <div class="loading">Loading...</div>
        </div>

        <button id="create-key-btn" class="btn-primary" style="margin-top: 1rem;">
          + Generate New Key
        </button>
      </section>
    </main>
  </div>

  <!-- Edit Modal -->
  <div id="edit-modal" class="modal hidden">
    <div class="modal-backdrop"></div>
    <div class="modal-content">
      <h2>Edit Session</h2>
      <form id="edit-form">
        <label>
          Title
          <input type="text" id="edit-title" maxlength="200">
        </label>
        <label>
          Visibility
          <select id="edit-visibility">
            <option value="public">Public (link with key)</option>
            <option value="private">Private (password protected)</option>
          </select>
        </label>
        <div id="current-password-fields" class="hidden">
          <label>
            Current Password
            <input type="password" id="edit-current-password" placeholder="Enter current password">
          </label>
          <p class="field-hint">Required to change visibility of a private session.</p>
        </div>
        <div id="new-password-fields" class="hidden">
          <label>
            New Password
            <input type="password" id="edit-password" placeholder="Enter password for private session">
          </label>
          <p class="field-hint">Required when changing to private. Anyone with the password can view.</p>
        </div>
        <div id="edit-error" class="edit-error hidden"></div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" onclick="closeModal()">Cancel</button>
          <button type="submit" class="btn-primary">Save</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Delete Confirmation Modal -->
  <div id="delete-modal" class="modal hidden">
    <div class="modal-backdrop"></div>
    <div class="modal-content">
      <h2>Delete Session?</h2>
      <p>This action cannot be undone. The session will be permanently deleted.</p>
      <div class="modal-actions">
        <button type="button" class="btn-secondary" onclick="closeDeleteModal()">Cancel</button>
        <button type="button" class="btn-danger" id="confirm-delete">Delete</button>
      </div>
    </div>
  </div>

  <!-- New API Key Modal -->
  <div id="new-key-modal" class="modal hidden">
    <div class="modal-backdrop"></div>
    <div class="modal-content">
      <h2>API Key Created</h2>
      <p>Copy this key now. You won't be able to see it again!</p>
      <div class="key-display">
        <code id="new-key-value"></code>
        <button class="btn-icon" onclick="copyNewKey()" title="Copy">📋</button>
      </div>
      <div class="key-usage">
        <p>Add to your shell profile:</p>
        <pre><code>export CCSHARE_API_KEY="<span id="new-key-export"></span>"</code></pre>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn-primary" onclick="closeNewKeyModal()">Done</button>
      </div>
    </div>
  </div>

  <!-- Delete Key Confirmation Modal -->
  <div id="delete-key-modal" class="modal hidden">
    <div class="modal-backdrop"></div>
    <div class="modal-content">
      <h2>Revoke API Key?</h2>
      <p>This key will stop working immediately. Any CLI using it will need a new key.</p>
      <div class="modal-actions">
        <button type="button" class="btn-secondary" onclick="closeDeleteKeyModal()">Cancel</button>
        <button type="button" class="btn-danger" id="confirm-delete-key">Revoke</button>
      </div>
    </div>
  </div>

  <script>
    let currentEditId = null;
    let currentDeleteId = null;

    async function loadSessions() {
      try {
        const res = await fetch('/api/my-sessions');
        if (!res.ok) throw new Error('Failed to load');
        const data = await res.json();

        const list = document.getElementById('sessions-list');
        const empty = document.getElementById('empty-state');

        if (data.sessions.length === 0) {
          list.classList.add('hidden');
          empty.classList.remove('hidden');
          return;
        }

        list.innerHTML = data.sessions.map(s => \`
          <div class="session-card" data-id="\${s.id}">
            <div class="session-main">
              <div class="session-title">\${escapeHtml(s.title)}</div>
              <div class="session-meta">
                <span>\${s.messageCount} messages</span>
                <span class="sep">·</span>
                <span>\${s.toolCount} tools</span>
                <span class="sep">·</span>
                <span>\${s.viewCount} views</span>
                <span class="sep">·</span>
                <span>\${formatDate(s.createdAt)}</span>
                <span class="visibility-badge \${s.visibility}">\${s.visibility === 'private' ? 'Private' : 'Public'}</span>
              </div>
            </div>
            <div class="session-actions">
              <button class="btn-text" onclick="copyLink('\${s.id}', '\${s.ownerKey || ''}')">Copy</button>
              <a href="/s/\${s.id}\${s.ownerKey ? '#key=' + s.ownerKey : ''}" class="btn-text" target="_blank">View</a>
              <button class="btn-text" onclick="openEditModal('\${s.id}', '\${escapeHtml(s.title).replace(/'/g, "\\\\'")}', '\${s.visibility}')">Edit</button>
              <button class="btn-icon btn-danger" onclick="openDeleteModal('\${s.id}')" title="Delete">×</button>
            </div>
          </div>
        \`).join('');
      } catch (err) {
        document.getElementById('sessions-list').innerHTML =
          '<div class="error">Failed to load sessions. Please try again.</div>';
      }
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str || '';
      return div.innerHTML;
    }

    function formatDate(dateStr) {
      const date = new Date(dateStr);
      const now = new Date();
      const diffMs = now - date;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

      if (diffDays === 0) return 'Today';
      if (diffDays === 1) return 'Yesterday';
      if (diffDays < 7) return diffDays + ' days ago';
      return date.toLocaleDateString();
    }

    function showToast(message) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    function copyLink(id, key) {
      let url = window.location.origin + '/s/' + id;
      if (key) url += '#key=' + key;
      navigator.clipboard.writeText(url);
      // Show brief feedback
      const btn = event.target;
      btn.textContent = 'Copied!';
      btn.disabled = true;
      setTimeout(() => {
        btn.textContent = 'Copy';
        btn.disabled = false;
      }, 1500);
    }

    let currentEditVisibility = null;

    function openEditModal(id, title, visibility) {
      currentEditId = id;
      currentEditVisibility = visibility;
      document.getElementById('edit-title').value = title;
      document.getElementById('edit-visibility').value = visibility;
      document.getElementById('edit-password').value = '';
      document.getElementById('edit-current-password').value = '';
      document.getElementById('edit-error').classList.add('hidden');
      updatePasswordFieldVisibility();
      document.getElementById('edit-modal').classList.remove('hidden');
    }

    function updatePasswordFieldVisibility() {
      const newVisibility = document.getElementById('edit-visibility').value;
      const currentPasswordFields = document.getElementById('current-password-fields');
      const newPasswordFields = document.getElementById('new-password-fields');

      // Show current password when changing FROM private
      if (currentEditVisibility === 'private' && newVisibility !== currentEditVisibility) {
        currentPasswordFields.classList.remove('hidden');
      } else {
        currentPasswordFields.classList.add('hidden');
      }

      // Show new password when changing TO private
      if (newVisibility === 'private' && currentEditVisibility === 'public') {
        newPasswordFields.classList.remove('hidden');
      } else {
        newPasswordFields.classList.add('hidden');
      }
    }

    document.getElementById('edit-visibility').addEventListener('change', updatePasswordFieldVisibility);

    function closeModal() {
      document.getElementById('edit-modal').classList.add('hidden');
      currentEditId = null;
      currentEditVisibility = null;
    }

    function openDeleteModal(id) {
      currentDeleteId = id;
      document.getElementById('delete-modal').classList.remove('hidden');
    }

    function closeDeleteModal() {
      document.getElementById('delete-modal').classList.add('hidden');
      currentDeleteId = null;
    }

    document.getElementById('edit-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const title = document.getElementById('edit-title').value;
      const visibility = document.getElementById('edit-visibility').value;
      const password = document.getElementById('edit-password').value;
      const currentPassword = document.getElementById('edit-current-password').value;
      const errorEl = document.getElementById('edit-error');
      errorEl.classList.add('hidden');

      // Validate: current password required when changing FROM private
      if (currentEditVisibility === 'private' && visibility !== currentEditVisibility && !currentPassword) {
        errorEl.textContent = 'Current password is required to change visibility';
        errorEl.classList.remove('hidden');
        return;
      }

      // Validate: new password required when changing TO private
      if (visibility === 'private' && currentEditVisibility === 'public' && !password) {
        errorEl.textContent = 'Password is required when making a session private';
        errorEl.classList.remove('hidden');
        return;
      }

      try {
        const body = { title };
        if (visibility !== currentEditVisibility) {
          body.visibility = visibility;
          if (password) body.password = password;
          if (currentPassword) body.currentPassword = currentPassword;
        }

        const res = await fetch('/api/sessions/' + currentEditId, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });

        const data = await res.json();

        if (!res.ok) {
          throw new Error(data.error || 'Failed to update');
        }

        // Save ID before closing modal (closeModal clears it)
        const sessionId = currentEditId;
        closeModal();

        // Reload sessions first so UI updates
        await loadSessions();

        // If we got a new key (changed to public), copy and show toast
        if (data.newKey) {
          const newUrl = window.location.origin + '/s/' + sessionId + '#key=' + data.newKey;
          navigator.clipboard.writeText(newUrl);
          showToast('Session is now public! Link copied to clipboard.');
        } else {
          showToast('Session updated successfully.');
        }
      } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
      }
    });

    document.getElementById('confirm-delete').addEventListener('click', async () => {
      try {
        const res = await fetch('/api/sessions/' + currentDeleteId, {
          method: 'DELETE'
        });

        if (!res.ok) throw new Error('Failed to delete');
        closeDeleteModal();
        loadSessions();
      } catch (err) {
        alert('Failed to delete session');
      }
    });

    // Close modals on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(el => {
      el.addEventListener('click', () => {
        closeModal();
        closeDeleteModal();
        closeNewKeyModal();
        closeDeleteKeyModal();
      });
    });

    // ========== API Keys Management ==========
    let currentDeleteKeyId = null;
    let currentNewKey = null;

    async function loadApiKeys() {
      try {
        const res = await fetch('/api/keys');
        if (!res.ok) throw new Error('Failed to load');
        const data = await res.json();

        const list = document.getElementById('api-keys-list');

        if (data.keys.length === 0) {
          list.innerHTML = '<div class="no-keys">No API keys yet. Generate one to link CLI sessions to your account.</div>';
          return;
        }

        list.innerHTML = data.keys.map(k => \`
          <div class="api-key-card">
            <div class="key-info">
              <span class="key-name">\${escapeHtml(k.name)}</span>
              <span class="key-meta">Created \${formatDate(k.createdAt)}\${k.lastUsedAt ? ' · Last used ' + formatDate(k.lastUsedAt) : ''}</span>
            </div>
            <button class="btn-icon btn-danger" onclick="openDeleteKeyModal('\${k.id}')" title="Revoke">×</button>
          </div>
        \`).join('');
      } catch (err) {
        document.getElementById('api-keys-list').innerHTML =
          '<div class="error">Failed to load API keys.</div>';
      }
    }

    document.getElementById('create-key-btn').addEventListener('click', async () => {
      try {
        const res = await fetch('/api/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'CLI Key' })
        });

        if (!res.ok) throw new Error('Failed to create');
        const data = await res.json();

        currentNewKey = data.key;
        document.getElementById('new-key-value').textContent = data.key;
        document.getElementById('new-key-export').textContent = data.key;
        document.getElementById('new-key-modal').classList.remove('hidden');

        loadApiKeys();
      } catch (err) {
        alert('Failed to create API key');
      }
    });

    function copyNewKey() {
      if (currentNewKey) {
        navigator.clipboard.writeText(currentNewKey);
        const btn = event.target;
        const original = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => btn.textContent = original, 1500);
      }
    }

    function closeNewKeyModal() {
      document.getElementById('new-key-modal').classList.add('hidden');
      currentNewKey = null;
    }

    function openDeleteKeyModal(id) {
      currentDeleteKeyId = id;
      document.getElementById('delete-key-modal').classList.remove('hidden');
    }

    function closeDeleteKeyModal() {
      document.getElementById('delete-key-modal').classList.add('hidden');
      currentDeleteKeyId = null;
    }

    document.getElementById('confirm-delete-key').addEventListener('click', async () => {
      try {
        const res = await fetch('/api/keys/' + currentDeleteKeyId, {
          method: 'DELETE'
        });

        if (!res.ok) throw new Error('Failed to delete');
        closeDeleteKeyModal();
        loadApiKeys();
      } catch (err) {
        alert('Failed to revoke API key');
      }
    });

    // Load data on page load
    loadSessions();
    loadApiKeys();
  </script>

  <div id="toast" class="toast"></div>
</body>
</html>`;
}

function generateAdminHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard - claudereview</title>
  <style>${ADMIN_CSS}</style>
</head>
<body>
  <!-- Login prompt -->
  <div id="login-screen" class="login-screen">
    <div class="login-box">
      <div class="logo">
        <span class="logo-icon">◈</span>
        <span class="logo-text">claude<span class="accent">review</span></span>
        <span class="admin-badge">admin</span>
      </div>
      <form id="login-form">
        <input type="password" id="admin-key" placeholder="Admin password" autocomplete="off" autofocus>
        <button type="submit">Login</button>
      </form>
      <div id="login-error" class="error hidden">Invalid password</div>
    </div>
  </div>

  <!-- Dashboard (hidden until authenticated) -->
  <div id="dashboard" class="container hidden">
    <header>
      <div class="logo">
        <span class="logo-icon">◈</span>
        <span class="logo-text">claude<span class="accent">review</span></span>
        <span class="admin-badge">admin</span>
      </div>
      <button id="logout-btn" class="logout-btn">Logout</button>
    </header>

    <main>
      <div class="stats-grid" id="stats-grid">
        <div class="stat-card">
          <div class="stat-value" id="total-sessions">-</div>
          <div class="stat-label">Total Sessions</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="total-views">-</div>
          <div class="stat-label">Total Views</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="public-count">-</div>
          <div class="stat-label">Public</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="private-count">-</div>
          <div class="stat-label">Private</div>
        </div>
      </div>

      <section class="section">
        <h2>Sessions per Day (Last 30 days)</h2>
        <div class="chart" id="chart"></div>
      </section>

      <section class="section">
        <h2>Top Viewed Sessions</h2>
        <table class="data-table" id="top-viewed">
          <thead>
            <tr><th>Title</th><th>Views</th><th>Link</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </section>

      <section class="section">
        <h2>Recent Sessions</h2>
        <table class="data-table" id="recent-sessions">
          <thead>
            <tr><th>Title</th><th>Type</th><th>Views</th><th>Created</th><th>Link</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </section>
    </main>
  </div>
  <script>
    (function() {
      const loginScreen = document.getElementById('login-screen');
      const dashboard = document.getElementById('dashboard');
      const loginForm = document.getElementById('login-form');
      const loginError = document.getElementById('login-error');
      const adminKeyInput = document.getElementById('admin-key');
      const logoutBtn = document.getElementById('logout-btn');

      // Check for saved session
      const savedKey = sessionStorage.getItem('adminKey');
      if (savedKey) {
        authenticate(savedKey);
      }

      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const key = adminKeyInput.value;
        loginError.classList.add('hidden');
        await authenticate(key);
      });

      logoutBtn.addEventListener('click', () => {
        sessionStorage.removeItem('adminKey');
        loginScreen.classList.remove('hidden');
        dashboard.classList.add('hidden');
        adminKeyInput.value = '';
      });

      async function authenticate(key) {
        try {
          const res = await fetch('/api/admin/stats', {
            headers: { 'Authorization': 'Bearer ' + key }
          });

          if (!res.ok) {
            loginError.classList.remove('hidden');
            sessionStorage.removeItem('adminKey');
            return;
          }

          sessionStorage.setItem('adminKey', key);
          const data = await res.json();
          renderDashboard(data);
          loginScreen.classList.add('hidden');
          dashboard.classList.remove('hidden');
        } catch (err) {
          loginError.textContent = 'Error: ' + err.message;
          loginError.classList.remove('hidden');
        }
      }

      function renderDashboard(data) {
        document.getElementById('total-sessions').textContent = data.totalSessions.toLocaleString();
        document.getElementById('total-views').textContent = data.totalViews.toLocaleString();

        const publicCount = data.visibilityStats.find(s => s.visibility === 'public')?.count || 0;
        const privateCount = data.visibilityStats.find(s => s.visibility === 'private')?.count || 0;
        document.getElementById('public-count').textContent = publicCount.toLocaleString();
        document.getElementById('private-count').textContent = privateCount.toLocaleString();

        // Render chart
        const chart = document.getElementById('chart');
        if (data.sessionsPerDay.length === 0) {
          chart.innerHTML = '<div class="no-data">No data yet</div>';
        } else {
          const maxCount = Math.max(...data.sessionsPerDay.map(d => d.count), 1);
          chart.innerHTML = data.sessionsPerDay.map(d => {
            const height = (d.count / maxCount * 100).toFixed(0);
            const date = new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            return '<div class="bar" style="height:' + height + '%"><span class="bar-value">' + d.count + '</span><span class="bar-label">' + date + '</span></div>';
          }).join('');
        }

        // Top viewed
        const topViewedBody = document.querySelector('#top-viewed tbody');
        if (data.topViewed.length === 0) {
          topViewedBody.innerHTML = '<tr><td colspan="3" class="no-data">No sessions yet</td></tr>';
        } else {
          topViewedBody.innerHTML = data.topViewed.map(s =>
            '<tr><td>' + escapeHtml(s.title?.slice(0,50) || 'Untitled') + '</td><td>' + s.viewCount + '</td><td><a href="/s/' + s.id + '">View</a></td></tr>'
          ).join('');
        }

        // Recent sessions
        const recentBody = document.querySelector('#recent-sessions tbody');
        if (data.recentSessions.length === 0) {
          recentBody.innerHTML = '<tr><td colspan="5" class="no-data">No sessions yet</td></tr>';
        } else {
          recentBody.innerHTML = data.recentSessions.map(s => {
            const date = new Date(s.createdAt).toLocaleDateString();
            const type = s.visibility === 'private' ? '🔐' : '🔗';
            return '<tr><td>' + escapeHtml(s.title?.slice(0,50) || 'Untitled') + '</td><td>' + type + '</td><td>' + s.viewCount + '</td><td>' + date + '</td><td><a href="/s/' + s.id + '">View</a></td></tr>';
          }).join('');
        }
      }

      function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
      }
    })();
  </script>
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
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.logo-icon { color: var(--accent); font-size: 1.5rem; }
.logo-text { font-size: 1.25rem; color: var(--text-muted); }
.accent { color: var(--accent); }

.login-btn {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 1rem;
  color: var(--text);
  text-decoration: none;
  font-size: 0.875rem;
  transition: all 0.15s;
}

.login-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}

.user-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
  color: var(--text);
  padding: 0.25rem 0.5rem;
  border-radius: 6px;
  transition: background 0.15s;
}

.user-link:hover {
  background: var(--bg-secondary);
}

.user-link .avatar {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: 2px solid var(--border);
}

.user-link .username {
  font-size: 0.875rem;
}

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

const ADMIN_CSS = `
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
  --purple: #a371f7;
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
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
}

header {
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.logo-icon { color: var(--accent); font-size: 1.5rem; }
.logo-text { font-size: 1.25rem; color: var(--text-muted); }
.accent { color: var(--accent); }

.admin-badge {
  background: var(--purple);
  color: white;
  font-size: 0.75rem;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  margin-left: 0.5rem;
  font-weight: 500;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin-bottom: 2rem;
}

.stat-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  text-align: center;
}

.stat-value {
  font-size: 2rem;
  font-weight: 600;
  color: var(--text-bright);
  font-family: var(--font-sans);
}

.stat-label {
  color: var(--text-muted);
  font-size: 0.875rem;
  margin-top: 0.5rem;
}

.section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}

.section h2 {
  font-family: var(--font-sans);
  font-size: 1rem;
  color: var(--text-bright);
  margin-bottom: 1rem;
}

.chart {
  display: flex;
  align-items: flex-end;
  gap: 4px;
  height: 150px;
  padding: 1rem 0;
}

.bar {
  flex: 1;
  min-width: 20px;
  background: linear-gradient(to top, var(--accent), var(--purple));
  border-radius: 4px 4px 0 0;
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  min-height: 4px;
}

.bar-value {
  font-size: 0.625rem;
  color: var(--text-bright);
  position: absolute;
  top: -18px;
}

.bar-label {
  font-size: 0.5rem;
  color: var(--text-muted);
  position: absolute;
  bottom: -18px;
  white-space: nowrap;
  transform: rotate(-45deg);
  transform-origin: top left;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.data-table th,
.data-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.data-table th {
  color: var(--text-muted);
  font-weight: 500;
}

.data-table td {
  color: var(--text);
}

.data-table a {
  color: var(--accent);
  text-decoration: none;
}

.data-table a:hover {
  text-decoration: underline;
}

/* Login screen */
.login-screen {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--bg);
}

.login-box {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 2rem;
  text-align: center;
  width: 100%;
  max-width: 360px;
}

.login-box .logo {
  justify-content: center;
  margin-bottom: 2rem;
}

.login-box form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.login-box input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  font-family: var(--font-mono);
  font-size: 1rem;
  color: var(--text);
  text-align: center;
}

.login-box input:focus {
  outline: none;
  border-color: var(--accent);
}

.login-box button {
  background: var(--accent);
  border: none;
  border-radius: 6px;
  padding: 0.75rem;
  font-size: 1rem;
  font-weight: 500;
  color: white;
  cursor: pointer;
  font-family: var(--font-mono);
}

.login-box button:hover {
  opacity: 0.9;
}

.login-box .error {
  color: #f85149;
  font-size: 0.875rem;
  margin-top: 1rem;
}

.logout-btn {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 1rem;
  color: var(--text-muted);
  cursor: pointer;
  font-family: var(--font-mono);
  font-size: 0.875rem;
}

.logout-btn:hover {
  color: var(--text);
  border-color: var(--text-muted);
}

.hidden { display: none !important; }

.no-data {
  color: var(--text-muted);
  text-align: center;
  padding: 2rem;
  font-style: italic;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

@media (max-width: 768px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
}
`;

const DASHBOARD_CSS = `
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
  min-height: 100vh;
}

.container {
  max-width: 900px;
  margin: 0 auto;
  padding: 2rem;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border);
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.logo-icon { color: var(--accent); font-size: 1.5rem; }
.logo-text {
  font-size: 1.25rem;
  color: var(--text-muted);
  text-decoration: none;
}
.logo-text:hover { color: var(--text); }
.accent { color: var(--accent); }

.user-info {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  border: 2px solid var(--border);
}

.username {
  color: var(--text);
  font-weight: 500;
}

.logout-link {
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.875rem;
  padding: 0.25rem 0.5rem;
  border: 1px solid var(--border);
  border-radius: 4px;
}

.logout-link:hover {
  color: var(--text);
  border-color: var(--text-muted);
}

main h1 {
  font-family: var(--font-sans);
  font-size: 1.5rem;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
}

.subtitle {
  color: var(--text-muted);
  margin-bottom: 2rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.session-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: border-color 0.15s;
}

.session-card:hover {
  border-color: var(--text-muted);
}

.session-main {
  flex: 1;
  min-width: 0;
}

.session-title {
  font-weight: 500;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
  font-family: var(--font-sans);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.session-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  color: var(--text-muted);
  font-size: 0.8125rem;
}

.session-meta .sep { opacity: 0.5; }

.visibility-badge {
  font-size: 0.75rem;
  padding: 0.125rem 0.375rem;
  border-radius: 4px;
  margin-left: 0.5rem;
}

.visibility-badge.public {
  background: rgba(88, 166, 255, 0.15);
  color: var(--accent);
}

.visibility-badge.private {
  background: rgba(163, 113, 247, 0.15);
  color: var(--purple);
}

.session-actions {
  display: flex;
  gap: 0.5rem;
  margin-left: 1rem;
}

.btn-icon {
  background: transparent;
  border: 1px solid transparent;
  border-radius: 6px;
  padding: 0.5rem;
  cursor: pointer;
  font-size: 1rem;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s;
}

.btn-icon:hover {
  background: var(--bg-tertiary);
  border-color: var(--border);
}

.btn-icon.btn-danger:hover {
  background: rgba(248, 81, 73, 0.15);
  border-color: var(--red);
  color: var(--red);
}

.btn-text {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.375rem 0.75rem;
  cursor: pointer;
  font-size: 0.8125rem;
  font-family: var(--font-mono);
  color: var(--text-muted);
  text-decoration: none;
  transition: all 0.15s;
}

.btn-text:hover {
  background: var(--bg-tertiary);
  border-color: var(--text-muted);
  color: var(--text);
}

.btn-text:disabled {
  color: var(--green);
  border-color: var(--green);
  cursor: default;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
  color: var(--text-muted);
}

.empty-icon { font-size: 3rem; margin-bottom: 1rem; }
.empty-state h2 {
  font-family: var(--font-sans);
  color: var(--text-bright);
  margin-bottom: 0.5rem;
}
.empty-state p { margin-bottom: 1.5rem; }
.empty-state pre {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem 1.5rem;
  display: inline-block;
}

.loading {
  text-align: center;
  padding: 2rem;
  color: var(--text-muted);
}

.error {
  text-align: center;
  padding: 2rem;
  color: var(--red);
}

/* Modals */
.modal {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.modal-backdrop {
  position: absolute;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  backdrop-filter: blur(4px);
}

.modal-content {
  position: relative;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem;
  width: 100%;
  max-width: 400px;
  margin: 1rem;
}

.modal-content h2 {
  font-family: var(--font-sans);
  color: var(--text-bright);
  margin-bottom: 1rem;
}

.modal-content p {
  color: var(--text-muted);
  margin-bottom: 1.5rem;
}

.modal-content label {
  display: block;
  color: var(--text);
  font-size: 0.8125rem;
  font-weight: 500;
  margin-bottom: 1.25rem;
}

.modal-content input[type="text"],
.modal-content input[type="password"],
.modal-content select {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.625rem 0.75rem;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  color: var(--text);
  margin-top: 0.5rem;
}

.modal-content select {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%238b949e' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 0.75rem center;
  padding-right: 2rem;
  cursor: pointer;
}

.modal-content input:focus,
.modal-content select:focus {
  outline: none;
  border-color: var(--accent);
}

.modal-content select option {
  background: var(--bg-secondary);
  color: var(--text);
}

.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
}

.edit-error {
  background: rgba(248, 81, 73, 0.1);
  border: 1px solid rgba(248, 81, 73, 0.3);
  color: var(--red);
  padding: 0.75rem 1rem;
  border-radius: 6px;
  font-size: 0.8125rem;
  margin-bottom: 1rem;
}

.field-hint {
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-top: 0.375rem;
  line-height: 1.4;
}

#current-password-fields,
#new-password-fields {
  background: var(--bg-tertiary);
  border-radius: 8px;
  padding: 1rem;
  margin-top: -0.25rem;
  margin-bottom: 0.5rem;
}

#current-password-fields label,
#new-password-fields label {
  margin-bottom: 0;
}

#current-password-fields .field-hint,
#new-password-fields .field-hint {
  margin-top: 0.75rem;
}

.btn-secondary, .btn-primary, .btn-danger {
  border: none;
  border-radius: 6px;
  padding: 0.625rem 1rem;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  cursor: pointer;
  transition: opacity 0.15s;
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text);
  border: 1px solid var(--border);
}

.btn-primary {
  background: var(--accent);
  color: white;
}

.btn-danger {
  background: var(--red);
  color: white;
}

.btn-secondary:hover, .btn-primary:hover, .btn-danger:hover {
  opacity: 0.9;
}

/* Toast notification */
.toast {
  position: fixed;
  bottom: 2rem;
  left: 50%;
  transform: translateX(-50%) translateY(100px);
  background: var(--green);
  color: var(--bg);
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  opacity: 0;
  transition: all 0.3s ease;
  z-index: 1000;
  pointer-events: none;
}

.toast.show {
  transform: translateX(-50%) translateY(0);
  opacity: 1;
}

/* API Keys Section */
.api-keys-section {
  margin-top: 3rem;
  padding-top: 2rem;
  border-top: 1px solid var(--border);
}

.api-keys-section h2 {
  font-family: var(--font-sans);
  font-size: 1.25rem;
  color: var(--text-bright);
  margin-bottom: 0.25rem;
}

.api-keys-list {
  margin-top: 1rem;
}

.api-key-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem 1rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.key-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.key-name {
  font-weight: 500;
  color: var(--text-bright);
}

.key-meta {
  font-size: 0.75rem;
  color: var(--text-muted);
}

.no-keys {
  color: var(--text-muted);
  font-size: 0.875rem;
  padding: 1rem 0;
}

/* New Key Modal */
.key-display {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.key-display code {
  font-size: 0.8rem;
  color: var(--accent);
  word-break: break-all;
}

.key-usage {
  background: var(--bg-tertiary);
  border-radius: 6px;
  padding: 1rem;
  margin-bottom: 1.5rem;
}

.key-usage p {
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-bottom: 0.5rem;
}

.key-usage pre {
  font-size: 0.75rem;
  color: var(--text);
  overflow-x: auto;
}

.key-usage code {
  color: var(--green);
}

.hidden { display: none !important; }

@media (max-width: 640px) {
  .session-card {
    flex-direction: column;
    align-items: stretch;
  }
  .session-actions {
    margin-left: 0;
    margin-top: 1rem;
    justify-content: flex-end;
  }
  .user-info .username { display: none; }
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

    // Check for key in URL fragment or use ownerKey if available
    const hash = window.location.hash;
    const keyMatch = hash.match(/key=([^&]+)/);

    if (sessionData.ownerKey) {
      // Owner viewing their own session - use stored key
      await decryptAndRender(sessionData, sessionData.ownerKey);
    } else if (keyMatch && !sessionData.salt) {
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
    const decrypted = await decryptSession(
      sessionData.encryptedBlob,
      sessionData.iv,
      keyOrPassword,
      sessionData.salt
    );

    passwordPrompt.classList.add('hidden');
    viewer.classList.remove('hidden');

    // Check if this is the new format with pre-rendered HTML
    if (decrypted.html) {
      // New format: Replace page content with pre-rendered HTML
      // Parse the HTML and inject properly so scripts execute
      const parser = new DOMParser();
      const doc = parser.parseFromString(decrypted.html, 'text/html');

      // Copy theme attribute
      const theme = doc.documentElement.getAttribute('data-theme');
      if (theme) document.documentElement.setAttribute('data-theme', theme);

      // Replace head content (styles)
      const newStyles = doc.querySelectorAll('style');
      document.head.innerHTML = doc.head.innerHTML;

      // Replace body content
      document.body.innerHTML = doc.body.innerHTML;
      document.body.className = doc.body.className;

      // Re-create script elements so they execute
      const scripts = doc.querySelectorAll('script');
      scripts.forEach(oldScript => {
        const newScript = document.createElement('script');
        if (oldScript.src) {
          newScript.src = oldScript.src;
        } else {
          newScript.textContent = oldScript.textContent;
        }
        if (oldScript.type) newScript.type = oldScript.type;
        if (oldScript.id) newScript.id = oldScript.id;
        document.body.appendChild(newScript);
      });
      return;
    } else {
      // Legacy format: render from session data
      const session = decrypted;

      document.getElementById('header').innerHTML = \`
        <div class="header-main">
          <div class="logo">
            <span class="logo-icon">◈</span>
            <a href="/" class="logo-text">claude<span class="accent">review</span></a>
          </div>
          <div class="session-id">\${session.id ? session.id.slice(0, 8) : ''}</div>
        </div>
        <h1 class="session-title">\${escapeHtml(session.title || 'Session')}</h1>
        <div class="session-meta">
          <span>\${session.metadata?.messageCount || 0} messages</span>
          <span>·</span>
          <span>\${formatDuration(session.metadata?.durationSeconds || 0)}</span>
        </div>
      \`;

      // Render messages the old way
      if (session.messages) {
        document.getElementById('messages').innerHTML = session.messages.map(renderMessage).join('');
      }
    }
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
