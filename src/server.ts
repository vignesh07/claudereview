import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { setCookie, getCookie, deleteCookie } from 'hono/cookie';
import { nanoid } from 'nanoid';
import { z } from 'zod';
import { timingSafeEqual } from 'crypto';
import sharp from 'sharp';
import { db, sessions, users, apiKeys, sessionViews, type NewSession, type Session, type User } from './db/index.ts';
import { eq, sql, desc, count, and, gte, between } from 'drizzle-orm';
import { decrypt, encrypt, encryptForPublic, encryptForPrivate, generateKey, deriveKey, generateSalt } from './crypto.ts';

const app = new Hono();

// Environment
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-in-production';

// Maximum upload size (100MB - PostgreSQL TEXT can handle up to 1GB)
const MAX_UPLOAD_SIZE = 100 * 1024 * 1024;

// Simple session store (in production, use Redis or database)
const sessionStore = new Map<string, { userId: string; expiresAt: number }>();

// Session cleanup interval (hourly)
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessionStore.entries()) {
    if (session.expiresAt < now) {
      sessionStore.delete(id);
    }
  }
}, 60 * 60 * 1000);

// Timing-safe string comparison
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

// Middleware
app.use('*', logger());
app.use('*', secureHeaders({
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  strictTransportSecurity: 'max-age=31536000; includeSubDomains',
}));
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

  if (!code || !state || !storedState || !constantTimeEqual(state, storedState)) {
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

  // Determine the final visibility (current or changing to)
  const finalVisibility = body.visibility || session.visibility;

  // Handle title update - block for private sessions (metadata not stored)
  if (body.title) {
    if (finalVisibility === 'private') {
      return c.json({ error: 'Cannot set title for private sessions' }, 400);
    }
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
        // Clear all metadata for private sessions
        updates.title = null;
        updates.messageCount = null;
        updates.toolCount = null;
        updates.durationSeconds = null;
      } else {
        // Changing to public: encrypt with random key
        const encrypted = encryptForPublic(decryptedData);
        updates.encryptedBlob = encrypted.ciphertext;
        updates.iv = encrypted.iv;
        updates.salt = null;
        updates.ownerKey = encrypted.key; // Store key for owner access
        updates.visibility = 'public';
        newKey = encrypted.key; // Return to client for URL

        // Restore metadata from decrypted session when converting to public
        // Handle both formats:
        // - Current: { html, session: { id, title, metadata } }
        // - Legacy: { id, title, metadata, messages }
        try {
          const sessionData = JSON.parse(decryptedData);

          // Try current format first (session.metadata)
          const session = sessionData.session || sessionData;
          const metadata = session.metadata;
          const title = session.title;

          if (title) updates.title = title.slice(0, 200);
          if (metadata) {
            updates.messageCount = metadata.messageCount ?? null;
            updates.toolCount = metadata.toolCount ?? null;
            updates.durationSeconds = metadata.durationSeconds ?? null;
          }
        } catch {
          // If parsing fails, leave metadata as null
        }
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
  encryptedBlob: z.string().max(MAX_UPLOAD_SIZE, 'Session too large (max 100MB)'),
  iv: z.string().max(100),
  salt: z.string().max(100).optional(),
  ownerKey: z.string().max(100).optional(), // encryption key for owner to view later
  visibility: z.enum(['public', 'private']),
  metadata: z.object({
    title: z.string().max(500),
    messageCount: z.number().int().min(0).max(100000),
    toolCount: z.number().int().min(0).max(100000),
    durationSeconds: z.number().int().min(0).max(864000), // max 10 days
  }),
});

// API: Upload session
app.post('/api/upload', async (c) => {
  try {
    const body = await c.req.json();
    const parsed = uploadSchema.parse(body);

    // Generate short ID for URL
    const id = nanoid(12);

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
    // For private sessions, don't store metadata (title, counts) to ensure true privacy
    const isPrivate = parsed.visibility === 'private';
    const session: NewSession = {
      id,
      userId,
      title: isPrivate ? null : parsed.metadata.title.slice(0, 200), // Don't store title for private
      messageCount: isPrivate ? null : parsed.metadata.messageCount,
      toolCount: isPrivate ? null : parsed.metadata.toolCount,
      durationSeconds: isPrivate ? null : parsed.metadata.durationSeconds,
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

    // Increment view count (using SQL to avoid race conditions)
    await db.update(sessions)
      .set({ viewCount: sql`${sessions.viewCount} + 1` })
      .where(eq(sessions.id, id));

    // Record view (no IP/location tracking for privacy)
    try {
      await db.insert(sessionViews).values({
        id: nanoid(12),
        sessionId: id,
        country: null,
        city: null,
        latitude: null,
        longitude: null,
      });
    } catch (e) {
      // Silently ignore view recording errors
      console.error('View recording error:', e);
    }

    // For private sessions, don't expose any metadata until decrypted
    const isPrivateSession = session.visibility === 'private';

    return c.json({
      id: session.id,
      encryptedBlob: session.encryptedBlob,
      iv: session.iv,
      visibility: session.visibility,
      salt: session.salt,
      ownerKey: isOwner ? session.ownerKey : undefined, // Only include key for owner
      // Only include metadata for non-private sessions
      metadata: isPrivateSession ? undefined : {
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

// OG Image for social sharing - convert SVG to PNG for compatibility
let cachedOgImage: Buffer | null = null;

app.get('/og-image.png', async (c) => {
  try {
    // Use cached PNG if available
    if (cachedOgImage) {
      return new Response(cachedOgImage, {
        headers: {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=86400',
        },
      });
    }

    const svg = generateOgImageSvg();

    // Convert SVG to PNG using sharp
    const pngBuffer = await sharp(Buffer.from(svg))
      .png()
      .toBuffer();

    // Cache for subsequent requests
    cachedOgImage = pngBuffer;

    return new Response(pngBuffer, {
      headers: {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=86400',
      },
    });
  } catch (error) {
    console.error('OG image generation error:', error);
    // Fallback to SVG if PNG conversion fails
    const svg = generateOgImageSvg();
    return new Response(svg, {
      headers: {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'public, max-age=86400',
      },
    });
  }
});

// Privacy page
app.get('/privacy', async (c) => {
  const user = await getCurrentUser(c);
  return c.html(generatePrivacyHtml(user));
});

function generateOgImageSvg(): string {
  return `<svg width="1200" height="630" viewBox="0 0 1200 630" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#fafafa"/>
      <stop offset="100%" style="stop-color:#f0f0f0"/>
    </linearGradient>
    <linearGradient id="accent" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#0066ff"/>
      <stop offset="100%" style="stop-color:#0052cc"/>
    </linearGradient>
  </defs>

  <!-- Background -->
  <rect width="1200" height="630" fill="url(#bg)"/>

  <!-- Decorative elements -->
  <rect x="60" y="60" width="8" height="80" rx="4" fill="#0066ff" opacity="0.15"/>
  <rect x="80" y="60" width="8" height="120" rx="4" fill="#0066ff" opacity="0.1"/>
  <rect x="100" y="60" width="8" height="60" rx="4" fill="#0066ff" opacity="0.08"/>

  <rect x="1092" y="450" width="8" height="120" rx="4" fill="#0066ff" opacity="0.15"/>
  <rect x="1112" y="490" width="8" height="80" rx="4" fill="#0066ff" opacity="0.1"/>
  <rect x="1132" y="470" width="8" height="100" rx="4" fill="#0066ff" opacity="0.08"/>

  <!-- Terminal preview mockup -->
  <rect x="640" y="140" width="480" height="350" rx="16" fill="#0d1117" stroke="#30363d" stroke-width="1"/>
  <circle cx="672" cy="168" r="6" fill="#f85149"/>
  <circle cx="694" cy="168" r="6" fill="#d29922"/>
  <circle cx="716" cy="168" r="6" fill="#3fb950"/>

  <!-- Terminal content -->
  <text x="672" y="220" fill="#8b949e" font-family="monospace" font-size="14">$ ccshare share --last</text>
  <text x="672" y="250" fill="#3fb950" font-family="monospace" font-size="14">✓ Session encrypted</text>
  <text x="672" y="280" fill="#3fb950" font-family="monospace" font-size="14">✓ Uploaded to claudereview.com</text>
  <text x="672" y="320" fill="#c9d1d9" font-family="monospace" font-size="14">Share URL:</text>
  <text x="672" y="350" fill="#58a6ff" font-family="monospace" font-size="13">claudereview.com/s/abc123#key=...</text>

  <!-- Message bubbles hint -->
  <rect x="672" y="390" width="200" height="24" rx="4" fill="#161b22"/>
  <rect x="672" y="420" width="280" height="24" rx="4" fill="#1f6feb" opacity="0.2"/>
  <rect x="672" y="450" width="160" height="24" rx="4" fill="#161b22"/>

  <!-- Logo and text -->
  <text x="80" y="260" fill="#0066ff" font-family="system-ui, sans-serif" font-size="48" font-weight="500">◈</text>
  <text x="140" y="260" fill="#1a1a1a" font-family="system-ui, sans-serif" font-size="42" font-weight="600">claude</text>
  <text x="318" y="260" fill="#0066ff" font-family="system-ui, sans-serif" font-size="42" font-weight="600">review</text>

  <!-- Tagline -->
  <text x="80" y="320" fill="#1a1a1a" font-family="system-ui, sans-serif" font-size="32" font-weight="600">Share how the code was built,</text>
  <text x="80" y="365" fill="#1a1a1a" font-family="system-ui, sans-serif" font-size="32" font-weight="600">not just the final diff.</text>

  <!-- Subtitle -->
  <text x="80" y="420" fill="#666666" font-family="system-ui, sans-serif" font-size="20">Encrypted Claude Code session sharing</text>

  <!-- URL -->
  <text x="80" y="540" fill="#0066ff" font-family="monospace" font-size="18">claudereview.com</text>
</svg>`;
}

// Admin middleware (for API only)
const requireAdminApi = async (c: any, next: any) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) {
    return c.json({ error: 'Admin not configured' }, 500);
  }

  const authHeader = c.req.header('Authorization');
  const providedKey = authHeader?.replace('Bearer ', '');

  if (!providedKey || !constantTimeEqual(providedKey, adminKey)) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  await next();
};

// Helper to get date N days ago
function daysAgo(days: number): Date {
  const date = new Date();
  date.setDate(date.getDate() - days);
  date.setHours(0, 0, 0, 0);
  return date;
}

// Admin API: Get analytics
app.get('/api/admin/stats', requireAdminApi, async (c) => {
  if (!db) {
    return c.json({ error: 'Database not configured' }, 500);
  }

  try {
    // Get stats for all time periods
    const periods = {
      '7d': daysAgo(7),
      '30d': daysAgo(30),
      'all': new Date(0), // Beginning of time
    };

    // Stats by period
    const statsByPeriod: Record<string, { sessions: number; views: number; users: number }> = {};

    for (const [period, startDate] of Object.entries(periods)) {
      // Sessions in period
      const [sessionCount] = await db.select({ count: count() })
        .from(sessions)
        .where(period === 'all' ? sql`1=1` : gte(sessions.createdAt, startDate));

      // Views in period (from sessionViews table)
      const [viewCount] = await db.select({ count: count() })
        .from(sessionViews)
        .where(period === 'all' ? sql`1=1` : gte(sessionViews.viewedAt, startDate));

      // Users in period
      const [userCount] = await db.select({ count: count() })
        .from(users)
        .where(period === 'all' ? sql`1=1` : gte(users.createdAt, startDate));

      statsByPeriod[period] = {
        sessions: sessionCount?.count || 0,
        views: viewCount?.count || 0,
        users: userCount?.count || 0,
      };
    }

    // Total legacy view count (sum of viewCount column)
    const [viewsResult] = await db.select({
      total: sql<number>`COALESCE(SUM(${sessions.viewCount}), 0)`
    }).from(sessions);
    const legacyViews = viewsResult?.total || 0;

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
      .where(gte(sessions.createdAt, daysAgo(30)))
      .groupBy(sql`DATE(${sessions.createdAt})`)
      .orderBy(sql`DATE(${sessions.createdAt})`);

    // Views per day (last 30 days) from sessionViews
    const viewsPerDay = await db.select({
      date: sql<string>`DATE(${sessionViews.viewedAt})`,
      count: count(),
    }).from(sessionViews)
      .where(gte(sessionViews.viewedAt, daysAgo(30)))
      .groupBy(sql`DATE(${sessionViews.viewedAt})`)
      .orderBy(sql`DATE(${sessionViews.viewedAt})`);

    // Top viewed sessions
    const topViewed = await db.select({
      id: sessions.id,
      title: sessions.title,
      viewCount: sessions.viewCount,
    }).from(sessions).orderBy(desc(sessions.viewCount)).limit(10);

    // Location data for map (views with lat/long in last 30 days)
    const viewLocations = await db.select({
      latitude: sessionViews.latitude,
      longitude: sessionViews.longitude,
      city: sessionViews.city,
      country: sessionViews.country,
    }).from(sessionViews)
      .where(and(
        gte(sessionViews.viewedAt, daysAgo(30)),
        sql`${sessionViews.latitude} IS NOT NULL`,
        sql`${sessionViews.longitude} IS NOT NULL`
      ))
      .limit(500); // Limit to prevent huge payloads

    // Country breakdown
    const viewsByCountry = await db.select({
      country: sessionViews.country,
      count: count(),
    }).from(sessionViews)
      .where(and(
        gte(sessionViews.viewedAt, daysAgo(30)),
        sql`${sessionViews.country} IS NOT NULL`
      ))
      .groupBy(sessionViews.country)
      .orderBy(desc(count()))
      .limit(20);

    return c.json({
      stats: statsByPeriod,
      legacyViews,
      visibilityStats,
      recentSessions,
      sessionsPerDay,
      viewsPerDay,
      topViewed,
      viewLocations,
      viewsByCountry,
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
  // For private sessions, use generic metadata to avoid leaking sensitive info
  const isPrivate = session?.visibility === 'private';
  const title = isPrivate ? 'Protected Session' : (session?.title || 'Claude Code Session');
  const description = isPrivate
    ? 'This session is password protected'
    : session
    ? `${session.messageCount} messages · ${formatDuration(session.durationSeconds)}`
    : 'View Claude Code session';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - claudereview</title>
  <meta property="og:type" content="website">
  <meta property="og:title" content="${isPrivate ? 'Protected Session' : 'Claude Session: ' + escapeHtml(title)}">
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
  const userSection = user
    ? `<a href="/dashboard" class="user-link">
        <img src="${escapeHtml(user.githubAvatarUrl || '')}" alt="" class="avatar">
        ${escapeHtml(user.githubUsername)}
      </a>`
    : `<a href="/auth/github" class="login-btn"><svg class="github-icon" viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>Sign in with GitHub</a>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>claudereview — Share Claude Code Sessions</title>
  <meta name="description" content="Share your Claude Code sessions for code review. Encrypted, beautiful viewer. Drop a link in your PR.">
  <meta property="og:title" content="claudereview — Share Claude Code Sessions">
  <meta property="og:description" content="Share how the code was built, not just the final diff. Encrypted.">
  <meta property="og:type" content="website">
  <meta property="og:image" content="https://claudereview.com/og-image.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:image" content="https://claudereview.com/og-image.png">
  <style>${LANDING_CSS}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <span class="logo-icon">◈</span>
        <span class="logo-text">claude<span class="accent">review</span></span>
      </div>
      <div class="header-right">
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
          <span class="theme-icon">◐</span>
        </button>
        ${userSection}
      </div>
    </header>

    <section class="hero">
      <div class="hero-badge">Open Source</div>
      <h1>Share Claude Code sessions<br>for code review</h1>
      <p class="hero-subtitle">
        Drop a link in your PR so reviewers can see how the code was built, not just the final diff. Encrypted.
      </p>
      <div class="hero-actions">
        <a href="#install" class="btn-primary">Get Started</a>
        <a href="https://github.com/vignesh07/claudereview" class="btn-secondary" target="_blank">View on GitHub</a>
      </div>
    </section>

    <section class="preview-section">
      <div class="preview-window">
        <div class="preview-header">
          <span class="preview-dot red"></span>
          <span class="preview-dot yellow"></span>
          <span class="preview-dot green"></span>
          <span class="preview-title">claudereview.com/s/abc123</span>
        </div>
        <div class="preview-content">
          <div class="preview-message">
            <div class="preview-role human">Human</div>
            <div class="preview-text">Add a dark mode toggle to the settings page</div>
          </div>
          <div class="preview-message">
            <div class="preview-role assistant">Claude</div>
            <div class="preview-text">I'll add a dark mode toggle. Let me first check the current theme implementation...</div>
            <div class="preview-tool">
              <div class="preview-tool-name">Read · src/theme.ts</div>
              <div class="preview-tool-content">Found theme context with light mode only</div>
            </div>
            <div class="preview-tool">
              <div class="preview-tool-name">Edit · src/settings.tsx</div>
              <div class="preview-tool-content">Added toggle switch component</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="features-section">
      <h2>Built for developers</h2>
      <div class="features-grid">
        <div class="feature-card">
          <div class="feature-icon">◇</div>
          <h3>Encrypted</h3>
          <p>Sessions are encrypted before upload. Password-protected sessions use client-side key derivation.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">→</div>
          <h3>Deep linking</h3>
          <p>Link directly to specific messages. Perfect for pointing reviewers to key decisions.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">⚡</div>
          <h3>Instant sharing</h3>
          <p>One command to share. Built with Bun for speed. Works with any Claude Code session.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">◈</div>
          <h3>Beautiful viewer</h3>
          <p>TUI-style interface with syntax highlighting, collapsible tools, and keyboard navigation.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">⊕</div>
          <h3>Public or private</h3>
          <p>Share openly with a link, or password-protect sensitive sessions. You control access.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">↻</div>
          <h3>Open source</h3>
          <p>MIT licensed. Self-host if you prefer. Audit the code yourself.</p>
        </div>
      </div>
    </section>

    <section class="install-section" id="install">
      <h2>Get started in seconds</h2>
      <p class="subtitle">Install the CLI and share your first session</p>
      <div class="install-box">
        <code>bun add -g claudereview</code>
        <button class="copy-btn" onclick="copyInstall(this)">Copy</button>
      </div>
      <p class="install-alt">or npm install -g claudereview</p>
    </section>

    <section class="usage-section">
      <h2>Simple commands</h2>
      <p class="subtitle">Everything you need to share sessions</p>
      <pre class="usage-code"><span class="comment"># List your recent sessions</span>
<span class="cmd">ccshare list</span>

<span class="comment"># Share a specific session by ID</span>
<span class="cmd">ccshare share abc123</span>

<span class="comment"># Share your last session</span>
<span class="cmd">ccshare share --last</span>

<span class="comment"># Password-protect a session</span>
<span class="cmd">ccshare share --last --private "secret"</span>

<span class="comment"># Preview locally before sharing</span>
<span class="cmd">ccshare preview --last</span></pre>
    </section>

    <section class="integration-section">
      <h2>Claude Code integration</h2>
      <p class="subtitle">Share sessions without leaving Claude</p>

      <div class="integration-grid">
        <div class="integration-card">
          <h3>MCP Server</h3>
          <p>Share sessions directly from Claude. Add to <code>~/.mcp.json</code>:</p>
          <pre class="integration-code">{
  "mcpServers": {
    "claudereview": {
      "command": "bunx",
      "args": ["claudereview-mcp"]
    }
  }
}</pre>
          <p class="integration-tip">Then just ask Claude: "Share this session"</p>
        </div>

        <div class="integration-card">
          <h3>Slash Command</h3>
          <p>Quick shortcut. Create <code>~/.claude/commands/share.md</code>:</p>
          <pre class="integration-code">Share this Claude Code session.

Run: bunx claudereview share --last

Return the URL to me.</pre>
          <p class="integration-tip">Then type <code>/share</code> in any session</p>
        </div>
      </div>
    </section>

    <footer>
      <div class="footer-links">
        <a href="https://github.com/vignesh07/claudereview">GitHub</a>
        <a href="/privacy">Privacy</a>
        <a href="/dashboard">Dashboard</a>
      </div>
      <p class="footer-note">Built for developers who use Claude Code</p>
    </footer>
  </div>

  <script>
    function toggleTheme() {
      const html = document.documentElement;
      const current = html.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      updateThemeIcon();
    }

    function updateThemeIcon() {
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      document.querySelector('.theme-icon').textContent = isDark ? '○' : '◐';
    }

    function copyInstall(btn) {
      const textarea = document.createElement('textarea');
      textarea.value = 'bun add -g claudereview';
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 1500);
    }

    // Check saved theme or system preference
    const saved = localStorage.getItem('theme');
    if (saved) {
      document.documentElement.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
    updateThemeIcon();

    // Header scroll effect
    window.addEventListener('scroll', () => {
      document.querySelector('header').classList.toggle('scrolled', window.scrollY > 10);
    });
  </script>
</body>
</html>`;
}

function generatePrivacyHtml(user: User | null): string {
  const userSection = user
    ? `<a href="/dashboard" class="user-link">
        <img src="${escapeHtml(user.githubAvatarUrl || '')}" alt="" class="avatar">
        ${escapeHtml(user.githubUsername)}
      </a>`
    : `<a href="/auth/github" class="login-btn"><svg class="github-icon" viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>Sign in with GitHub</a>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Privacy & Security - claudereview</title>
  <meta name="description" content="How claudereview handles your data and protects your privacy.">
  <style>${LANDING_CSS}
    .privacy-content {
      max-width: 800px;
      margin: 0 auto;
      padding: 80px 24px;
    }
    .privacy-content h1 {
      font-size: 2.5rem;
      font-weight: 600;
      margin-bottom: 16px;
      color: var(--text-primary);
    }
    .privacy-content .subtitle {
      color: var(--text-secondary);
      font-size: 1.1rem;
      margin-bottom: 48px;
    }
    .privacy-content h2 {
      font-size: 1.5rem;
      font-weight: 600;
      margin: 48px 0 16px;
      color: var(--text-primary);
    }
    .privacy-content h3 {
      font-size: 1.1rem;
      font-weight: 600;
      margin: 24px 0 12px;
      color: var(--text-primary);
    }
    .privacy-content p, .privacy-content li {
      color: var(--text-secondary);
      line-height: 1.7;
      margin-bottom: 16px;
    }
    .privacy-content ul {
      padding-left: 24px;
      margin-bottom: 16px;
    }
    .privacy-content li {
      margin-bottom: 8px;
    }
    .privacy-content code {
      background: var(--surface);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: 'DM Mono', monospace;
      font-size: 0.9em;
    }
    .privacy-content .highlight-box {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin: 24px 0;
    }
    .privacy-content .highlight-box h3 {
      margin-top: 0;
      color: var(--accent);
    }
    .privacy-content .diagram {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
      margin: 24px 0;
      font-family: 'DM Mono', monospace;
      font-size: 0.85rem;
      line-height: 1.5;
      overflow-x: auto;
      white-space: pre;
      color: var(--text-secondary);
    }
    .privacy-content .badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 500;
      margin-right: 8px;
    }
    .privacy-content .badge.green {
      background: rgba(34, 197, 94, 0.1);
      color: #22c55e;
    }
    .privacy-content .badge.blue {
      background: rgba(59, 130, 246, 0.1);
      color: #3b82f6;
    }
    .privacy-content .badge.yellow {
      background: rgba(234, 179, 8, 0.1);
      color: #eab308;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <span class="logo-icon">◈</span>
        <a href="/" class="logo-text">claude<span class="accent">review</span></a>
      </div>
      <div class="header-right">
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
          <span class="theme-icon">◐</span>
        </button>
        ${userSection}
      </div>
    </header>

    <div class="privacy-content">
      <h1>Privacy & Security</h1>
      <p class="subtitle">How claudereview handles your data and protects your sessions.</p>

      <h2>Overview</h2>
      <p>claudereview is designed with privacy in mind. All sessions are encrypted before they leave your machine. However, the level of protection depends on how you choose to share:</p>

      <div class="highlight-box">
        <h3><span class="badge green">Password-Protected</span> True End-to-End Encryption</h3>
        <p>When you share with <code>--private "password"</code>, the encryption key is derived from your password using PBKDF2 (600,000 iterations, SHA-256). The key never leaves your machine and is never stored on our servers. We cannot decrypt these sessions even if we wanted to.</p>
      </div>

      <div class="highlight-box">
        <h3><span class="badge blue">Public Links</span> Encrypted at Rest</h3>
        <p>When you share without a password, the session is encrypted with a random key. The key is embedded in the URL fragment (<code>#key=xxx</code>). For anonymous shares, the key is only in the URL. For authenticated users, we store the key so you can view your sessions from the dashboard.</p>
      </div>

      <h2>How Encryption Works</h2>

      <h3>Password-Protected Sessions (True E2E)</h3>
      <div class="diagram">┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Your CLI  │────▶│ Password + Salt  │────▶│   PBKDF2    │
│             │     │                  │     │ Key Derivation
└─────────────┘     └──────────────────┘     └──────┬──────┘
                                                    │
                                                    ▼
                                            ┌──────────────┐
                                            │   AES-256    │
                                            │  Encryption  │
                                            └──────┬───────┘
                                                   │
                    ┌──────────────────────────────┘
                    ▼
        ┌───────────────────────┐
        │   Encrypted Blob      │────▶ Server stores only:
        │   (unreadable)        │      • Encrypted blob
        └───────────────────────┘      • Salt (for key derivation)
                                       • Basic metadata*

* Metadata (title, message count) is NOT stored for private sessions.</div>

      <h3>Public Link Sessions</h3>
      <div class="diagram">┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Your CLI  │────▶│  Random 256-bit  │────▶│   AES-256   │
│             │     │      Key         │     │  Encryption │
└─────────────┘     └──────────────────┘     └──────┬──────┘
                                                    │
                    ┌───────────────────────────────┘
                    ▼
        ┌───────────────────────┐
        │   Encrypted Blob      │────▶ Server stores:
        │   (unreadable)        │      • Encrypted blob
        └───────────────────────┘      • Metadata
                                       • Key (for authenticated users only)

URL: claudereview.com/s/abc123#key=xxxxx
                                └─────┘
                                Fragment never sent to server</div>

      <h2>What We Store</h2>

      <table style="width: 100%; border-collapse: collapse; margin: 24px 0;">
        <thead>
          <tr style="border-bottom: 1px solid var(--border);">
            <th style="text-align: left; padding: 12px 8px; color: var(--text-primary);">Data</th>
            <th style="text-align: center; padding: 12px 8px; color: var(--text-primary);">Public (Anonymous)</th>
            <th style="text-align: center; padding: 12px 8px; color: var(--text-primary);">Public (Signed In)</th>
            <th style="text-align: center; padding: 12px 8px; color: var(--text-primary);">Password-Protected</th>
          </tr>
        </thead>
        <tbody>
          <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 8px; color: var(--text-secondary);">Encrypted session blob</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
          </tr>
          <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 8px; color: var(--text-secondary);">Session title</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
            <td style="text-align: center; padding: 12px 8px;">✗</td>
          </tr>
          <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 8px; color: var(--text-secondary);">Message/tool counts</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
            <td style="text-align: center; padding: 12px 8px;">✗</td>
          </tr>
          <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 8px; color: var(--text-secondary);">Encryption key</td>
            <td style="text-align: center; padding: 12px 8px;">✗ (URL only)</td>
            <td style="text-align: center; padding: 12px 8px;">✓ (for dashboard)</td>
            <td style="text-align: center; padding: 12px 8px;">✗ (derived from password)</td>
          </tr>
          <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 8px; color: var(--text-secondary);">User association</td>
            <td style="text-align: center; padding: 12px 8px;">✗</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
            <td style="text-align: center; padding: 12px 8px;">✓ (if signed in)</td>
          </tr>
          <tr>
            <td style="padding: 12px 8px; color: var(--text-secondary);">Salt (for key derivation)</td>
            <td style="text-align: center; padding: 12px 8px;">✗</td>
            <td style="text-align: center; padding: 12px 8px;">✗</td>
            <td style="text-align: center; padding: 12px 8px;">✓</td>
          </tr>
        </tbody>
      </table>

      <h2>Can We Read Your Sessions?</h2>

      <ul>
        <li><strong>Password-protected sessions:</strong> <span class="badge green">No</span> The key is derived from your password and never stored. We cannot decrypt these even with database access.</li>
        <li><strong>Public sessions (signed in):</strong> <span class="badge yellow">Technically yes</span> We store the encryption key to enable dashboard viewing. However, we do not access session content and the code is open source for you to verify.</li>
        <li><strong>Public sessions (anonymous):</strong> <span class="badge green">No</span> The key exists only in the URL fragment which is never sent to our servers.</li>
      </ul>

      <h2>Recommendations</h2>
      <ul>
        <li>Use <code>--private "password"</code> for sensitive sessions that you want to guarantee cannot be read by anyone (including us)</li>
        <li>Share public links for routine code reviews where convenience matters more than maximum privacy</li>
        <li>If you lose a password for a private session, the session is unrecoverable by design</li>
      </ul>

      <h2>Open Source</h2>
      <p>claudereview is open source. You can audit the code yourself:</p>
      <ul>
        <li><a href="https://github.com/vignesh07/claudereview" style="color: var(--accent);">GitHub Repository</a></li>
        <li>Self-host if you prefer complete control</li>
      </ul>

      <h2>Data Retention</h2>
      <ul>
        <li>Sessions are stored indefinitely unless you delete them from your dashboard</li>
        <li>Anonymous sessions cannot be deleted (you don't own them)</li>
        <li>We may add session expiration features in the future</li>
      </ul>

      <h2>Questions?</h2>
      <p>Open an issue on <a href="https://github.com/vignesh07/claudereview/issues" style="color: var(--accent);">GitHub</a> or contact us at privacy@claudereview.com.</p>
    </div>

    <footer>
      <div class="footer-links">
        <a href="https://github.com/vignesh07/claudereview">GitHub</a>
        <a href="/privacy">Privacy</a>
        <a href="/dashboard">Dashboard</a>
      </div>
      <p class="footer-note">Built for developers who use Claude Code</p>
    </footer>
  </div>

  <script>
    function toggleTheme() {
      const html = document.documentElement;
      const current = html.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      updateThemeIcon();
    }

    function updateThemeIcon() {
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      document.querySelector('.theme-icon').textContent = isDark ? '○' : '◐';
    }

    const saved = localStorage.getItem('theme');
    if (saved) {
      document.documentElement.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
    updateThemeIcon();
  </script>
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
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
          <span class="icon-sun">&#9728;</span>
          <span class="icon-moon">&#9790;</span>
        </button>
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
    // Theme toggle
    function toggleTheme() {
      const html = document.documentElement;
      const current = html.getAttribute('data-theme');
      const next = current === 'dark' ? null : 'dark';
      if (next) {
        html.setAttribute('data-theme', next);
        localStorage.setItem('ccshare-theme', next);
      } else {
        html.removeAttribute('data-theme');
        localStorage.removeItem('ccshare-theme');
      }
    }

    // Apply saved theme on load
    (function() {
      const saved = localStorage.getItem('ccshare-theme');
      if (saved === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    })();

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

    function copyToClipboard(text) {
      // Use fallback method to avoid permission prompts
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }

    function copyLink(id, key) {
      let url = window.location.origin + '/s/' + id;
      if (key) url += '#key=' + key;
      copyToClipboard(url);
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
          copyToClipboard(newUrl);
          showToast('Session is now public! Link copied.');
        } else {
          showToast('Session updated.');
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
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>◈</text></svg>">
  <style>${ADMIN_CSS}</style>
  <!-- Leaflet for maps -->
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
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
      <div class="header-left">
        <a href="/" class="logo">
          <span class="logo-icon">◈</span>
          <span class="logo-text">claude<span class="accent">review</span></span>
        </a>
        <span class="admin-badge">Admin</span>
      </div>
      <div class="header-right">
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
          <span class="icon-sun">&#9728;</span>
          <span class="icon-moon">&#9790;</span>
        </button>
        <button id="logout-btn" class="logout-btn">Logout</button>
      </div>
    </header>

    <main>
      <!-- Period Toggle -->
      <div class="period-toggle">
        <button class="period-btn" data-period="7d">7 days</button>
        <button class="period-btn active" data-period="30d">30 days</button>
        <button class="period-btn" data-period="all">All time</button>
      </div>

      <!-- Stats Grid -->
      <div class="stats-grid">
        <div class="stat-card sessions">
          <div class="stat-icon">&#9881;</div>
          <div class="stat-value" id="stat-sessions">-</div>
          <div class="stat-label">Sessions Shared</div>
        </div>
        <div class="stat-card views">
          <div class="stat-icon">&#128065;</div>
          <div class="stat-value" id="stat-views">-</div>
          <div class="stat-label">Total Views</div>
        </div>
        <div class="stat-card users">
          <div class="stat-icon">&#128100;</div>
          <div class="stat-value" id="stat-users">-</div>
          <div class="stat-label">Users</div>
        </div>
        <div class="stat-card public">
          <div class="stat-icon">&#128279;</div>
          <div class="stat-value" id="stat-public">-</div>
          <div class="stat-label">Public Sessions</div>
        </div>
      </div>

      <!-- Charts Row -->
      <div class="grid-2">
        <section class="section">
          <div class="section-header">
            <h2>Sessions per Day</h2>
          </div>
          <div class="chart" id="sessions-chart"></div>
        </section>
        <section class="section">
          <div class="section-header">
            <h2>Views per Day</h2>
          </div>
          <div class="chart" id="views-chart"></div>
        </section>
      </div>

      <!-- Map and Countries Row -->
      <div class="grid-3-1">
        <section class="section">
          <div class="section-header">
            <h2>View Locations</h2>
          </div>
          <div class="map-container" id="map"></div>
        </section>
        <section class="section">
          <div class="section-header">
            <h2>Top Countries</h2>
          </div>
          <div class="country-list" id="country-list">
            <div class="no-data">Loading...</div>
          </div>
        </section>
      </div>

      <!-- Tables Row -->
      <div class="grid-2">
        <section class="section">
          <div class="section-header">
            <h2>Top Viewed</h2>
          </div>
          <table class="data-table" id="top-viewed">
            <thead>
              <tr><th>Title</th><th>Views</th><th></th></tr>
            </thead>
            <tbody></tbody>
          </table>
        </section>
        <section class="section">
          <div class="section-header">
            <h2>Recent Sessions</h2>
          </div>
          <table class="data-table" id="recent-sessions">
            <thead>
              <tr><th>Title</th><th>Type</th><th>Views</th><th>Created</th></tr>
            </thead>
            <tbody></tbody>
          </table>
        </section>
      </div>
    </main>
  </div>

  <script>
    // Theme toggle
    function toggleTheme() {
      const html = document.documentElement;
      const current = html.getAttribute('data-theme');
      const next = current === 'dark' ? null : 'dark';
      if (next) {
        html.setAttribute('data-theme', next);
        localStorage.setItem('ccshare-admin-theme', next);
      } else {
        html.removeAttribute('data-theme');
        localStorage.removeItem('ccshare-admin-theme');
      }
      updateMapTheme();
    }

    // Apply saved theme
    (function() {
      const saved = localStorage.getItem('ccshare-admin-theme');
      if (saved === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
      }
    })();

    // Country code to flag emoji
    function countryFlag(code) {
      if (!code) return '🌍';
      const codePoints = code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0));
      return String.fromCodePoint(...codePoints);
    }

    // Country code to name
    const countryNames = {
      US: 'United States', GB: 'United Kingdom', DE: 'Germany', FR: 'France',
      IN: 'India', CA: 'Canada', AU: 'Australia', JP: 'Japan', BR: 'Brazil',
      NL: 'Netherlands', SE: 'Sweden', ES: 'Spain', IT: 'Italy', PL: 'Poland',
      CH: 'Switzerland', AT: 'Austria', BE: 'Belgium', DK: 'Denmark', NO: 'Norway',
      FI: 'Finland', IE: 'Ireland', NZ: 'New Zealand', SG: 'Singapore', KR: 'South Korea',
      MX: 'Mexico', AR: 'Argentina', CO: 'Colombia', CL: 'Chile', PT: 'Portugal',
      RU: 'Russia', UA: 'Ukraine', IL: 'Israel', AE: 'UAE', ZA: 'South Africa',
      CN: 'China', HK: 'Hong Kong', TW: 'Taiwan', TH: 'Thailand', MY: 'Malaysia',
      PH: 'Philippines', ID: 'Indonesia', VN: 'Vietnam', PK: 'Pakistan', BD: 'Bangladesh'
    };

    function countryName(code) {
      return countryNames[code] || code || 'Unknown';
    }

    let map = null;
    let markers = [];
    let cachedData = null;
    let currentPeriod = '30d';

    (function() {
      const loginScreen = document.getElementById('login-screen');
      const dashboard = document.getElementById('dashboard');
      const loginForm = document.getElementById('login-form');
      const loginError = document.getElementById('login-error');
      const adminKeyInput = document.getElementById('admin-key');
      const logoutBtn = document.getElementById('logout-btn');

      // Period toggle
      document.querySelectorAll('.period-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          currentPeriod = btn.dataset.period;
          if (cachedData) updateStats(cachedData);
        });
      });

      const savedKey = sessionStorage.getItem('adminKey');
      if (savedKey) authenticate(savedKey);

      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.classList.add('hidden');
        await authenticate(adminKeyInput.value);
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
          cachedData = await res.json();
          renderDashboard(cachedData);
          loginScreen.classList.add('hidden');
          dashboard.classList.remove('hidden');
        } catch (err) {
          loginError.textContent = 'Error: ' + err.message;
          loginError.classList.remove('hidden');
        }
      }

      function updateStats(data) {
        const stats = data.stats[currentPeriod] || { sessions: 0, views: 0, users: 0 };
        document.getElementById('stat-sessions').textContent = stats.sessions.toLocaleString();
        // Show tracked views + legacy views for all time
        const viewCount = currentPeriod === 'all' ? (stats.views + (data.legacyViews || 0)) : stats.views;
        document.getElementById('stat-views').textContent = viewCount.toLocaleString();
        document.getElementById('stat-users').textContent = stats.users.toLocaleString();

        const publicCount = data.visibilityStats.find(s => s.visibility === 'public')?.count || 0;
        document.getElementById('stat-public').textContent = publicCount.toLocaleString();
      }

      function renderDashboard(data) {
        updateStats(data);

        // Sessions chart
        renderChart('sessions-chart', data.sessionsPerDay, 'Sessions');

        // Views chart
        renderChart('views-chart', data.viewsPerDay || [], 'Views');

        // Initialize map
        initMap(data.viewLocations || []);

        // Country list
        renderCountries(data.viewsByCountry || []);

        // Top viewed table
        const topViewedBody = document.querySelector('#top-viewed tbody');
        if (!data.topViewed?.length) {
          topViewedBody.innerHTML = '<tr><td colspan="3" class="no-data">No sessions yet</td></tr>';
        } else {
          topViewedBody.innerHTML = data.topViewed.slice(0, 8).map(s =>
            '<tr><td>' + escapeHtml(s.title?.slice(0,40) || 'Untitled') + '</td><td>' + s.viewCount + '</td><td><a href="/s/' + s.id + '">View</a></td></tr>'
          ).join('');
        }

        // Recent sessions table
        const recentBody = document.querySelector('#recent-sessions tbody');
        if (!data.recentSessions?.length) {
          recentBody.innerHTML = '<tr><td colspan="4" class="no-data">No sessions yet</td></tr>';
        } else {
          recentBody.innerHTML = data.recentSessions.slice(0, 8).map(s => {
            const date = new Date(s.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            const pill = '<span class="visibility-pill ' + s.visibility + '">' + s.visibility + '</span>';
            return '<tr><td><a href="/s/' + s.id + '">' + escapeHtml(s.title?.slice(0,30) || 'Untitled') + '</a></td><td>' + pill + '</td><td>' + s.viewCount + '</td><td>' + date + '</td></tr>';
          }).join('');
        }
      }

      function renderChart(containerId, data, label) {
        const chart = document.getElementById(containerId);
        if (!data?.length) {
          chart.innerHTML = '<div class="no-data">No data yet</div>';
          return;
        }
        const maxCount = Math.max(...data.map(d => d.count), 1);
        chart.innerHTML = data.slice(-30).map(d => {
          const height = Math.max((d.count / maxCount * 100), 4);
          const date = new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
          return '<div class="bar" style="height:' + height + '%" data-count="' + d.count + '"><span class="bar-label">' + date + '</span></div>';
        }).join('');
      }

      function initMap(locations) {
        const mapContainer = document.getElementById('map');
        if (!locations?.length) {
          mapContainer.innerHTML = '<div class="map-placeholder"><span class="map-placeholder-icon">🗺️</span>No location data yet</div>';
          return;
        }

        // Initialize Leaflet map
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const tileUrl = isDark
          ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
          : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';

        if (map) {
          map.remove();
        }

        map = L.map('map', {
          center: [20, 0],
          zoom: 2,
          scrollWheelZoom: false,
          attributionControl: false
        });

        L.tileLayer(tileUrl, {
          maxZoom: 18,
        }).addTo(map);

        // Create custom marker icon
        const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
        const markerColor = isDarkMode ? '#4d94ff' : '#0066ff';
        const glowColor = isDarkMode ? 'rgba(77, 148, 255, 0.3)' : 'rgba(0, 102, 255, 0.2)';

        // Group locations by coordinates for counting
        const locationCounts = {};
        locations.forEach(loc => {
          const key = loc.latitude + ',' + loc.longitude;
          if (!locationCounts[key]) {
            locationCounts[key] = { ...loc, count: 0 };
          }
          locationCounts[key].count++;
        });

        // Add markers with size based on view count
        markers = Object.values(locationCounts).map(loc => {
          const lat = parseFloat(loc.latitude);
          const lng = parseFloat(loc.longitude);
          if (isNaN(lat) || isNaN(lng)) return null;

          const count = loc.count;
          const baseRadius = 6;
          const maxRadius = 16;
          const radius = Math.min(baseRadius + Math.log(count + 1) * 3, maxRadius);

          // Create outer glow circle
          const glowMarker = L.circleMarker([lat, lng], {
            radius: radius + 4,
            fillColor: markerColor,
            color: 'transparent',
            fillOpacity: 0.15
          }).addTo(map);

          // Create main circle marker
          const marker = L.circleMarker([lat, lng], {
            radius: radius,
            fillColor: markerColor,
            color: '#ffffff',
            weight: 2,
            opacity: 1,
            fillOpacity: 0.9
          });

          const locationName = loc.city ? loc.city + ', ' + loc.country : loc.country || 'Unknown';
          const popupContent = '<div style="text-align:center;font-weight:500;">' + locationName + '</div>' +
            '<div style="text-align:center;color:#888;font-size:0.75rem;margin-top:2px;">' + count + ' view' + (count > 1 ? 's' : '') + '</div>';

          marker.bindPopup(popupContent, { closeButton: false, className: 'custom-popup' });
          marker.addTo(map);

          return marker;
        }).filter(Boolean);
      }

      function updateMapTheme() {
        if (!map) return;
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const tileUrl = isDark
          ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
          : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';

        // Remove existing tile layer and add new one
        map.eachLayer(layer => {
          if (layer instanceof L.TileLayer) {
            map.removeLayer(layer);
          }
        });
        L.tileLayer(tileUrl, { maxZoom: 18 }).addTo(map);
      }

      window.updateMapTheme = updateMapTheme;

      function renderCountries(countries) {
        const container = document.getElementById('country-list');
        if (!countries?.length) {
          container.innerHTML = '<div class="no-data">No location data yet</div>';
          return;
        }
        container.innerHTML = countries.slice(0, 10).map(c =>
          '<div class="country-item">' +
            '<span class="country-name">' +
              '<span class="country-flag">' + countryFlag(c.country) + '</span>' +
              countryName(c.country) +
            '</span>' +
            '<span class="country-count">' + c.count + '</span>' +
          '</div>'
        ).join('');
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
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,700;1,9..40,400&family=DM+Mono:wght@400;500&display=swap');

:root {
  --bg: #fafafa;
  --bg-secondary: #ffffff;
  --bg-tertiary: #f0f0f0;
  --border: #e0e0e0;
  --text: #1a1a1a;
  --text-muted: #666666;
  --text-bright: #000000;
  --accent: #0066ff;
  --accent-soft: rgba(0, 102, 255, 0.08);
  --green: #00a67d;
  --font-mono: 'DM Mono', 'JetBrains Mono', monospace;
  --font-sans: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
}

[data-theme="dark"] {
  --bg: #0a0a0a;
  --bg-secondary: #141414;
  --bg-tertiary: #1a1a1a;
  --border: #2a2a2a;
  --text: #e0e0e0;
  --text-muted: #888888;
  --text-bright: #ffffff;
  --accent: #4d94ff;
  --accent-soft: rgba(77, 148, 255, 0.1);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html {
  scroll-behavior: smooth;
}

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-sans);
  min-height: 100vh;
  line-height: 1.6;
  transition: background 0.3s, color 0.3s;
}

.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 0 2rem;
}

/* Header */
header {
  padding: 1.5rem 0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  background: var(--bg);
  z-index: 100;
  border-bottom: 1px solid transparent;
}

header.scrolled {
  border-bottom-color: var(--border);
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.625rem;
}

.logo-icon {
  color: var(--accent);
  font-size: 1.5rem;
  font-weight: 500;
}

.logo-text {
  font-family: var(--font-mono);
  font-size: 1.125rem;
  color: var(--text);
  font-weight: 500;
  letter-spacing: -0.02em;
}

.accent { color: var(--accent); }

.header-right {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.theme-toggle {
  background: none;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem;
  cursor: pointer;
  color: var(--text-muted);
  font-size: 1rem;
  transition: all 0.15s;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
}

.theme-toggle:hover {
  border-color: var(--text-muted);
  color: var(--text);
}

.login-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: var(--text-bright);
  border: none;
  border-radius: 6px;
  padding: 0.5rem 1rem;
  color: var(--bg);
  text-decoration: none;
  font-size: 0.875rem;
  font-weight: 500;
  transition: all 0.15s;
}

.login-btn .github-icon {
  flex-shrink: 0;
}

.login-btn:hover {
  opacity: 0.85;
}

.user-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
  color: var(--text);
  padding: 0.375rem 0.75rem;
  border-radius: 6px;
  border: 1px solid var(--border);
  transition: all 0.15s;
  font-size: 0.875rem;
  font-weight: 500;
}

.user-link:hover {
  border-color: var(--text-muted);
}

.user-link .avatar {
  width: 24px;
  height: 24px;
  border-radius: 50%;
}

/* Hero Section */
.hero {
  padding: 6rem 0 4rem;
  text-align: center;
}

.hero-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: var(--accent-soft);
  color: var(--accent);
  padding: 0.375rem 0.875rem;
  border-radius: 100px;
  font-size: 0.8125rem;
  font-weight: 500;
  margin-bottom: 1.5rem;
}

.hero h1 {
  font-size: clamp(2.5rem, 5vw, 3.5rem);
  font-weight: 700;
  color: var(--text-bright);
  line-height: 1.1;
  margin-bottom: 1.25rem;
  letter-spacing: -0.03em;
}

.hero-subtitle {
  color: var(--text-muted);
  font-size: 1.25rem;
  line-height: 1.6;
  max-width: 600px;
  margin: 0 auto 2.5rem;
}

.hero-actions {
  display: flex;
  gap: 1rem;
  justify-content: center;
  flex-wrap: wrap;
}

.btn-primary {
  background: var(--text-bright);
  color: var(--bg);
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  text-decoration: none;
  font-weight: 500;
  font-size: 0.9375rem;
  transition: all 0.15s;
  border: none;
  cursor: pointer;
}

.btn-primary:hover {
  opacity: 0.85;
  transform: translateY(-1px);
}

.btn-secondary {
  background: transparent;
  color: var(--text);
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  text-decoration: none;
  font-weight: 500;
  font-size: 0.9375rem;
  border: 1px solid var(--border);
  transition: all 0.15s;
}

.btn-secondary:hover {
  border-color: var(--text-muted);
}

/* Preview Section */
.preview-section {
  padding: 2rem 0 6rem;
}

.preview-window {
  background: #0d1117;
  border-radius: 12px;
  overflow: hidden;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
  border: 1px solid #30363d;
}

.preview-header {
  background: #161b22;
  padding: 0.75rem 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  border-bottom: 1px solid #30363d;
}

.preview-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.preview-dot.red { background: #ff5f56; }
.preview-dot.yellow { background: #ffbd2e; }
.preview-dot.green { background: #27ca40; }

.preview-title {
  flex: 1;
  text-align: center;
  color: #8b949e;
  font-family: var(--font-mono);
  font-size: 0.8125rem;
}

.preview-content {
  padding: 1.5rem;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  color: #c9d1d9;
  min-height: 300px;
}

.preview-message {
  margin-bottom: 1.5rem;
}

.preview-role {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.preview-role.human { color: #58a6ff; }
.preview-role.assistant { color: #a371f7; }

.preview-text {
  color: #e6edf3;
  line-height: 1.6;
}

.preview-tool {
  background: #1c2128;
  border-radius: 6px;
  padding: 0.75rem 1rem;
  margin: 0.75rem 0;
  border-left: 3px solid #3fb950;
}

.preview-tool-name {
  color: #3fb950;
  font-size: 0.75rem;
  font-weight: 500;
  margin-bottom: 0.25rem;
}

.preview-tool-content {
  color: #8b949e;
  font-size: 0.8125rem;
}

/* Install Section */
.install-section {
  padding: 4rem 0;
  text-align: center;
}

.install-section h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
  letter-spacing: -0.02em;
}

.install-section .subtitle {
  color: var(--text-muted);
  margin-bottom: 2rem;
}

.install-box {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem 1.5rem;
  display: inline-flex;
  align-items: center;
  gap: 1rem;
  font-family: var(--font-mono);
  font-size: 1rem;
  color: var(--text-bright);
}

.install-box code {
  user-select: all;
}

.copy-btn {
  background: var(--accent-soft);
  border: none;
  border-radius: 6px;
  padding: 0.5rem 0.75rem;
  color: var(--accent);
  font-size: 0.8125rem;
  font-weight: 500;
  cursor: pointer;
  font-family: var(--font-sans);
  transition: all 0.15s;
}

.copy-btn:hover {
  background: var(--accent);
  color: white;
}

.install-alt {
  color: var(--text-muted);
  font-size: 0.875rem;
  margin-top: 1rem;
}

/* Features Section */
.features-section {
  padding: 4rem 0;
}

.features-section h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-bright);
  text-align: center;
  margin-bottom: 3rem;
  letter-spacing: -0.02em;
}

.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
}

.feature-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.75rem;
  transition: all 0.2s;
}

.feature-card:hover {
  border-color: var(--text-muted);
  transform: translateY(-2px);
}

.feature-icon {
  width: 40px;
  height: 40px;
  background: var(--accent-soft);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
  margin-bottom: 1rem;
}

.feature-card h3 {
  font-size: 1.0625rem;
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
}

.feature-card p {
  color: var(--text-muted);
  font-size: 0.9375rem;
  line-height: 1.5;
}

/* Usage Section */
.usage-section {
  padding: 4rem 0;
}

.usage-section h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-bright);
  text-align: center;
  margin-bottom: 0.5rem;
  letter-spacing: -0.02em;
}

.usage-section .subtitle {
  color: var(--text-muted);
  text-align: center;
  margin-bottom: 2.5rem;
}

.usage-code {
  background: #0d1117;
  border-radius: 12px;
  padding: 1.5rem 2rem;
  font-family: var(--font-mono);
  font-size: 0.9rem;
  line-height: 2;
  overflow-x: auto;
  color: #e6edf3;
  border: 1px solid #30363d;
}

.usage-code .comment { color: #8b949e; }
.usage-code .cmd { color: #79c0ff; }

/* Integration Section */
.integration-section {
  padding: 4rem 0;
  border-top: 1px solid var(--border);
}

.integration-section h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-bright);
  text-align: center;
  margin-bottom: 0.5rem;
  letter-spacing: -0.02em;
}

.integration-section .subtitle {
  color: var(--text-muted);
  text-align: center;
  margin-bottom: 2.5rem;
}

.integration-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 1.5rem;
}

.integration-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem;
}

.integration-card h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: 0.75rem;
}

.integration-card p {
  color: var(--text-muted);
  font-size: 0.9rem;
  margin-bottom: 1rem;
}

.integration-card code {
  background: var(--bg-tertiary);
  padding: 0.125rem 0.375rem;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: 0.85em;
  color: var(--text);
}

.integration-code {
  background: #0d1117;
  border-radius: 8px;
  padding: 1rem;
  font-family: var(--font-mono);
  font-size: 0.8rem;
  line-height: 1.5;
  overflow-x: auto;
  color: #e6edf3;
  border: 1px solid #30363d;
  margin-bottom: 1rem;
  white-space: pre;
}

.integration-tip {
  color: var(--text-muted);
  font-size: 0.85rem;
  font-style: italic;
  margin-bottom: 0;
}

.integration-tip code {
  font-style: normal;
}

/* Footer */
footer {
  padding: 3rem 0;
  text-align: center;
  border-top: 1px solid var(--border);
  margin-top: 2rem;
}

footer a {
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.875rem;
  transition: color 0.15s;
}

footer a:hover {
  color: var(--text);
}

.footer-links {
  display: flex;
  gap: 1.5rem;
  justify-content: center;
  margin-bottom: 1rem;
}

.footer-note {
  color: var(--text-muted);
  font-size: 0.8125rem;
}

/* Responsive */
@media (max-width: 768px) {
  .hero { padding: 4rem 0 3rem; }
  .hero h1 { font-size: 2rem; }
  .hero-subtitle { font-size: 1.0625rem; }
  .preview-content { min-height: 250px; padding: 1rem; }
  .features-grid { grid-template-columns: 1fr; }
  .install-box { flex-direction: column; gap: 0.75rem; }
}

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
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');

:root {
  --bg: #fafafa;
  --bg-secondary: #ffffff;
  --bg-tertiary: #f5f5f5;
  --border: #e5e5e5;
  --text: #333333;
  --text-muted: #666666;
  --text-bright: #1a1a1a;
  --accent: #0066ff;
  --accent-soft: rgba(0, 102, 255, 0.08);
  --green: #22863a;
  --green-soft: rgba(34, 134, 58, 0.08);
  --purple: #8957e5;
  --purple-soft: rgba(137, 87, 229, 0.08);
  --orange: #d97706;
  --orange-soft: rgba(217, 119, 6, 0.08);
  --font-mono: 'DM Mono', 'JetBrains Mono', monospace;
  --font-sans: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.06);
}

[data-theme="dark"] {
  --bg: #0a0a0a;
  --bg-secondary: #141414;
  --bg-tertiary: #1a1a1a;
  --border: #2a2a2a;
  --text: #e0e0e0;
  --text-muted: #888888;
  --text-bright: #ffffff;
  --accent: #4d94ff;
  --accent-soft: rgba(77, 148, 255, 0.12);
  --green: #3fb950;
  --green-soft: rgba(63, 185, 80, 0.12);
  --purple: #a371f7;
  --purple-soft: rgba(163, 113, 247, 0.12);
  --orange: #f59e0b;
  --orange-soft: rgba(245, 158, 11, 0.12);
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.3);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-sans);
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}

.container {
  max-width: 1400px;
  margin: 0 auto;
  padding: 2rem;
}

/* Header */
header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.625rem;
  text-decoration: none;
}

.logo-icon {
  color: var(--accent);
  font-size: 1.5rem;
  font-weight: 500;
}

.logo-text {
  font-size: 1.25rem;
  font-weight: 500;
  color: var(--text-muted);
  letter-spacing: -0.02em;
  transition: color 0.15s;
}

.logo:hover .logo-text {
  color: var(--text);
}

.accent { color: var(--accent); }

.admin-badge {
  background: var(--purple-soft);
  color: var(--purple);
  font-size: 0.6875rem;
  font-weight: 600;
  padding: 0.25rem 0.75rem;
  border-radius: 100px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.theme-toggle {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.5rem;
  cursor: pointer;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  width: 38px;
  height: 38px;
  transition: all 0.15s;
}

.theme-toggle:hover {
  border-color: var(--text-muted);
  color: var(--text);
  background: var(--bg-tertiary);
}

.theme-toggle .icon-sun { display: none; }
.theme-toggle .icon-moon { display: inline; }
[data-theme="dark"] .theme-toggle .icon-sun { display: inline; }
[data-theme="dark"] .theme-toggle .icon-moon { display: none; }

.logout-btn {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.5rem 1rem;
  color: var(--text-muted);
  cursor: pointer;
  font-family: var(--font-mono);
  font-size: 0.8125rem;
  transition: all 0.15s;
}

.logout-btn:hover {
  color: var(--text);
  border-color: var(--text-muted);
  background: var(--bg-tertiary);
}

/* Period Toggle */
.period-toggle {
  display: inline-flex;
  background: var(--bg-tertiary);
  border-radius: 8px;
  padding: 4px;
  gap: 2px;
  margin-bottom: 1.5rem;
}

.period-btn {
  background: none;
  border: none;
  padding: 0.5rem 1rem;
  font-family: var(--font-mono);
  font-size: 0.8125rem;
  color: var(--text-muted);
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.15s;
}

.period-btn:hover {
  color: var(--text);
}

.period-btn.active {
  background: var(--bg-secondary);
  color: var(--text-bright);
  box-shadow: var(--shadow-sm);
}

/* Stats Grid */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1.25rem;
  margin-bottom: 2.5rem;
}

.stat-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 1.5rem;
  transition: all 0.2s;
}

.stat-card:hover {
  transform: translateY(-2px);
  border-color: var(--text-muted);
  box-shadow: var(--shadow-md);
}

.stat-card.sessions { border-left: 4px solid var(--accent); }
.stat-card.views { border-left: 4px solid var(--green); }
.stat-card.users { border-left: 4px solid var(--purple); }
.stat-card.public { border-left: 4px solid var(--orange); }

.stat-icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.125rem;
  margin-bottom: 1rem;
}

.stat-card.sessions .stat-icon { background: var(--accent-soft); color: var(--accent); }
.stat-card.views .stat-icon { background: var(--green-soft); color: var(--green); }
.stat-card.users .stat-icon { background: var(--purple-soft); color: var(--purple); }
.stat-card.public .stat-icon { background: var(--orange-soft); color: var(--orange); }

.stat-value {
  font-size: 2.25rem;
  font-weight: 700;
  color: var(--text-bright);
  font-variant-numeric: tabular-nums;
  line-height: 1.1;
  letter-spacing: -0.02em;
}

.stat-label {
  color: var(--text-muted);
  font-size: 0.8125rem;
  margin-top: 0.5rem;
}

/* Grid Layout */
.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
  margin-bottom: 1.5rem;
}

.grid-3-1 {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 1.5rem;
  margin-bottom: 1.5rem;
}

/* Section Cards */
.section {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 1.5rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.25rem;
}

.section h2 {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-bright);
  letter-spacing: -0.01em;
}

/* Chart */
.chart {
  display: flex;
  align-items: flex-end;
  gap: 4px;
  height: 150px;
  padding: 0.5rem 0 1.75rem;
}

.bar {
  flex: 1;
  background: linear-gradient(to top, var(--accent), color-mix(in srgb, var(--accent) 70%, white));
  border-radius: 4px 4px 0 0;
  position: relative;
  min-height: 4px;
  transition: all 0.2s ease;
  cursor: pointer;
}

[data-theme="dark"] .bar {
  background: linear-gradient(to top, var(--accent), color-mix(in srgb, var(--accent) 80%, #333));
}

.bar:hover {
  background: var(--purple);
  transform: scaleY(1.02);
}

.bar::after {
  content: attr(data-count);
  position: absolute;
  top: -22px;
  left: 50%;
  transform: translateX(-50%);
  font-size: 0.6875rem;
  font-family: var(--font-mono);
  font-weight: 500;
  color: var(--text);
  background: var(--bg-secondary);
  padding: 2px 6px;
  border-radius: 4px;
  box-shadow: var(--shadow-sm);
  opacity: 0;
  transition: opacity 0.15s;
  white-space: nowrap;
}

.bar:hover::after {
  opacity: 1;
}

.bar-label {
  font-size: 0.5625rem;
  font-family: var(--font-mono);
  color: var(--text-muted);
  position: absolute;
  bottom: -20px;
  left: 50%;
  transform: translateX(-50%);
  white-space: nowrap;
}

/* Data Table */
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8125rem;
}

.data-table th,
.data-table td {
  padding: 0.75rem 0.5rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.data-table th {
  color: var(--text-muted);
  font-weight: 500;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.data-table td {
  color: var(--text);
  font-family: var(--font-mono);
}

.data-table tr:last-child td {
  border-bottom: none;
}

.data-table a {
  color: var(--accent);
  text-decoration: none;
}

.data-table a:hover {
  text-decoration: underline;
}

.visibility-pill {
  display: inline-block;
  font-size: 0.6875rem;
  padding: 0.125rem 0.5rem;
  border-radius: 100px;
  font-weight: 500;
}

.visibility-pill.public {
  background: var(--accent-soft);
  color: var(--accent);
}

.visibility-pill.private {
  background: var(--purple-soft);
  color: var(--purple);
}

/* Map Container */
.map-container {
  height: 320px;
  border-radius: 12px;
  overflow: hidden;
  background: var(--bg-tertiary);
  position: relative;
  border: 1px solid var(--border);
}

/* Custom Leaflet styling */
.map-container .leaflet-container {
  background: var(--bg-tertiary);
  font-family: var(--font-sans);
}

.map-container .leaflet-popup-content-wrapper {
  background: var(--bg-secondary);
  color: var(--text);
  border-radius: 10px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
  font-family: var(--font-sans);
  font-size: 0.8125rem;
  padding: 4px 8px;
}

.map-container .leaflet-popup-tip {
  background: var(--bg-secondary);
}

.map-container .leaflet-popup-close-button {
  color: var(--text-muted);
}

/* Custom map marker pulse effect */
@keyframes markerPulse {
  0% { transform: scale(1); opacity: 0.8; }
  50% { transform: scale(1.2); opacity: 0.4; }
  100% { transform: scale(1); opacity: 0.8; }
}

.map-marker-glow {
  animation: markerPulse 2s ease-in-out infinite;
}

.map-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--text-muted);
  font-size: 0.9375rem;
  gap: 0.75rem;
}

.map-placeholder-icon {
  font-size: 2.5rem;
  opacity: 0.6;
}

/* Country List */
.country-list {
  max-height: 300px;
  overflow-y: auto;
}

.country-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.625rem 0;
  border-bottom: 1px solid var(--border);
}

.country-item:last-child {
  border-bottom: none;
}

.country-name {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
}

.country-flag {
  font-size: 1.125rem;
}

.country-count {
  font-family: var(--font-mono);
  font-size: 0.8125rem;
  color: var(--text-muted);
}

/* Login Screen */
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
  border-radius: 16px;
  padding: 2.5rem;
  text-align: center;
  width: 100%;
  max-width: 380px;
  box-shadow: var(--shadow-md);
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
  border-radius: 8px;
  padding: 0.875rem 1rem;
  font-family: var(--font-mono);
  font-size: 0.9375rem;
  color: var(--text);
  text-align: center;
  transition: border-color 0.15s;
}

.login-box input:focus {
  outline: none;
  border-color: var(--accent);
}

.login-box button {
  background: var(--text-bright);
  border: none;
  border-radius: 10px;
  padding: 0.875rem;
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--bg);
  cursor: pointer;
  font-family: var(--font-sans);
  transition: all 0.15s;
}

.login-box button:hover {
  opacity: 0.9;
  transform: translateY(-1px);
}

.login-box .error {
  color: #d73a49;
  font-size: 0.8125rem;
  margin-top: 1rem;
}

.hidden { display: none !important; }

.no-data {
  color: var(--text-muted);
  text-align: center;
  padding: 2rem;
  font-size: 0.875rem;
}

/* Responsive */
@media (max-width: 1024px) {
  .grid-3-1 { grid-template-columns: 1fr; }
  .grid-2 { grid-template-columns: 1fr; }
}

@media (max-width: 768px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .container { padding: 1rem; }
}

@media (max-width: 480px) {
  .stats-grid { grid-template-columns: 1fr; }
  .header-left { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
}
`;

const DASHBOARD_CSS = `
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=DM+Mono:wght@400;500&display=swap');

:root {
  --bg: #fafafa;
  --bg-secondary: #ffffff;
  --bg-tertiary: #f0f0f0;
  --border: #e0e0e0;
  --text: #1a1a1a;
  --text-muted: #666666;
  --text-bright: #000000;
  --accent: #0066ff;
  --accent-soft: rgba(0, 102, 255, 0.08);
  --green: #00a67d;
  --green-soft: rgba(0, 166, 125, 0.08);
  --red: #dc2626;
  --red-soft: rgba(220, 38, 38, 0.08);
  --purple: #7c3aed;
  --purple-soft: rgba(124, 58, 237, 0.08);
  --font-mono: 'DM Mono', 'JetBrains Mono', monospace;
  --font-sans: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
}

[data-theme="dark"] {
  --bg: #0a0a0a;
  --bg-secondary: #141414;
  --bg-tertiary: #1a1a1a;
  --border: #2a2a2a;
  --text: #e0e0e0;
  --text-muted: #888888;
  --text-bright: #ffffff;
  --accent: #4d94ff;
  --accent-soft: rgba(77, 148, 255, 0.1);
  --green: #22c55e;
  --green-soft: rgba(34, 197, 94, 0.1);
  --red: #f87171;
  --red-soft: rgba(248, 113, 113, 0.1);
  --purple: #a78bfa;
  --purple-soft: rgba(167, 139, 250, 0.1);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-sans);
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  line-height: 1.6;
  transition: background 0.3s, color 0.3s;
}

.container {
  max-width: 960px;
  margin: 0 auto;
  padding: 2rem;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 3rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.625rem;
  text-decoration: none;
}

.logo-icon {
  color: var(--accent);
  font-size: 1.5rem;
  font-weight: 500;
}

.logo-text {
  font-size: 1.25rem;
  font-weight: 500;
  color: var(--text-muted);
  text-decoration: none;
  letter-spacing: -0.02em;
  transition: color 0.15s;
}

.logo-text:hover { color: var(--text); }
.accent { color: var(--accent); }

.user-info {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  border: 2px solid var(--border);
  transition: border-color 0.15s;
}

.avatar:hover {
  border-color: var(--text-muted);
}

.username {
  color: var(--text);
  font-weight: 500;
  font-size: 0.9375rem;
}

.logout-link {
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.8125rem;
  font-family: var(--font-mono);
  padding: 0.5rem 0.875rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  transition: all 0.15s;
}

.logout-link:hover {
  color: var(--text);
  border-color: var(--text-muted);
  background: var(--bg-tertiary);
}

main h1 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
  letter-spacing: -0.02em;
}

.subtitle {
  color: var(--text-muted);
  margin-bottom: 2rem;
  font-size: 1rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
}

.session-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.25rem 1.5rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: all 0.2s;
}

.session-card:hover {
  border-color: var(--text-muted);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04);
}

[data-theme="dark"] .session-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

.session-main {
  flex: 1;
  min-width: 0;
}

.session-title {
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
  font-size: 1rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  letter-spacing: -0.01em;
}

.session-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  color: var(--text-muted);
  font-size: 0.8125rem;
  font-family: var(--font-mono);
}

.session-meta .sep { opacity: 0.4; }

.visibility-badge {
  font-size: 0.6875rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  padding: 0.1875rem 0.5rem;
  border-radius: 100px;
  margin-left: 0.25rem;
}

.visibility-badge.public {
  background: var(--accent-soft);
  color: var(--accent);
}

.visibility-badge.private {
  background: var(--purple-soft);
  color: var(--purple);
}

.session-actions {
  display: flex;
  gap: 0.5rem;
  margin-left: 1.25rem;
}

.btn-icon {
  background: transparent;
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 0.5rem;
  cursor: pointer;
  font-size: 1rem;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s;
  color: var(--text-muted);
}

.btn-icon:hover {
  background: var(--bg-tertiary);
  border-color: var(--border);
  color: var(--text);
}

.btn-icon.btn-danger:hover {
  background: var(--red-soft);
  border-color: transparent;
  color: var(--red);
}

.btn-text {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.5rem 1rem;
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
  background: var(--green-soft);
  border-color: transparent;
  cursor: default;
}

.empty-state {
  text-align: center;
  padding: 5rem 2rem;
  color: var(--text-muted);
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 16px;
}

.empty-icon {
  font-size: 3.5rem;
  margin-bottom: 1.25rem;
  opacity: 0.8;
}

.empty-state h2 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: 0.5rem;
  letter-spacing: -0.01em;
}

.empty-state p {
  margin-bottom: 1.75rem;
  font-size: 0.9375rem;
}

.empty-state pre {
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem 1.5rem;
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  color: var(--text-bright);
}

.loading {
  text-align: center;
  padding: 3rem 2rem;
  color: var(--text-muted);
  font-size: 0.9375rem;
}

.error {
  text-align: center;
  padding: 2rem;
  color: var(--red);
  background: var(--red-soft);
  border-radius: 12px;
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
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.modal-content {
  position: relative;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 2rem;
  width: 100%;
  max-width: 420px;
  margin: 1rem;
  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.12);
}

[data-theme="dark"] .modal-content {
  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.4);
}

.modal-content h2 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-bright);
  margin-bottom: 0.75rem;
  letter-spacing: -0.01em;
}

.modal-content p {
  color: var(--text-muted);
  margin-bottom: 1.5rem;
  font-size: 0.9375rem;
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
  border-radius: 10px;
  padding: 0.75rem 1rem;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  color: var(--text);
  margin-top: 0.5rem;
  transition: border-color 0.15s;
}

.modal-content select {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23666666' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 1rem center;
  padding-right: 2.5rem;
  cursor: pointer;
  font-family: var(--font-sans);
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
  margin-top: 1.75rem;
  padding-top: 1.25rem;
  border-top: 1px solid var(--border);
}

.edit-error {
  background: var(--red-soft);
  border: 1px solid transparent;
  color: var(--red);
  padding: 0.875rem 1rem;
  border-radius: 10px;
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
  border-radius: 10px;
  padding: 0.75rem 1.25rem;
  font-family: var(--font-sans);
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text);
  border: 1px solid var(--border);
}

.btn-secondary:hover {
  border-color: var(--text-muted);
}

.btn-primary {
  background: var(--text-bright);
  color: var(--bg);
}

.btn-primary:hover {
  opacity: 0.9;
}

.btn-danger {
  background: var(--red);
  color: white;
}

.btn-danger:hover {
  opacity: 0.9;
}

/* Toast notification */
.toast {
  position: fixed;
  bottom: 2rem;
  left: 50%;
  transform: translateX(-50%) translateY(100px);
  background: var(--text-bright);
  color: var(--bg);
  padding: 0.875rem 1.75rem;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 500;
  opacity: 0;
  transition: all 0.3s ease;
  z-index: 1000;
  pointer-events: none;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
}

[data-theme="dark"] .toast {
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}

.toast.show {
  transform: translateX(-50%) translateY(0);
  opacity: 1;
}

/* API Keys Section */
.api-keys-section {
  margin-top: 4rem;
  padding-top: 2.5rem;
  border-top: 1px solid var(--border);
}

.api-keys-section h2 {
  font-size: 1.375rem;
  font-weight: 700;
  color: var(--text-bright);
  margin-bottom: 0.375rem;
  letter-spacing: -0.02em;
}

.api-keys-list {
  margin-top: 1.25rem;
}

.api-key-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1rem 1.25rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
  transition: all 0.15s;
}

.api-key-card:hover {
  border-color: var(--text-muted);
}

.key-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.key-name {
  font-weight: 600;
  color: var(--text-bright);
  font-size: 0.9375rem;
}

.key-meta {
  font-size: 0.75rem;
  font-family: var(--font-mono);
  color: var(--text-muted);
}

.no-keys {
  color: var(--text-muted);
  font-size: 0.9375rem;
  padding: 1.5rem 0;
  text-align: center;
}

/* New Key Modal */
.key-display {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem 1.25rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  margin-bottom: 1.25rem;
}

.key-display code {
  font-size: 0.8125rem;
  font-family: var(--font-mono);
  color: var(--accent);
  word-break: break-all;
  flex: 1;
}

.key-usage {
  background: var(--bg-tertiary);
  border-radius: 10px;
  padding: 1.25rem;
  margin-bottom: 1.5rem;
}

.key-usage p {
  font-size: 0.8125rem;
  color: var(--text-muted);
  margin-bottom: 0.625rem;
}

.key-usage pre {
  font-size: 0.8125rem;
  font-family: var(--font-mono);
  color: var(--text);
  overflow-x: auto;
}

.key-usage code {
  color: var(--green);
}

.hidden { display: none !important; }

/* Theme toggle */
.theme-toggle {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.5rem;
  cursor: pointer;
  color: var(--text-muted);
  font-size: 1rem;
  transition: all 0.15s;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 38px;
  height: 38px;
}

.theme-toggle:hover {
  border-color: var(--text-muted);
  color: var(--text);
  background: var(--bg-tertiary);
}

.theme-toggle .icon-sun { display: none; }
.theme-toggle .icon-moon { display: inline; }

[data-theme="dark"] .theme-toggle .icon-sun { display: inline; }
[data-theme="dark"] .theme-toggle .icon-moon { display: none; }

@media (max-width: 640px) {
  .container {
    padding: 1.5rem;
  }

  header {
    margin-bottom: 2rem;
  }

  .session-card {
    flex-direction: column;
    align-items: stretch;
    padding: 1rem;
  }

  .session-actions {
    margin-left: 0;
    margin-top: 1rem;
    justify-content: flex-end;
  }

  .user-info .username { display: none; }

  main h1 {
    font-size: 1.5rem;
  }
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
