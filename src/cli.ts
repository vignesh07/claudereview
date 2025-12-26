#!/usr/bin/env bun
import { Command } from 'commander';
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { listSessions, getSession, getLastSession, parseSession, parseLastSession, parseSessionWithGit, formatDuration, formatRelativeTime, detectGitContext } from './session.ts';
import { renderSessionToHtml } from './renderer.ts';
import { encryptForPublic, encryptForPrivate } from './crypto.ts';

const program = new Command();

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

const c = (color: keyof typeof colors, text: string) => `${colors[color]}${text}${colors.reset}`;

/**
 * Parse a session with git context
 */
async function parseWithGitContext(sessionId?: string, last?: boolean) {
  let session;
  let projectPath: string | undefined;

  if (last || !sessionId) {
    const localSession = await getLastSession();
    if (!localSession) throw new Error('No sessions found');
    session = await parseSession(localSession.id);
    projectPath = localSession.projectPath;
  } else {
    const localSession = await getSession(sessionId);
    if (!localSession) throw new Error(`Session not found: ${sessionId}`);
    session = await parseSession(localSession.id);
    projectPath = localSession.projectPath;
  }

  // Add git context
  if (projectPath) {
    const gitContext = await detectGitContext(projectPath);
    session.metadata = {
      ...session.metadata,
      ...gitContext,
    };
  }

  return session;
}

program
  .name('ccshare')
  .description('Share Claude Code sessions for code review')
  .version('0.1.0');

// List command
program
  .command('list')
  .description('List available Claude Code sessions')
  .option('-n, --limit <number>', 'Limit number of results', '20')
  .option('-p, --project <path>', 'Filter by project directory')
  .action(async (options) => {
    try {
      let sessions = await listSessions();

      if (options.project) {
        sessions = sessions.filter(s =>
          s.projectPath.toLowerCase().includes(options.project.toLowerCase())
        );
      }

      const limit = parseInt(options.limit, 10);
      sessions = sessions.slice(0, limit);

      if (sessions.length === 0) {
        console.log(c('dim', 'No sessions found.'));
        return;
      }

      console.log(c('bold', '\n  Claude Code Sessions\n'));

      sessions.forEach((session, index) => {
        const num = c('dim', `${index + 1}.`.padStart(4));
        const id = c('cyan', session.id.slice(0, 8));
        const title = session.title
          ? truncate(session.title, 50)
          : c('dim', 'Untitled');
        const time = c('dim', formatRelativeTime(session.modifiedAt));
        const project = c('dim', truncate(session.projectPath, 30));

        console.log(`${num} ${id}  ${title}`);
        console.log(`        ${project}  ${time}\n`);
      });

      console.log(c('dim', `  Showing ${sessions.length} sessions. Use --limit to show more.\n`));
    } catch (error) {
      console.error(c('yellow', `Error: ${error}`));
      process.exit(1);
    }
  });

// Preview command
program
  .command('preview [session-id]')
  .description('Preview a session locally in browser')
  .option('-l, --last', 'Preview the most recent session')
  .option('-t, --title <title>', 'Custom title for the session')
  .option('--light', 'Use light mode theme')
  .option('--embed', 'Embed mode (compact, no chrome)')
  .action(async (sessionId, options) => {
    try {
      const session = await parseWithGitContext(sessionId, options.last);

      // Override title if provided
      if (options.title) {
        session.title = options.title;
      }

      console.log(c('dim', `Generating preview for: ${session.title}`));

      // Generate HTML
      const html = renderSessionToHtml(session, {
        theme: options.light ? 'light' : 'dark',
        embed: options.embed,
      });

      // Write to temp file
      const tempDir = join(homedir(), '.ccshare', 'previews');
      await mkdir(tempDir, { recursive: true });
      const tempFile = join(tempDir, `${session.id}.html`);
      await writeFile(tempFile, html);

      console.log(c('green', `✓ Preview generated`));
      console.log(c('dim', `  File: ${tempFile}`));

      // Open in browser
      const openCmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
      Bun.spawn([openCmd, tempFile]);

      console.log(c('dim', `  Opening in browser...`));
    } catch (error) {
      console.error(c('yellow', `Error: ${error}`));
      process.exit(1);
    }
  });

// Export command
program
  .command('export [session-id]')
  .description('Export a session to HTML file')
  .option('-l, --last', 'Export the most recent session')
  .option('-o, --output <path>', 'Output file path')
  .option('-t, --title <title>', 'Custom title for the session')
  .option('--light', 'Use light mode theme')
  .option('--embed', 'Embed mode (compact, no chrome)')
  .option('--private <password>', 'Create password-protected export')
  .action(async (sessionId, options) => {
    try {
      const session = await parseWithGitContext(sessionId, options.last);

      // Override title if provided
      if (options.title) {
        session.title = options.title;
      }

      console.log(c('dim', `Exporting: ${session.title}`));

      let html: string;

      const renderOptions = {
        theme: options.light ? 'light' as const : 'dark' as const,
        embed: options.embed,
      };

      if (options.private) {
        // Encrypt with password
        const sessionJson = JSON.stringify(session);
        const { ciphertext, iv, salt } = await encryptForPrivate(sessionJson, options.private);

        html = renderSessionToHtml(session, {
          ...renderOptions,
          encrypted: true,
          encryptedBlob: ciphertext,
          iv,
          salt,
        });

        console.log(c('yellow', `⚠ Password-protected export`));
      } else {
        html = renderSessionToHtml(session, renderOptions);
      }

      // Determine output path
      const outputPath = options.output || `${session.id}.html`;
      await writeFile(outputPath, html);

      console.log(c('green', `✓ Exported to ${outputPath}`));
      console.log(c('dim', `  Messages: ${session.metadata.messageCount}`));
      console.log(c('dim', `  Duration: ${formatDuration(session.metadata.durationSeconds)}`));
    } catch (error) {
      console.error(c('yellow', `Error: ${error}`));
      process.exit(1);
    }
  });

// Share command
program
  .command('share [session-id]')
  .description('Share a session and get a URL')
  .option('-l, --last', 'Share the most recent session')
  .option('-t, --title <title>', 'Custom title for the session')
  .option('--private <password>', 'Create password-protected share')
  .option('-q, --quiet', 'Only output the URL')
  .action(async (sessionId, options) => {
    try {
      const session = await parseWithGitContext(sessionId, options.last);

      // Override title if provided
      if (options.title) {
        session.title = options.title;
      }

      if (!options.quiet) {
        console.log(c('dim', `\nPreparing to share: ${session.title}`));
        console.log(c('dim', `  Messages: ${session.metadata.messageCount}`));
        console.log(c('dim', `  Duration: ${formatDuration(session.metadata.durationSeconds)}`));
      }

      // Render session to full HTML with all features
      const renderedHtml = renderSessionToHtml(session, {
        theme: 'dark',
        embed: true, // No chrome, just the content
      });

      // Create payload with both rendered HTML and metadata
      const payload = JSON.stringify({
        html: renderedHtml,
        session: {
          id: session.id,
          title: session.title,
          metadata: session.metadata,
        }
      });

      let encryptedBlob: string;
      let iv: string;
      let key: string | undefined;
      let salt: string | undefined;
      const visibility = options.private ? 'private' : 'public';

      if (options.private) {
        // Encrypt with password
        const encrypted = await encryptForPrivate(payload, options.private);
        encryptedBlob = encrypted.ciphertext;
        iv = encrypted.iv;
        salt = encrypted.salt;
      } else {
        // Encrypt with random key
        const encrypted = encryptForPublic(payload);
        encryptedBlob = encrypted.ciphertext;
        iv = encrypted.iv;
        key = encrypted.key;
      }

      // Get API URL from environment or default
      const apiUrl = process.env.CCSHARE_API_URL || 'https://claudereview.com';

      // Get API key from env or config
      let apiKey = process.env.CCSHARE_API_KEY;
      if (!apiKey) {
        const config = await loadConfig();
        apiKey = config.apiKey;
      }

      // Upload to server
      const response = await fetch(`${apiUrl}/api/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(apiKey && { 'Authorization': `Bearer ${apiKey}` }),
        },
        body: JSON.stringify({
          encryptedBlob,
          iv,
          salt,
          ownerKey: apiKey ? key : undefined, // Send key so owner can view from dashboard
          visibility,
          metadata: {
            title: session.title,
            messageCount: session.metadata.messageCount,
            toolCount: session.metadata.toolCount,
            durationSeconds: session.metadata.durationSeconds,
          },
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Upload failed: ${error}`);
      }

      const result = await response.json() as { id: string; url: string };

      // Construct full URL
      let shareUrl = result.url;
      if (key) {
        shareUrl += `#key=${key}`;
      }

      if (options.quiet) {
        console.log(shareUrl);
      } else {
        console.log(c('green', `\n✓ Session shared!`));
        console.log(c('bold', `\n  ${shareUrl}\n`));

        if (options.private) {
          console.log(c('yellow', `  ⚠ Password required to view`));
        }
      }
    } catch (error) {
      if (!options.quiet) {
        console.error(c('yellow', `Error: ${error}`));
      }
      process.exit(1);
    }
  });

// Config file path
const CONFIG_DIR = join(homedir(), '.config', 'ccshare');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

interface Config {
  apiKey?: string;
}

async function loadConfig(): Promise<Config> {
  try {
    const content = await Bun.file(CONFIG_FILE).text();
    return JSON.parse(content);
  } catch {
    return {};
  }
}

async function saveConfig(config: Config): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(CONFIG_FILE, JSON.stringify(config, null, 2));
}

function getApiKey(): string | undefined {
  // Environment variable takes precedence
  return process.env.CCSHARE_API_KEY;
}

// Auth command
program
  .command('auth')
  .description('Authenticate with claudereview.com')
  .option('--status', 'Check authentication status')
  .option('--logout', 'Remove saved credentials')
  .action(async (options) => {
    const apiUrl = process.env.CCSHARE_API_URL || 'https://claudereview.com';

    if (options.status) {
      const config = await loadConfig();
      const envKey = process.env.CCSHARE_API_KEY;

      if (envKey) {
        console.log(c('green', '✓ Authenticated via CCSHARE_API_KEY environment variable'));
        console.log(c('dim', `  Key: ${envKey.slice(0, 10)}...`));
      } else if (config.apiKey) {
        console.log(c('green', '✓ Authenticated via saved config'));
        console.log(c('dim', `  Key: ${config.apiKey.slice(0, 10)}...`));
        console.log(c('dim', `  Config: ${CONFIG_FILE}`));
      } else {
        console.log(c('yellow', '✗ Not authenticated'));
        console.log(c('dim', '  Run: ccshare auth'));
      }
      return;
    }

    if (options.logout) {
      await saveConfig({});
      console.log(c('green', '✓ Logged out'));
      console.log(c('dim', '  Removed saved credentials from ' + CONFIG_FILE));
      return;
    }

    // Interactive auth flow
    console.log(c('bold', '\n  claudereview Authentication\n'));
    console.log(c('dim', '  Opening browser to sign in with GitHub...\n'));

    // Open browser to dashboard
    const openCmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    Bun.spawn([openCmd, `${apiUrl}/dashboard`]);

    console.log('  Steps:');
    console.log(c('dim', '  1. Sign in with GitHub (if not already)'));
    console.log(c('dim', '  2. Scroll to "API Keys" section'));
    console.log(c('dim', '  3. Click "Generate New Key"'));
    console.log(c('dim', '  4. Copy the key and paste it below\n'));

    // Prompt for API key
    process.stdout.write(c('cyan', '  Paste your API key: '));

    const input = await new Promise<string>((resolve) => {
      let data = '';
      process.stdin.setRawMode?.(false);
      process.stdin.resume();
      process.stdin.setEncoding('utf8');
      process.stdin.once('data', (chunk) => {
        data = chunk.toString().trim();
        resolve(data);
      });
    });

    if (!input || !input.startsWith('cr_')) {
      console.log(c('yellow', '\n  Invalid API key. Keys should start with "cr_"'));
      process.exit(1);
    }

    // Verify the key works
    console.log(c('dim', '\n  Verifying...'));

    try {
      const res = await fetch(`${apiUrl}/api/my-sessions`, {
        headers: { 'Authorization': `Bearer ${input}` }
      });

      if (!res.ok) {
        console.log(c('yellow', '  Invalid API key. Please try again.'));
        process.exit(1);
      }
    } catch {
      console.log(c('yellow', '  Could not verify key. Saving anyway.'));
    }

    // Save to config
    await saveConfig({ apiKey: input });

    console.log(c('green', '\n  ✓ Authenticated successfully!\n'));
    console.log(c('dim', `  Config saved to: ${CONFIG_FILE}`));
    console.log(c('dim', '  Your sessions will now be linked to your account.\n'));
  });

// Helper functions
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

// Parse and run
program.parse();
