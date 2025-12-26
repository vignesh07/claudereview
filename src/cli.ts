#!/usr/bin/env bun
import { Command } from 'commander';
import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { listSessions, getSession, getLastSession, parseSession, parseLastSession, formatDuration, formatRelativeTime } from './session.ts';
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
      let session;

      if (options.last || !sessionId) {
        session = await parseLastSession();
      } else {
        session = await parseSession(sessionId);
      }

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
      let session;

      if (options.last || !sessionId) {
        session = await parseLastSession();
      } else {
        session = await parseSession(sessionId);
      }

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
      let session;

      if (options.last || !sessionId) {
        session = await parseLastSession();
      } else {
        session = await parseSession(sessionId);
      }

      // Override title if provided
      if (options.title) {
        session.title = options.title;
      }

      if (!options.quiet) {
        console.log(c('dim', `\nPreparing to share: ${session.title}`));
        console.log(c('dim', `  Messages: ${session.metadata.messageCount}`));
        console.log(c('dim', `  Duration: ${formatDuration(session.metadata.durationSeconds)}`));
      }

      const sessionJson = JSON.stringify(session);
      let encryptedBlob: string;
      let iv: string;
      let key: string | undefined;
      let salt: string | undefined;
      const visibility = options.private ? 'private' : 'public';

      if (options.private) {
        // Encrypt with password
        const encrypted = await encryptForPrivate(sessionJson, options.private);
        encryptedBlob = encrypted.ciphertext;
        iv = encrypted.iv;
        salt = encrypted.salt;
      } else {
        // Encrypt with random key
        const encrypted = encryptForPublic(sessionJson);
        encryptedBlob = encrypted.ciphertext;
        iv = encrypted.iv;
        key = encrypted.key;
      }

      // Get API URL from environment or default
      const apiUrl = process.env.CCSHARE_API_URL || 'https://claudereview.com';

      // Upload to server
      const response = await fetch(`${apiUrl}/api/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(process.env.CCSHARE_API_KEY && { 'Authorization': `Bearer ${process.env.CCSHARE_API_KEY}` }),
        },
        body: JSON.stringify({
          encryptedBlob,
          iv,
          salt,
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

// Auth command (placeholder for now)
program
  .command('auth')
  .description('Authenticate with claudereview.com')
  .action(async () => {
    console.log(c('dim', 'Opening browser for authentication...'));

    const apiUrl = process.env.CCSHARE_API_URL || 'https://claudereview.com';

    // Open browser for OAuth flow
    const openCmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    Bun.spawn([openCmd, `${apiUrl}/login?cli=true`]);

    console.log(c('dim', '\nAfter logging in, copy your API key and set it:'));
    console.log(c('cyan', '  export CCSHARE_API_KEY=your_key_here\n'));
  });

// Helper functions
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

// Parse and run
program.parse();
