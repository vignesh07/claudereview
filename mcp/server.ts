#!/usr/bin/env bun
/**
 * claudereview MCP Server
 *
 * Exposes tools for sharing Claude Code sessions via the Model Context Protocol.
 *
 * Tools:
 * - list_sessions: List available Claude Code sessions
 * - share_session: Share a session and get a URL
 * - preview_session: Generate a local HTML preview
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { readdir, stat, readFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { renderSessionToHtml } from './renderer.ts';
import type { ParsedSession, ParsedMessage, SessionMetadata } from './types.ts';

const CLAUDE_PROJECTS_DIR = join(homedir(), '.claude', 'projects');
const API_URL = process.env.CCSHARE_API_URL || process.env.CLAUDEREVIEW_API_URL || 'https://claudereview.com';
const API_KEY = process.env.CCSHARE_API_KEY;

// Session discovery
interface LocalSession {
  id: string;
  path: string;
  projectPath: string;
  modifiedAt: Date;
  title?: string;
}

async function listSessions(limit = 10): Promise<LocalSession[]> {
  const sessions: LocalSession[] = [];

  try {
    const projectDirs = await readdir(CLAUDE_PROJECTS_DIR);

    for (const projectDir of projectDirs) {
      const projectPath = join(CLAUDE_PROJECTS_DIR, projectDir);
      const projectStat = await stat(projectPath);

      if (!projectStat.isDirectory()) continue;

      const files = await readdir(projectPath);
      const sessionFiles = files.filter(f => f.endsWith('.jsonl'));

      for (const file of sessionFiles) {
        const filePath = join(projectPath, file);
        const fileStat = await stat(filePath);
        const id = file.replace('.jsonl', '');

        // Try to get title
        let title: string | undefined;
        try {
          const content = await readFile(filePath, 'utf-8');
          const firstLine = content.split('\n')[0];
          if (firstLine) {
            const parsed = JSON.parse(firstLine);
            if (parsed.type === 'summary' && parsed.summary) {
              title = parsed.summary;
            }
          }
        } catch {}

        sessions.push({
          id,
          path: filePath,
          projectPath: '/' + projectDir.replace(/^-/, '').replace(/-/g, '/'),
          modifiedAt: fileStat.mtime,
          title,
        });
      }
    }

    sessions.sort((a, b) => b.modifiedAt.getTime() - a.modifiedAt.getTime());
    return sessions.slice(0, limit);
  } catch {
    return [];
  }
}

async function getSessionContent(sessionId: string): Promise<string | null> {
  const sessions = await listSessions(100);
  const session = sessions.find(s => s.id === sessionId || s.id.startsWith(sessionId));
  if (!session) return null;
  return await readFile(session.path, 'utf-8');
}

function parseSessionContent(content: string, sessionId: string, customTitle?: string): ParsedSession {
  const lines = content.trim().split('\n').filter(line => line.trim());
  const messages: ParsedMessage[] = [];
  let title = customTitle || 'Untitled Session';
  const timestamps: number[] = [];
  const toolCounts: Record<string, number> = {};
  let messageIndex = 0;

  // Key moments tracking (matching CLI parser)
  const filesCreated = new Set<string>();
  const filesModified = new Set<string>();
  const commandsRun: string[] = [];
  let totalChars = 0;

  for (const line of lines) {
    try {
      const raw = JSON.parse(line);

      // Extract title from summary
      if (raw.type === 'summary' && raw.summary && !customTitle) {
        title = raw.summary;
        continue;
      }

      if (raw.type === 'file-history-snapshot') continue;
      if (!raw.message) continue;

      const timestamp = raw.timestamp || new Date().toISOString();
      if (raw.timestamp) {
        timestamps.push(new Date(raw.timestamp).getTime());
      }

      if (raw.type === 'user') {
        if (typeof raw.message.content === 'string') {
          // Human message
          totalChars += raw.message.content.length;
          messages.push({
            id: `msg-${messageIndex++}`,
            type: 'human',
            content: raw.message.content,
            timestamp,
          });
        } else if (Array.isArray(raw.message.content)) {
          // Tool results
          for (const block of raw.message.content) {
            if (block.type === 'tool_result') {
              let output = '';
              if (raw.toolUseResult?.stdout) output = raw.toolUseResult.stdout;
              if (raw.toolUseResult?.stderr) output += (output ? '\n' : '') + raw.toolUseResult.stderr;
              if (!output && typeof block.content === 'string') output = block.content;

              totalChars += output.length;
              messages.push({
                id: `msg-${messageIndex++}`,
                type: 'tool_result',
                content: output,
                timestamp,
                toolId: block.tool_use_id,
                toolOutput: output,
                isError: block.is_error,
              });
            }
          }
        }
      } else if (raw.type === 'assistant' && Array.isArray(raw.message.content)) {
        for (const block of raw.message.content) {
          if (block.type === 'thinking') continue;

          if (block.type === 'text' && block.text) {
            totalChars += block.text.length;
            messages.push({
              id: `msg-${messageIndex++}`,
              type: 'assistant',
              content: block.text,
              timestamp,
            });
          } else if (block.type === 'tool_use') {
            toolCounts[block.name] = (toolCounts[block.name] || 0) + 1;

            // Extract key moments
            const input = block.input as Record<string, unknown> | undefined;
            if (block.name === 'Write' && input?.file_path) {
              filesCreated.add(String(input.file_path));
            }
            if (block.name === 'Edit' && input?.file_path) {
              filesModified.add(String(input.file_path));
            }
            if (block.name === 'Bash' && input?.command) {
              const cmd = String(input.command);
              // Only track interesting commands (not cd, ls, etc.)
              if (!cmd.match(/^(cd|ls|pwd|echo|cat|head|tail)\b/) && cmd.length < 100) {
                commandsRun.push(cmd);
              }
            }

            messages.push({
              id: `msg-${messageIndex++}`,
              type: 'tool_call',
              content: formatToolCall(block.name, block.input),
              timestamp,
              toolName: block.name,
              toolInput: block.input,
              toolId: block.id,
            });
          }
        }
      }
    } catch {}
  }

  // Use first human message as title if no summary
  if (title === 'Untitled Session') {
    const firstHuman = messages.find(m => m.type === 'human');
    if (firstHuman) {
      title = firstHuman.content.slice(0, 100) + (firstHuman.content.length > 100 ? '...' : '');
    }
  }

  const startTime = timestamps.length > 0 ? new Date(Math.min(...timestamps)).toISOString() : new Date().toISOString();
  const endTime = timestamps.length > 0 ? new Date(Math.max(...timestamps)).toISOString() : new Date().toISOString();
  const durationSeconds = timestamps.length >= 2 ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000) : 0;

  return {
    id: sessionId,
    title,
    messages,
    metadata: {
      messageCount: messages.filter(m => m.type === 'human' || m.type === 'assistant').length,
      toolCount: Object.values(toolCounts).reduce((a, b) => a + b, 0),
      durationSeconds,
      startTime,
      endTime,
      tools: toolCounts,
      filesCreated: [...filesCreated].slice(0, 20),
      filesModified: [...filesModified].slice(0, 20),
      commandsRun: commandsRun.slice(0, 15),
      estimatedTokens: Math.round(totalChars / 4),
    },
  };
}

function formatToolCall(name: string, input?: Record<string, unknown>): string {
  if (!input) return name;
  if (name === 'Bash' && input.command) return `$ ${input.command}`;
  if (name === 'Read' && input.file_path) return `read ${input.file_path}`;
  if (name === 'Write' && input.file_path) return `write ${input.file_path}`;
  if (name === 'Edit' && input.file_path) return `edit ${input.file_path}`;
  return `${name}: ${JSON.stringify(input)}`;
}

// Simple encryption (matching the CLI)
function generateKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function encrypt(data: string, key: Uint8Array): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoder.encode(data));

  return {
    ciphertext: Buffer.from(encrypted).toString('base64url'),
    iv: Buffer.from(iv).toString('base64url'),
  };
}

async function shareSession(sessionId: string, title?: string): Promise<{ url: string } | { error: string }> {
  const content = await getSessionContent(sessionId);
  if (!content) {
    return { error: `Session not found: ${sessionId}` };
  }

  // Parse session into structured format (matching CLI parser)
  const parsedSession = parseSessionContent(content, sessionId, title);

  // Render session to full HTML (matching CLI)
  const renderedHtml = renderSessionToHtml(parsedSession);

  // Create payload with both HTML and session data (like CLI does)
  const payload = JSON.stringify({
    html: renderedHtml,
    session: {
      id: parsedSession.id,
      title: parsedSession.title,
      metadata: parsedSession.metadata,
      messages: parsedSession.messages,
    },
  });

  // Encrypt the payload
  const key = generateKey();
  const { ciphertext, iv } = await encrypt(payload, key);

  const { messageCount, toolCount, durationSeconds } = parsedSession.metadata;

  // Upload
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (API_KEY) {
      headers['Authorization'] = `Bearer ${API_KEY}`;
    }

    const response = await fetch(`${API_URL}/api/upload`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        encryptedBlob: ciphertext,
        iv,
        visibility: 'public',
        metadata: {
          title: parsedSession.title.slice(0, 200),
          messageCount,
          toolCount,
          durationSeconds,
        },
      }),
    });

    if (!response.ok) {
      return { error: `Upload failed: ${response.statusText}` };
    }

    const result = await response.json() as { id: string; url: string };
    const keyBase64 = Buffer.from(key).toString('base64url');
    return { url: `${result.url}#key=${keyBase64}` };
  } catch (err) {
    return { error: `Upload failed: ${err}` };
  }
}

// MCP Server setup
const server = new Server(
  { name: 'claudereview', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'list_sessions',
      description: `List available Claude Code sessions from ~/.claude/projects.

Returns the most recent sessions with:
- Session ID (use for sharing)
- Title (from session summary)
- Project path
- Last modified time

Example: list_sessions(limit: 5)`,
      inputSchema: {
        type: 'object',
        properties: {
          limit: {
            type: 'number',
            description: 'Maximum number of sessions to return (default: 10)',
          },
        },
      },
    },
    {
      name: 'share_session',
      description: `Share a Claude Code session to claudereview.com with full-featured viewer.

Creates an E2E encrypted link with:
- TUI-style dark/light theme viewer
- Search overlay (⌘F)
- Collapsible tool outputs
- Syntax highlighted code blocks
- Diff view for file edits
- Key moments summary (files created/modified, commands run)
- Git context (repo, branch, commit)
- Clickable tool badges to jump to instances
- Token/cost estimates
- Deep linking to specific messages
- OG meta tags for link previews

The encryption key is embedded in the URL fragment (#key=xxx) and never sent to the server.

Set CCSHARE_API_KEY environment variable to link sessions to your account and manage them in the dashboard.

Example: share_session(session_id: "last", title: "Bug fix for auth")`,
      inputSchema: {
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Session ID to share. Use "last" for the most recent session, or provide the session ID from list_sessions.',
          },
          title: {
            type: 'string',
            description: 'Custom title for the shared session. If not provided, uses the session summary.',
          },
        },
        required: ['session_id'],
      },
    },
  ],
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === 'list_sessions') {
    const limit = (args?.limit as number) || 10;
    const sessions = await listSessions(limit);

    const formatted = sessions.map((s, i) =>
      `${i + 1}. [${s.id.slice(0, 8)}] ${s.title || 'Untitled'}\n   Project: ${s.projectPath}\n   Modified: ${s.modifiedAt.toLocaleString()}`
    ).join('\n\n');

    return {
      content: [{ type: 'text', text: formatted || 'No sessions found.' }],
    };
  }

  if (name === 'share_session') {
    let sessionId = args?.session_id as string;
    const title = args?.title as string | undefined;

    if (sessionId === 'last') {
      const sessions = await listSessions(1);
      if (sessions.length === 0) {
        return { content: [{ type: 'text', text: 'No sessions found.' }] };
      }
      sessionId = sessions[0]!.id;
    }

    const result = await shareSession(sessionId, title);

    if ('error' in result) {
      return { content: [{ type: 'text', text: `Error: ${result.error}` }] };
    }

    const authNote = API_KEY
      ? 'This session is linked to your account.'
      : '⚠️ No API key configured - session shared anonymously. Set CCSHARE_API_KEY to link sessions to your account.';

    return {
      content: [{ type: 'text', text: `Session shared successfully!\n\nURL: ${result.url}\n\nThis link is encrypted. Only people with this exact URL can view the session.\n\n${authNote}` }],
    };
  }

  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('claudereview MCP server running');
}

main().catch(console.error);
