import { readdir, stat, readFile, open } from 'fs/promises';
import { join, basename } from 'path';
import { homedir } from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import type { LocalSession, ParsedSession } from './types.ts';
import { parseSessionFile, parseSessionContent } from './parser.ts';
import { parseCodexSessionFile } from './codex-parser.ts';
import { parseGeminiSessionFile, isGeminiFormat } from './gemini-parser.ts';

const execAsync = promisify(exec);

const CLAUDE_PROJECTS_DIR = join(homedir(), '.claude', 'projects');
const CODEX_SESSIONS_DIR = join(homedir(), '.codex', 'sessions');
const GEMINI_SESSIONS_DIR = join(homedir(), '.gemini', 'tmp');
const FIRST_LINE_READ_LIMIT_BYTES = 64 * 1024;
const FIRST_LINE_CHUNK_BYTES = 4 * 1024;

function parseCodexSessionId(file: string): string {
  const idMatch = file.match(/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\.jsonl$/i);
  return idMatch?.[1] ?? file.replace('.jsonl', '');
}

async function readFirstLine(filePath: string, limitBytes = FIRST_LINE_READ_LIMIT_BYTES): Promise<string> {
  const handle = await open(filePath, 'r');

  try {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let position = 0;

    while (totalBytes < limitBytes) {
      const bytesToRead = Math.min(FIRST_LINE_CHUNK_BYTES, limitBytes - totalBytes);
      const buffer = Buffer.alloc(bytesToRead);
      const { bytesRead } = await handle.read(buffer, 0, bytesToRead, position);

      if (bytesRead === 0) break;

      const chunk = buffer.subarray(0, bytesRead);
      const newlineIndex = chunk.indexOf(0x0a);

      if (newlineIndex >= 0) {
        chunks.push(chunk.subarray(0, newlineIndex));
        break;
      }

      chunks.push(chunk);
      totalBytes += bytesRead;
      position += bytesRead;
    }

    return Buffer.concat(chunks).toString('utf-8').replace(/\r$/, '');
  } finally {
    await handle.close();
  }
}

async function readCodexProjectPath(filePath: string): Promise<string> {
  try {
    const firstLine = await readFirstLine(filePath);
    if (!firstLine) return '';

    const parsed = JSON.parse(firstLine);
    if (parsed.type === 'session_meta' && parsed.payload?.cwd) {
      return parsed.payload.cwd;
    }
  } catch {
    // Ignore errors reading metadata
  }

  return '';
}

async function createCodexLocalSession(filePath: string, file: string): Promise<LocalSession> {
  const fileStat = await stat(filePath);

  return {
    id: parseCodexSessionId(file),
    path: filePath,
    projectPath: await readCodexProjectPath(filePath),
    modifiedAt: fileStat.mtime,
    title: undefined,
    source: 'codex',
  };
}

function looksLikeCodexSessionId(sessionId: string): boolean {
  return /^[a-f0-9-]{8,}$/i.test(sessionId);
}

async function getCodexSessionById(sessionId: string): Promise<LocalSession | null> {
  let prefixMatch: { filePath: string; file: string } | null = null;

  try {
    const years = await readdir(CODEX_SESSIONS_DIR);

    for (const year of years) {
      const yearPath = join(CODEX_SESSIONS_DIR, year);
      let yearStat;
      try {
        yearStat = await stat(yearPath);
      } catch {
        continue;
      }
      if (!yearStat.isDirectory()) continue;

      const months = await readdir(yearPath);
      for (const month of months) {
        const monthPath = join(yearPath, month);
        let monthStat;
        try {
          monthStat = await stat(monthPath);
        } catch {
          continue;
        }
        if (!monthStat.isDirectory()) continue;

        const days = await readdir(monthPath);
        for (const day of days) {
          const dayPath = join(monthPath, day);
          let dayStat;
          try {
            dayStat = await stat(dayPath);
          } catch {
            continue;
          }
          if (!dayStat.isDirectory()) continue;

          const files = await readdir(dayPath);
          for (const file of files.filter(f => f.endsWith('.jsonl'))) {
            const id = parseCodexSessionId(file);
            const filePath = join(dayPath, file);

            if (id === sessionId) {
              return createCodexLocalSession(filePath, file);
            }

            if (!id.startsWith(sessionId)) continue;

            if (prefixMatch) {
              throw new Error(`Ambiguous session ID "${sessionId}" matches multiple Codex sessions`);
            }

            prefixMatch = { filePath, file };
          }
        }
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }

  if (!prefixMatch) return null;

  return createCodexLocalSession(prefixMatch.filePath, prefixMatch.file);
}

/**
 * List all available sessions across all projects (Claude Code, Codex, and Gemini)
 */
export async function listSessions(): Promise<LocalSession[]> {
  const claudeSessions = await listClaudeSessions();
  const codexSessions = await listCodexSessions();
  const geminiSessions = await listGeminiSessions();

  // Merge and sort by modification time
  const allSessions = [...claudeSessions, ...codexSessions, ...geminiSessions];
  allSessions.sort((a, b) => b.modifiedAt.getTime() - a.modifiedAt.getTime());

  return allSessions;
}

/**
 * List Claude Code sessions from ~/.claude/projects/
 */
async function listClaudeSessions(): Promise<LocalSession[]> {
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

        // Extract session ID from filename
        const id = file.replace('.jsonl', '');

        // Try to get title from first line (summary)
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
        } catch {
          // Ignore errors reading title
        }

        sessions.push({
          id,
          path: filePath,
          projectPath: await decodeProjectPath(projectDir),
          modifiedAt: fileStat.mtime,
          title,
          source: 'claude',
        });
      }
    }

    return sessions;
  } catch (error) {
    console.error('Error listing Claude sessions:', error);
    return [];
  }
}

/**
 * List Codex sessions from ~/.codex/sessions/YYYY/MM/DD/
 */
async function listCodexSessions(): Promise<LocalSession[]> {
  const sessions: LocalSession[] = [];

  try {
    // Walk year directories
    const years = await readdir(CODEX_SESSIONS_DIR);

    for (const year of years) {
      const yearPath = join(CODEX_SESSIONS_DIR, year);
      let yearStat;
      try {
        yearStat = await stat(yearPath);
      } catch {
        continue;
      }
      if (!yearStat.isDirectory()) continue;

      // Walk month directories
      const months = await readdir(yearPath);
      for (const month of months) {
        const monthPath = join(yearPath, month);
        let monthStat;
        try {
          monthStat = await stat(monthPath);
        } catch {
          continue;
        }
        if (!monthStat.isDirectory()) continue;

        // Walk day directories
        const days = await readdir(monthPath);
        for (const day of days) {
          const dayPath = join(monthPath, day);
          let dayStat;
          try {
            dayStat = await stat(dayPath);
          } catch {
            continue;
          }
          if (!dayStat.isDirectory()) continue;

          // Find session files
          const files = await readdir(dayPath);
          for (const file of files.filter(f => f.endsWith('.jsonl'))) {
            const filePath = join(dayPath, file);
            sessions.push(await createCodexLocalSession(filePath, file));
          }
        }
      }
    }

    return sessions;
  } catch (error) {
    // Codex directory may not exist
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.error('Error listing Codex sessions:', error);
    }
    return [];
  }
}

/**
 * List Gemini CLI sessions from ~/.gemini/tmp/<project_hash>/chats/
 */
async function listGeminiSessions(): Promise<LocalSession[]> {
  const sessions: LocalSession[] = [];

  try {
    // Walk project hash directories
    const projectHashes = await readdir(GEMINI_SESSIONS_DIR);

    for (const projectHash of projectHashes) {
      const projectPath = join(GEMINI_SESSIONS_DIR, projectHash);
      let projectStat;
      try {
        projectStat = await stat(projectPath);
      } catch {
        continue;
      }
      if (!projectStat.isDirectory()) continue;

      // Look for chats directory
      const chatsDir = join(projectPath, 'chats');
      try {
        await stat(chatsDir);
      } catch {
        continue; // No chats directory
      }

      // Find session files (session-*.json or checkpoint-*.json)
      const files = await readdir(chatsDir);
      const sessionFiles = files.filter(f => f.endsWith('.json'));

      for (const file of sessionFiles) {
        const filePath = join(chatsDir, file);
        const fileStat = await stat(filePath);

        // Extract session ID from filename
        const id = file.replace('.json', '').replace(/^(session-|checkpoint-)/, '');

        // Try to validate it's a Gemini session and get title from first user message
        let title: string | undefined;
        let cwd = '';
        try {
          const content = await readFile(filePath, 'utf-8');
          if (!isGeminiFormat(content)) continue; // Skip non-Gemini files

          const parsed = JSON.parse(content);
          const messages = parsed.messages || parsed.contents || [];
          const firstUser = messages.find((m: { role: string }) => m.role === 'user');
          if (firstUser?.parts?.[0]?.text) {
            title = firstUser.parts[0].text.slice(0, 100);
            if (firstUser.parts[0].text.length > 100) title += '...';
          }
          // Get cwd if available
          if (parsed.cwd) cwd = parsed.cwd;
        } catch {
          // Ignore errors reading metadata
        }

        sessions.push({
          id,
          path: filePath,
          projectPath: cwd || `gemini/${projectHash}`,
          modifiedAt: fileStat.mtime,
          title,
          source: 'gemini',
        });
      }
    }

    return sessions;
  } catch (error) {
    // Gemini directory may not exist
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.error('Error listing Gemini sessions:', error);
    }
    return [];
  }
}

/**
 * Find sessions for a specific project directory
 */
export async function listSessionsForProject(projectDir: string): Promise<LocalSession[]> {
  const allSessions = await listSessions();
  const normalizedProject = normalizeProjectPath(projectDir);

  return allSessions.filter(session => {
    const normalizedSession = normalizeProjectPath(session.projectPath);
    return normalizedSession === normalizedProject;
  });
}

/**
 * Get a session by ID (searches all projects)
 */
export async function getSession(sessionId: string): Promise<LocalSession | null> {
  if (looksLikeCodexSessionId(sessionId)) {
    const codexSession = await getCodexSessionById(sessionId);
    if (codexSession) return codexSession;
  }

  const sessions = await listSessions();

  // Try exact match first
  let session = sessions.find(s => s.id === sessionId);
  if (session) return session;

  // Try partial match (prefix)
  const matches = sessions.filter(s => s.id.startsWith(sessionId));
  if (matches.length === 1) return matches[0] ?? null;
  if (matches.length > 1) {
    throw new Error(`Ambiguous session ID "${sessionId}" matches ${matches.length} sessions`);
  }

  // Try index (1-based)
  const index = parseInt(sessionId, 10);
  if (!isNaN(index) && index >= 1 && index <= sessions.length) {
    return sessions[index - 1] ?? null;
  }

  return null;
}

/**
 * Get the most recent session
 */
export async function getLastSession(): Promise<LocalSession | null> {
  const sessions = await listSessions();
  return sessions[0] || null;
}

/**
 * Parse a session by ID (auto-detects Claude vs Codex vs Gemini)
 */
export async function parseSession(sessionId: string): Promise<ParsedSession> {
  const session = await getSession(sessionId);
  if (!session) {
    throw new Error(`Session not found: ${sessionId}`);
  }

  if (session.source === 'codex') {
    return parseCodexSessionFile(session.path);
  }
  if (session.source === 'gemini') {
    return parseGeminiSessionFile(session.path);
  }
  return parseSessionFile(session.path);
}

/**
 * Parse the most recent session
 */
export async function parseLastSession(): Promise<ParsedSession> {
  const session = await getLastSession();
  if (!session) {
    throw new Error('No sessions found');
  }

  if (session.source === 'codex') {
    return parseCodexSessionFile(session.path);
  }
  if (session.source === 'gemini') {
    return parseGeminiSessionFile(session.path);
  }
  return parseSessionFile(session.path);
}

/**
 * Decode the project directory name to actual path
 * e.g., "-Users-vignesh-myproject" -> "/Users/vignesh/myproject"
 *
 * Note: This encoding is lossy - a hyphen in a directory name (e.g., "my-app")
 * becomes indistinguishable from a path separator. We try to find the actual
 * path by walking up from the most specific interpretation.
 */
async function decodeProjectPath(encodedPath: string): Promise<string> {
  // Simple decode: replace leading dash and subsequent dashes with path separators
  const simpleDecoded = '/' + encodedPath.replace(/^-/, '').replace(/-/g, '/');

  // Try to validate the path exists
  try {
    await stat(simpleDecoded);
    return simpleDecoded;
  } catch {
    // Path doesn't exist, try to find a valid parent path
    // by progressively joining segments
  }

  // Try building path by checking each level
  const segments = encodedPath.replace(/^-/, '').split('-');
  let currentPath = '';

  for (let i = 0; i < segments.length; i++) {
    const testPath = currentPath + '/' + segments[i];
    try {
      await stat(testPath);
      currentPath = testPath;
    } catch {
      // This segment might need to be joined with the next
      // Try joining remaining segments with hyphens progressively
      let remaining = segments.slice(i).join('-');
      const testFullPath = currentPath + '/' + remaining;
      try {
        await stat(testFullPath);
        return testFullPath;
      } catch {
        // Keep trying with fewer hyphens converted to path separators
        currentPath = testPath;
      }
    }
  }

  // If we can't validate, return the simple decoded version
  // (it's only used for display/filtering anyway)
  return simpleDecoded;
}

/**
 * Normalize a project path for comparison
 */
function normalizeProjectPath(path: string): string {
  return path.replace(/\/$/, '').toLowerCase();
}

/**
 * Format duration in human readable format
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.round((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

/**
 * Format relative time
 */
export function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}

/**
 * Git context information
 */
export interface GitContext {
  gitRepo?: string;
  gitBranch?: string;
  gitCommit?: string;
}

/**
 * Detect git context from a project directory
 */
export async function detectGitContext(projectPath: string): Promise<GitContext> {
  const context: GitContext = {};

  try {
    // Get remote origin URL
    const { stdout: remoteUrl } = await execAsync('git remote get-url origin', { cwd: projectPath });
    context.gitRepo = remoteUrl.trim();
  } catch {
    // Not a git repo or no remote
  }

  try {
    // Get current branch
    const { stdout: branch } = await execAsync('git branch --show-current', { cwd: projectPath });
    context.gitBranch = branch.trim() || undefined;
  } catch {
    // No branch info
  }

  try {
    // Get current commit hash
    const { stdout: commit } = await execAsync('git rev-parse HEAD', { cwd: projectPath });
    context.gitCommit = commit.trim();
  } catch {
    // No commit info
  }

  return context;
}

/**
 * Parse a session with git context
 */
export async function parseSessionWithGit(sessionId: string): Promise<ParsedSession> {
  const session = await getSession(sessionId);
  if (!session) {
    throw new Error(`Session not found: ${sessionId}`);
  }

  let parsed: ParsedSession;
  if (session.source === 'codex') {
    parsed = await parseCodexSessionFile(session.path);
  } else if (session.source === 'gemini') {
    parsed = await parseGeminiSessionFile(session.path);
  } else {
    parsed = await parseSessionFile(session.path);
  }

  // Try to detect git context from the project directory
  // (Codex may already have git context from session_meta, but we'll override with fresh data)
  if (session.projectPath) {
    const gitContext = await detectGitContext(session.projectPath);

    // Merge git context into metadata
    parsed.metadata = {
      ...parsed.metadata,
      ...gitContext,
    };
  }

  return parsed;
}
