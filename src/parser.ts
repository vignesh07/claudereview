import { readFile } from 'fs/promises';
import type {
  RawMessage,
  ContentBlock,
  ParsedSession,
  ParsedMessage,
  MessagePart,
  SessionMetadata,
} from './types.ts';

/**
 * Parse a Claude Code session JSONL file into a structured format
 */
export async function parseSessionFile(filePath: string): Promise<ParsedSession> {
  const content = await readFile(filePath, 'utf-8');
  return parseSessionContent(content, extractSessionId(filePath));
}

/**
 * Parse JSONL content directly
 */
export function parseSessionContent(content: string, sessionId: string): ParsedSession {
  const lines = content.trim().split('\n').filter(line => line.trim());
  const rawMessages: RawMessage[] = [];
  let title = 'Untitled Session';

  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as RawMessage;
      rawMessages.push(parsed);

      // Extract title from summary if available
      if (parsed.type === 'summary' && parsed.summary) {
        title = parsed.summary;
      }
    } catch {
      // Skip malformed lines
      console.warn('Skipping malformed JSON line');
    }
  }

  const messages = processMessages(rawMessages);
  const metadata = computeMetadata(messages, rawMessages);

  // If no summary, use first human message as title
  if (title === 'Untitled Session') {
    const firstHuman = messages.find(m => m.type === 'human');
    if (firstHuman) {
      title = truncate(firstHuman.content, 100);
    }
  }

  return {
    id: sessionId,
    title,
    messages,
    metadata,
  };
}

/**
 * Process raw messages into parsed format
 */
function processMessages(rawMessages: RawMessage[]): ParsedMessage[] {
  const parsed: ParsedMessage[] = [];
  let messageIndex = 0;

  for (const raw of rawMessages) {
    // Skip metadata types
    if (raw.type === 'summary' || raw.type === 'file-history-snapshot') {
      continue;
    }

    if (!raw.message) continue;

    const timestamp = raw.timestamp || new Date().toISOString();

    if (raw.type === 'user') {
      // Check if it's a human message or tool result
      if (typeof raw.message.content === 'string') {
        // Human message
        parsed.push({
          id: `msg-${messageIndex++}`,
          type: 'human',
          content: raw.message.content,
          timestamp,
        });
      } else if (Array.isArray(raw.message.content)) {
        // Tool result(s)
        for (const block of raw.message.content) {
          if (block.type === 'tool_result') {
            const output = extractToolOutput(block, raw.toolUseResult);
            parsed.push({
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
    } else if (raw.type === 'assistant') {
      const content = raw.message.content;
      if (!Array.isArray(content)) continue;

      const parts: MessagePart[] = [];
      let hasText = false;

      for (const block of content) {
        // Skip thinking blocks - they're internal
        if (block.type === 'thinking') continue;

        if (block.type === 'text' && block.text) {
          hasText = true;
          parts.push({
            type: 'text',
            content: block.text,
          });
        } else if (block.type === 'tool_use') {
          parts.push({
            type: 'tool_call',
            toolName: block.name,
            toolInput: block.input,
            toolId: block.id,
          });
        }
      }

      // Only add if there's actual content
      if (parts.length > 0) {
        // If only text, simplify
        const firstPart = parts[0];
        if (parts.length === 1 && firstPart && firstPart.type === 'text') {
          parsed.push({
            id: `msg-${messageIndex++}`,
            type: 'assistant',
            content: firstPart.content || '',
            timestamp,
          });
        } else if (parts.every(p => p.type === 'tool_call')) {
          // Only tool calls
          for (const part of parts) {
            parsed.push({
              id: `msg-${messageIndex++}`,
              type: 'tool_call',
              content: formatToolCall(part.toolName!, part.toolInput),
              timestamp,
              toolName: part.toolName,
              toolInput: part.toolInput,
              toolId: part.toolId,
            });
          }
        } else {
          // Mixed content
          parsed.push({
            id: `msg-${messageIndex++}`,
            type: 'assistant',
            content: parts.filter(p => p.type === 'text').map(p => p.content).join('\n'),
            timestamp,
            parts,
          });
        }
      }
    }
  }

  return parsed;
}

/**
 * Extract tool output from block and optional toolUseResult
 */
function extractToolOutput(
  block: ContentBlock,
  toolUseResult?: RawMessage['toolUseResult']
): string {
  // Prefer parsed toolUseResult if available
  if (toolUseResult) {
    const parts: string[] = [];
    if (toolUseResult.stdout) parts.push(toolUseResult.stdout);
    if (toolUseResult.stderr) parts.push(`[stderr] ${toolUseResult.stderr}`);
    if (parts.length > 0) return parts.join('\n');
  }

  // Fall back to content from block
  if (typeof block.content === 'string') {
    return block.content;
  }

  return '';
}

/**
 * Format a tool call for display
 */
function formatToolCall(name: string, input?: Record<string, unknown>): string {
  if (!input) return name;

  // Special formatting for common tools
  if (name === 'Bash' && input.command) {
    return `$ ${input.command}`;
  }
  if (name === 'Read' && input.file_path) {
    return `read ${input.file_path}`;
  }
  if (name === 'Write' && input.file_path) {
    return `write ${input.file_path}`;
  }
  if (name === 'Edit' && input.file_path) {
    return `edit ${input.file_path}`;
  }
  if (name === 'Glob' && input.pattern) {
    return `glob ${input.pattern}`;
  }
  if (name === 'Grep' && input.pattern) {
    return `grep ${input.pattern}`;
  }

  return `${name}: ${JSON.stringify(input)}`;
}

/**
 * Compute session metadata from messages
 */
function computeMetadata(
  messages: ParsedMessage[],
  rawMessages: RawMessage[]
): SessionMetadata {
  const toolCounts: Record<string, number> = {};
  let toolCount = 0;

  // Key moments tracking
  const filesCreated = new Set<string>();
  const filesModified = new Set<string>();
  const commandsRun: string[] = [];

  // Token estimation (rough approximation: 1 token ≈ 4 chars)
  let totalChars = 0;

  for (const msg of messages) {
    // Count characters for token estimation
    totalChars += (msg.content || '').length;
    if (msg.toolOutput) totalChars += msg.toolOutput.length;

    if (msg.type === 'tool_call' && msg.toolName) {
      toolCounts[msg.toolName] = (toolCounts[msg.toolName] || 0) + 1;
      toolCount++;

      // Extract key moments
      const input = msg.toolInput;
      if (msg.toolName === 'Write' && input?.file_path) {
        filesCreated.add(String(input.file_path));
      }
      if (msg.toolName === 'Edit' && input?.file_path) {
        filesModified.add(String(input.file_path));
      }
      if (msg.toolName === 'Bash' && input?.command) {
        const cmd = String(input.command);
        // Only track interesting commands (not cd, ls, etc.)
        if (!cmd.match(/^(cd|ls|pwd|echo|cat|head|tail)\b/) && cmd.length < 100) {
          commandsRun.push(cmd);
        }
      }
    }
  }

  // Find start and end times from raw messages
  const timestamps = rawMessages
    .filter(m => m.timestamp)
    .map(m => new Date(m.timestamp!).getTime())
    .filter(t => !isNaN(t));

  const startTime = timestamps.length > 0
    ? new Date(Math.min(...timestamps)).toISOString()
    : new Date().toISOString();

  const endTime = timestamps.length > 0
    ? new Date(Math.max(...timestamps)).toISOString()
    : new Date().toISOString();

  const durationSeconds = timestamps.length >= 2
    ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000)
    : 0;

  return {
    messageCount: messages.filter(m => m.type === 'human' || m.type === 'assistant').length,
    toolCount,
    durationSeconds,
    startTime,
    endTime,
    tools: toolCounts,
    filesCreated: [...filesCreated].slice(0, 20), // Limit to 20
    filesModified: [...filesModified].slice(0, 20),
    commandsRun: commandsRun.slice(0, 15), // Limit to 15 interesting commands
    estimatedTokens: Math.round(totalChars / 4),
  };
}

/**
 * Extract session ID from file path
 */
function extractSessionId(filePath: string): string {
  const match = filePath.match(/([a-f0-9-]{36}|agent-[a-f0-9]+)\.jsonl$/);
  return match?.[1] ?? 'unknown';
}

/**
 * Truncate string to max length with ellipsis
 */
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}
