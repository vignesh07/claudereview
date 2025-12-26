// Types for Claude Code session parsing and sharing

export interface ParsedSession {
  id: string;
  title: string;
  messages: ParsedMessage[];
  metadata: SessionMetadata;
}

export interface SessionMetadata {
  messageCount: number;
  toolCount: number;
  durationSeconds: number;
  startTime: string;
  endTime: string;
  tools: Record<string, number>;
  filesCreated?: string[];
  filesModified?: string[];
  commandsRun?: string[];
  estimatedTokens?: number;
  gitRepo?: string;
  gitBranch?: string;
  gitCommit?: string;
}

export interface ParsedMessage {
  id: string;
  type: 'human' | 'assistant' | 'tool_call' | 'tool_result';
  content: string;
  timestamp: string;
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolId?: string;
  toolOutput?: string;
  isError?: boolean;
  parts?: MessagePart[];
}

export interface MessagePart {
  type: 'text' | 'tool_call';
  content?: string;
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolId?: string;
}
