// Types for Claude Code session parsing and sharing

// Raw JSONL message types from Claude Code sessions
export interface RawMessage {
  type: 'user' | 'assistant' | 'summary' | 'file-history-snapshot';
  uuid?: string;
  parentUuid?: string | null;
  timestamp?: string;
  sessionId?: string;
  message?: {
    role: 'user' | 'assistant';
    content: string | ContentBlock[];
  };
  summary?: string;
  toolUseResult?: {
    stdout?: string;
    stderr?: string;
    isImage?: boolean;
    status?: string;
  };
}

export interface ContentBlock {
  type: 'text' | 'thinking' | 'tool_use' | 'tool_result';
  text?: string;
  thinking?: string;
  name?: string;
  id?: string;
  input?: Record<string, unknown>;
  tool_use_id?: string;
  content?: string | ContentBlock[];
  is_error?: boolean;
}

// Parsed session structure
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
  tools: Record<string, number>; // tool name -> usage count
  // Key moments for TL;DR
  filesCreated?: string[];
  filesModified?: string[];
  commandsRun?: string[];
  // Estimated usage
  estimatedTokens?: number;
  // Git context if detectable
  gitRepo?: string;
  gitBranch?: string;
}

export interface ParsedMessage {
  id: string;
  type: 'human' | 'assistant' | 'tool_call' | 'tool_result';
  content: string;
  timestamp: string;
  // For tool_call type
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolId?: string;
  // For tool_result type
  toolOutput?: string;
  isError?: boolean;
  // For assistant type with multiple parts
  parts?: MessagePart[];
}

export interface MessagePart {
  type: 'text' | 'tool_call';
  content?: string;
  toolName?: string;
  toolInput?: Record<string, unknown>;
  toolId?: string;
}

// Session discovery
export interface LocalSession {
  id: string;
  path: string;
  projectPath: string;
  modifiedAt: Date;
  title?: string;
}

// Encrypted session for upload
export interface EncryptedSession {
  encryptedBlob: string; // base64 encoded
  iv: string; // base64 encoded initialization vector
  metadata: {
    title: string;
    messageCount: number;
    toolCount: number;
    durationSeconds: number;
  };
  visibility: 'public' | 'private';
  salt?: string; // for private sessions (password key derivation)
}

// API types
export interface UploadRequest {
  encryptedBlob: string;
  iv: string;
  metadata: {
    title: string;
    messageCount: number;
    toolCount: number;
    durationSeconds: number;
  };
  visibility: 'public' | 'private';
  salt?: string;
}

export interface UploadResponse {
  id: string;
  url: string;
  key?: string; // encryption key for public sessions (to construct full URL)
}

export interface SessionResponse {
  id: string;
  encryptedBlob: string;
  iv: string;
  visibility: 'public' | 'private';
  salt?: string;
  metadata: {
    title: string;
    messageCount: number;
    toolCount: number;
    durationSeconds: number;
    createdAt: string;
  };
}
