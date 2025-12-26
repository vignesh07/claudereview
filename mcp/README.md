# claudereview-mcp

MCP server for sharing Claude Code sessions via [claudereview.com](https://claudereview.com).

## Installation

```bash
npm install -g claudereview-mcp
# or
bun add -g claudereview-mcp
```

Then add to `~/.mcp.json`:

```json
{
  "mcpServers": {
    "claudereview": {
      "command": "bunx",
      "args": ["claudereview-mcp"]
    }
  }
}
```

## Tools

### `list_sessions`

List available Claude Code sessions.

```
list_sessions(limit?: number)
```

### `share_session`

Share a session and get an encrypted URL.

```
share_session(session_id: string, title?: string)
```

Use `session_id: "last"` to share the most recent session.

## Usage

Once configured, just ask Claude:

- "Share this session"
- "List my recent sessions"
- "Share session abc123 with title 'Bug fix review'"
