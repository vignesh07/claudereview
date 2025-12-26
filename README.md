# claudereview

Share Claude Code sessions for code review. End-to-end encrypted.

## Installation

```bash
# Install globally
bun add -g claudereview

# Or run directly
bunx claudereview
```

## Usage

```bash
# List your Claude Code sessions
ccshare list

# Share a specific session by ID
ccshare share abc123

# Share your last session
ccshare share --last

# Share with password protection
ccshare share --last --private "your-password"

# Preview the most recent session in browser
ccshare preview --last

# Export to HTML file
ccshare export --last -o session.html
```

## Features

- **E2E Encrypted**: Sessions are encrypted client-side. Keys never touch the server.
- **Public & Private Links**: Share openly or protect with a password.
- **TUI Aesthetic**: Beautiful terminal-style viewer.
- **Deep Linking**: Link directly to specific messages.
- **Self-Contained**: Exported HTML works offline.

## Claude Code Integration

### MCP Server

Share sessions directly from Claude by adding to `~/.claude/settings.json`:

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

Then just ask Claude: "Share this session" or "List my recent sessions".

### Slash Command

Add a quick slash command by creating `~/.claude/commands/share.md`:

```markdown
Share this Claude Code session using claudereview.

Run: bunx claudereview share --last

Return the URL to me.
```

Then type `/share` in any Claude Code session.

## How It Works

### Public Shares
1. CLI encrypts session with a random key
2. Uploads encrypted blob to claudereview.com
3. Returns URL with key in fragment: `claudereview.com/s/abc123#key=xxx`
4. The `#key=xxx` fragment is never sent to the server
5. Browser decrypts client-side

### Private Shares
1. CLI encrypts session with password-derived key (Argon2)
2. Uploads encrypted blob + salt
3. Returns URL without key: `claudereview.com/s/abc123`
4. Viewer prompts for password, derives key, decrypts

## Development

```bash
# Install dependencies
bun install

# Run server locally
bun run dev

# Run CLI
bun run cli list
```

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `BASE_URL`: Public URL (default: https://claudereview.com)
- `PORT`: Server port (default: 3000)
- `CCSHARE_API_URL`: API URL for CLI (default: https://claudereview.com)
- `CCSHARE_API_KEY`: API key for authenticated uploads

## Deployment

Deploy to Railway:

```bash
railway up
```

Required Railway services:
- PostgreSQL database

## License

MIT
