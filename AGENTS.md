# AGENTS.md - OpenCode Anthropic Auth Plugin

> Guidelines for AI agents working in this repository.

## Project Overview

This is an **OpenCode plugin** that provides OAuth2 authentication for Anthropic services (Claude Pro/Max and Console). It acts as transparent middleware that handles PKCE flows, token lifecycle, and API request/response transformations.

**Tech Stack**: Vanilla JavaScript (ES Modules), Bun runtime for scripts, JSDoc for types.

---

## Build / Lint / Test Commands

### Install Dependencies

```bash
bun install
# or
npm install
```

### Run / Test

This is a library plugin - no standalone execution. It's consumed by the OpenCode ecosystem.

**No test suite exists.** The plugin is validated through integration with OpenCode.

### Publish (Maintainers Only)

```bash
# Bump version and trigger GitHub Actions publish
bun run script/publish.ts patch   # or: minor, major
```

### CI/CD

- GitHub Actions workflow at `.github/workflows/publish.yml`
- Triggered manually via `workflow_dispatch`
- Publishes to npm with `--access public`

---

## Code Style Guidelines

### File Structure

```
.
├── index.mjs          # Main plugin implementation (single-file core)
├── package.json       # Dependencies and entry point
├── script/
│   └── publish.ts     # Bun-based publish automation
└── .github/workflows/ # CI/CD
```

### Language & Modules

- **ES Modules only** - use `import`/`export`, never `require()`
- File extension: `.mjs` for JavaScript, `.ts` for scripts
- Entry point defined in `package.json` as `"main": "./index.mjs"`

### Imports

```javascript
// Named imports from packages - at top of file
import { generatePKCE } from "@openauthjs/openauth/pkce";
```

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Functions & Variables | camelCase | `authorize`, `requestHeaders` |
| Constants | UPPER_SNAKE_CASE | `CLIENT_ID`, `TOOL_PREFIX` |
| Plugin Exports | PascalCase | `AnthropicAuthPlugin` |
| Files | lowercase | `index.mjs`, `publish.ts` |

### Formatting

- **Indentation**: 2 spaces
- **Quotes**: Double quotes (`"`)
- **Semicolons**: Required
- **Trailing commas**: Yes, in multi-line structures

```javascript
// Correct
const config = {
  key: "value",
  nested: {
    foo: "bar",
  },
};

// Incorrect
const config = {
    key: 'value'    // wrong indent, wrong quotes, missing comma
}
```

### Type Annotations (JSDoc)

Use JSDoc for type hints in `.mjs` files. Do NOT convert to TypeScript.

```javascript
/**
 * @param {"max" | "console"} mode
 */
async function authorize(mode) {
  // ...
}

/**
 * @type {import('@opencode-ai/plugin').Plugin}
 */
export async function AnthropicAuthPlugin({ client }) {
  // ...
}
```

For inline parameter types:

```javascript
/**
 * @param {string} code
 * @param {string} verifier
 */
async function exchange(code, verifier) {
  // ...
}
```

### Error Handling

1. **Network failures**: Check `response.ok`, return result objects or throw

```javascript
if (!result.ok) {
  return { type: "failed" };
}

// Or for critical failures:
if (!response.ok) {
  throw new Error(`Token refresh failed: ${response.status}`);
}
```

2. **Parsing failures**: Use try/catch with silent fallback when appropriate

```javascript
try {
  const parsed = JSON.parse(body);
  // transform...
} catch (e) {
  // ignore parse errors - keep original body
}
```

3. **Result objects**: Use `type` field for status

```javascript
return { type: "success", access: token };
return { type: "failed" };
```

### Comments

- Use JSDoc for function documentation
- Inline comments explain "why", not "what"

```javascript
// zero out cost for max plan
for (const model of Object.values(provider.models)) {
  model.cost = { input: 0, output: 0 };
}
```

---

## Key Patterns in This Codebase

### OAuth2 PKCE Flow

The plugin implements standard PKCE auth:
1. `authorize()` generates challenge/verifier pair
2. User visits auth URL, gets code
3. `exchange()` trades code for tokens

### Token Lifecycle

In `loader`, tokens are auto-refreshed when expired:

```javascript
if (!auth.access || auth.expires < Date.now()) {
  // refresh token flow
}
```

### Request/Response Transformation

The custom `fetch()` wrapper:
1. Injects `authorization` header with Bearer token
2. Sets required `anthropic-beta` headers
3. Prefixes tool names with `mcp_` in requests
4. Strips `mcp_` prefix from streaming responses

### Tool Name Prefixing

```javascript
const TOOL_PREFIX = "mcp_";
// Outgoing: tool.name → mcp_tool.name
// Incoming: "name": "mcp_foo" → "name": "foo"
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `@opencode-ai/plugin` | Plugin interface types (dev) |
| `@openauthjs/openauth` | PKCE generation for OAuth |

---

## Things to Avoid

- **Do NOT** add TypeScript compilation - this is intentionally vanilla JS
- **Do NOT** add linting/formatting configs - keep it simple
- **Do NOT** suppress errors with empty catch blocks (unless parsing fallback)
- **Do NOT** add new dependencies without strong justification
- **Do NOT** modify the PKCE or OAuth flow without understanding the full auth cycle

---

## Making Changes

1. All core logic lives in `index.mjs` - it's a single-file plugin
2. Test changes by integrating with OpenCode locally
3. Use `bun run script/publish.ts` to release (bumps version + triggers CI)
4. Follow existing patterns for request/response transformation
