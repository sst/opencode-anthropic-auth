import { generatePKCE } from "@openauthjs/openauth/pkce";

// ============================================================================
// Constants
// ============================================================================

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const BASE_FETCH = globalThis.fetch?.bind(globalThis);
const FETCH_PATCH_STATE = {
  installed: false,
  getAuth: null,
  client: null,
};

const MODEL_ID_OVERRIDES = new Map([
  ["claude-sonnet-4-5", "claude-sonnet-4-5-20250929"],
  ["claude-opus-4-5", "claude-opus-4-5-20251101"],
  ["claude-haiku-4-5", "claude-haiku-4-5-20251001"],
]);
const MODEL_ID_REVERSE_OVERRIDES = new Map(
  Array.from(MODEL_ID_OVERRIDES, ([base, full]) => [full, base]),
);

const CLAUDE_CODE_TOOL_NAMES = new Map([
  ["bash", "Bash"],
  ["read", "Read"],
  ["edit", "Edit"],
  ["write", "Write"],
  ["task", "Task"],
  ["glob", "Glob"],
  ["grep", "Grep"],
  ["webfetch", "WebFetch"],
  ["websearch", "WebSearch"],
  ["todowrite", "TodoWrite"],
]);
const OPENCODE_TOOL_NAMES = new Map(
  Array.from(CLAUDE_CODE_TOOL_NAMES, ([key, value]) => [value, key]),
);

const TOOL_NAME_CACHE_MAX_SIZE = 1000;
const TOOL_NAME_CACHE = new Map();
const TOOL_PREFIX_REGEX = /^(?:oc_|mcp_)/i;

let cachedMetadataUserIdPromise;

// ============================================================================
// Debug Logging
// ============================================================================

function debugLog(context, error) {
  if (globalThis.process?.env?.OPENCODE_DEBUG === "true") {
    console.debug(`[opencode-anthropic-auth] ${context}:`, error);
  }
}

// ============================================================================
// Low-level Utilities
// ============================================================================

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripToolPrefix(value) {
  if (!value) return value;
  return value.replace(TOOL_PREFIX_REGEX, "");
}

function toPascalCase(value) {
  if (!value) return value;
  const normalized = value.replace(/[^a-zA-Z0-9]+/g, " ");
  const tokens = normalized
    .split(" ")
    .flatMap((token) =>
      token
        .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
        .split(" ")
        .filter(Boolean),
    );
  if (tokens.length === 0) return value;
  return tokens
    .map((token) => {
      const lower = token.toLowerCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join("");
}

function toSnakeCase(value) {
  if (!value) return value;
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .toLowerCase();
}

function getBaseFetch() {
  return BASE_FETCH ?? globalThis.fetch;
}

// ============================================================================
// Environment & Headers
// ============================================================================

function getEnvConfig() {
  const env = globalThis.process?.env ?? {};
  const platform = globalThis.process?.platform ?? "linux";
  const os =
    env.OPENCODE_STAINLESS_OS ??
    (platform === "darwin"
      ? "Darwin"
      : platform === "win32"
        ? "Windows"
        : platform === "linux"
          ? "Linux"
          : platform);

  return {
    os,
    arch: env.OPENCODE_STAINLESS_ARCH ?? globalThis.process?.arch ?? "x64",
    lang: env.OPENCODE_STAINLESS_LANG ?? "js",
    packageVersion: env.OPENCODE_STAINLESS_PACKAGE_VERSION ?? "0.70.0",
    runtime: env.OPENCODE_STAINLESS_RUNTIME ?? "node",
    runtimeVersion:
      env.OPENCODE_STAINLESS_RUNTIME_VERSION ??
      globalThis.process?.version ??
      "v24.3.0",
    retryCount: env.OPENCODE_STAINLESS_RETRY_COUNT ?? "0",
    timeout: env.OPENCODE_STAINLESS_TIMEOUT ?? "600",
  };
}

function applyStainlessHeaders(headers, isStream = false) {
  const config = getEnvConfig();

  headers.set("user-agent", "claude-cli/2.1.2 (external, cli)");
  headers.set("x-app", "cli");
  headers.set("anthropic-dangerous-direct-browser-access", "true");
  headers.set("x-stainless-arch", config.arch);
  headers.set("x-stainless-lang", config.lang);
  headers.set("x-stainless-os", config.os);
  headers.set("x-stainless-package-version", config.packageVersion);
  headers.set("x-stainless-runtime", config.runtime);
  headers.set("x-stainless-runtime-version", config.runtimeVersion);
  headers.set("x-stainless-retry-count", config.retryCount);
  headers.set("x-stainless-timeout", config.timeout);

  if (isStream) {
    headers.set("x-stainless-helper-method", "stream");
  }
}

function getBetaHeadersForPath(pathname) {
  if (pathname === "/v1/messages") {
    return ["oauth-2025-04-20", "interleaved-thinking-2025-05-14"];
  }
  if (pathname === "/v1/messages/count_tokens") {
    return [
      "claude-code-20250219",
      "oauth-2025-04-20",
      "interleaved-thinking-2025-05-14",
      "token-counting-2024-11-01",
    ];
  }
  if (pathname.startsWith("/api/") && pathname !== "/api/hello") {
    return ["oauth-2025-04-20"];
  }
  return [];
}

function mergeHeaders(request, init) {
  const headers = new Headers();

  if (request instanceof Request) {
    request.headers.forEach((value, key) => headers.set(key, value));
  }

  const initHeaders = init?.headers;
  if (initHeaders) {
    if (initHeaders instanceof Headers) {
      initHeaders.forEach((value, key) => headers.set(key, value));
    } else if (Array.isArray(initHeaders)) {
      for (const [key, value] of initHeaders) {
        if (value !== undefined) headers.set(key, String(value));
      }
    } else {
      for (const [key, value] of Object.entries(initHeaders)) {
        if (value !== undefined) headers.set(key, String(value));
      }
    }
  }

  return headers;
}

function extractUrl(input) {
  try {
    if (typeof input === "string" || input instanceof URL) {
      return new URL(input.toString());
    }
    if (input instanceof Request) {
      return new URL(input.url);
    }
  } catch (error) {
    debugLog("extractUrl", error);
  }
  return null;
}

// ============================================================================
// Tool Name Normalization
// ============================================================================

function normalizeToolNameForClaude(name) {
  if (!name) return name;
  const stripped = stripToolPrefix(name);
  const mapped = CLAUDE_CODE_TOOL_NAMES.get(stripped.toLowerCase());
  const pascal = mapped ?? toPascalCase(stripped);
  if (pascal && pascal !== stripped) {
    // LRU-like eviction: remove oldest entries when cache is full
    if (TOOL_NAME_CACHE.size >= TOOL_NAME_CACHE_MAX_SIZE) {
      const firstKey = TOOL_NAME_CACHE.keys().next().value;
      TOOL_NAME_CACHE.delete(firstKey);
    }
    TOOL_NAME_CACHE.set(pascal, stripped);
  }
  return pascal;
}

function normalizeToolNameForOpenCode(name) {
  if (!name) return name;
  const cached = TOOL_NAME_CACHE.get(name);
  if (cached) return cached;
  return OPENCODE_TOOL_NAMES.get(name) ?? toSnakeCase(name);
}

function normalizeTools(tools) {
  if (Array.isArray(tools)) {
    return tools.map((tool) => ({
      ...tool,
      name: tool.name ? normalizeToolNameForClaude(tool.name) : tool.name,
    }));
  }

  if (tools && typeof tools === "object") {
    const mapped = {};
    for (const [key, value] of Object.entries(tools)) {
      const mappedKey = normalizeToolNameForClaude(key);
      mapped[mappedKey] =
        value && typeof value === "object"
          ? { ...value, name: value.name ? normalizeToolNameForClaude(value.name) : mappedKey }
          : value;
    }
    return mapped;
  }

  return tools;
}

function normalizeMessagesForClaude(messages) {
  if (!Array.isArray(messages)) return messages;
  return messages.map((message) => {
    if (!message || !Array.isArray(message.content)) return message;
    return {
      ...message,
      content: message.content.map((block) =>
        block?.type === "tool_use" && block.name
          ? { ...block, name: normalizeToolNameForClaude(block.name) }
          : block,
      ),
    };
  });
}

function normalizeModelId(id) {
  if (!id) return id;
  return MODEL_ID_OVERRIDES.get(id) ?? id;
}

function replaceToolNamesInText(text) {
  let output = text.replace(/"name"\s*:\s*"(?:oc_|mcp_)([^"]+)"/g, '"name": "$1"');

  output = output.replace(
    /"name"\s*:\s*"(Bash|Read|Edit|Write|Task|Glob|Grep|WebFetch|WebSearch|TodoWrite)"/g,
    (_, name) => `"name": "${normalizeToolNameForOpenCode(name)}"`,
  );

  for (const [pascal, original] of TOOL_NAME_CACHE.entries()) {
    if (pascal && pascal !== original) {
      output = output.replace(
        new RegExp(`"name"\\s*:\\s*"${escapeRegExp(pascal)}"`, "g"),
        `"name": "${original}"`,
      );
    }
  }

  for (const [full, base] of MODEL_ID_REVERSE_OVERRIDES.entries()) {
    output = output.replace(
      new RegExp(`"model"\\s*:\\s*"${escapeRegExp(full)}"`, "g"),
      `"model": "${base}"`,
    );
  }

  return output;
}

// ============================================================================
// Request/Response Processing
// ============================================================================

async function normalizeRequestBody(parsed, injectMetadata = false) {
  if (parsed.model) {
    parsed.model = normalizeModelId(parsed.model);
  }

  if (parsed.tools) {
    parsed.tools = normalizeTools(parsed.tools);
  }

  if (Array.isArray(parsed.messages)) {
    parsed.messages = normalizeMessagesForClaude(parsed.messages);
  }

  // OAuth API does not support tool_choice parameter - must be removed
  // to prevent "invalid_request_error" from Anthropic API
  if (parsed.tool_choice) {
    delete parsed.tool_choice;
  }

  if (injectMetadata) {
    const userId = await resolveMetadataUserId();
    if (userId) {
      parsed.metadata = parsed.metadata && typeof parsed.metadata === "object"
        ? { ...parsed.metadata }
        : {};
      if (!parsed.metadata.user_id) {
        parsed.metadata.user_id = userId;
      }
    }
  }

  return { body: parsed, isStream: !!parsed.stream };
}

function createTransformedResponse(response) {
  if (!response.body) return response;

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  
  // Buffer for incomplete SSE events (handles chunk boundary issues)
  let buffer = "";

  const stream = new ReadableStream({
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        // Process any remaining buffered content
        if (buffer.length > 0) {
          controller.enqueue(encoder.encode(replaceToolNamesInText(buffer)));
        }
        controller.close();
        return;
      }
      
      buffer += decoder.decode(value, { stream: true });
      
      // SSE events are separated by double newlines
      // Process only complete events, keep incomplete ones in buffer
      const events = buffer.split("\n\n");
      
      // Keep the last potentially incomplete event in buffer
      buffer = events.pop() ?? "";
      
      // Process and emit complete events
      if (events.length > 0) {
        const completeData = events.join("\n\n") + "\n\n";
        controller.enqueue(encoder.encode(replaceToolNamesInText(completeData)));
      }
    },
  });

  return new Response(stream, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

// ============================================================================
// OAuth Token Management
// ============================================================================

async function resolveMetadataUserId() {
  const env = globalThis.process?.env ?? {};
  const direct = env.OPENCODE_ANTHROPIC_USER_ID ?? env.CLAUDE_CODE_USER_ID ?? env.ANTHROPIC_USER_ID;
  if (direct) return direct;
  if (cachedMetadataUserIdPromise) return cachedMetadataUserIdPromise;

  cachedMetadataUserIdPromise = (async () => {
    const home = env.HOME ?? env.USERPROFILE;
    if (!home) return undefined;

    try {
      const { readFile } = await import("node:fs/promises");
      const data = JSON.parse(await readFile(env.OPENCODE_CLAUDE_CONFIG ?? `${home}/.claude.json`, "utf8"));
      const userId = data?.userID;
      const accountUuid = data?.oauthAccount?.accountUuid;

      let sessionId;
      const cwd = globalThis.process?.cwd?.();
      if (cwd && data?.projects?.[cwd]?.lastSessionId) {
        sessionId = data.projects[cwd].lastSessionId;
      } else if (data?.projects) {
        for (const project of Object.values(data.projects)) {
          if (project?.lastSessionId) {
            sessionId = project.lastSessionId;
            break;
          }
        }
      }

      if (userId && accountUuid && sessionId) {
        return `user_${userId}_account_${accountUuid}_session_${sessionId}`;
      }
    } catch (error) {
      debugLog("resolveMetadataUserId", error);
    }
    return undefined;
  })();

  return cachedMetadataUserIdPromise;
}

async function refreshOAuthToken(auth, baseFetch) {
  const response = await baseFetch("https://console.anthropic.com/v1/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "refresh_token",
      refresh_token: auth.refresh,
      client_id: CLIENT_ID,
    }),
  });
  if (!response.ok) throw new Error(`Token refresh failed: ${response.status}`);
  return response.json();
}

async function ensureOAuthAccess(getAuth, client) {
  if (!getAuth) return null;
  const auth = await getAuth();
  if (!auth || auth.type !== "oauth") return auth ?? null;
  if (auth.access && auth.expires > Date.now()) return auth;

  const json = await refreshOAuthToken(auth, getBaseFetch());
  const newExpires = Date.now() + json.expires_in * 1000;

  if (client?.auth?.set) {
    await client.auth.set({
      path: { id: "anthropic" },
      body: {
        type: "oauth",
        refresh: json.refresh_token,
        access: json.access_token,
        expires: newExpires,
      },
    });
  }

  // Update auth object in place (intentional mutation for caller's reference)
  // This ensures the caller's reference stays in sync with stored credentials
  auth.refresh = json.refresh_token;
  auth.access = json.access_token;
  auth.expires = newExpires;
  return auth;
}

// ============================================================================
// Anthropic Request Handler (shared logic)
// ============================================================================

async function handleAnthropicRequest(input, init, auth, baseFetch) {
  const requestUrl = extractUrl(input);
  
  // Safety check: if URL extraction failed, fall back to base fetch
  if (!requestUrl) {
    debugLog("handleAnthropicRequest", "Failed to extract URL from input");
    return baseFetch(input, init);
  }
  
  const requestHeaders = mergeHeaders(input instanceof Request ? input : null, init);

  // Beta headers
  const betaHeaders = getBetaHeadersForPath(requestUrl.pathname);
  if (betaHeaders.length > 0) {
    requestHeaders.set("anthropic-beta", betaHeaders.join(","));
  } else {
    requestHeaders.delete("anthropic-beta");
  }

  // Auth & stainless headers
  requestHeaders.set("authorization", `Bearer ${auth.access}`);
  requestHeaders.delete("x-api-key");

  // Process body
  const requestInit = init ?? {};
  let body = requestInit.body;

  if (!body && input instanceof Request) {
    try {
      body = await input.clone().text();
    } catch (error) {
      debugLog("handleAnthropicRequest.cloneBody", error);
      body = requestInit.body;
    }
  }

  let isStream = false;
  if (body && typeof body === "string") {
    try {
      const result = await normalizeRequestBody(
        JSON.parse(body),
        requestUrl.pathname === "/v1/messages",
      );
      body = JSON.stringify(result.body);
      isStream = result.isStream;
    } catch (error) {
      debugLog("handleAnthropicRequest.normalizeBody", error);
    }
  }

  applyStainlessHeaders(requestHeaders, isStream);

  // Beta query param
  if (
    (requestUrl.pathname === "/v1/messages" || requestUrl.pathname === "/v1/messages/count_tokens") &&
    !requestUrl.searchParams.has("beta")
  ) {
    requestUrl.searchParams.set("beta", "true");
  }

  // Build request
  let requestInput = requestUrl;
  let requestInitOut = { ...requestInit, headers: requestHeaders, body };

  if (input instanceof Request) {
    requestInput = new Request(requestUrl.toString(), { ...requestInit, headers: requestHeaders, body });
    requestInitOut = undefined;
  }

  const response = await baseFetch(requestInput, requestInitOut);
  return createTransformedResponse(response);
}

// ============================================================================
// Global Fetch Patch
// ============================================================================

function installAnthropicFetchPatch(getAuth, client) {
  if (FETCH_PATCH_STATE.installed) {
    if (getAuth) FETCH_PATCH_STATE.getAuth = getAuth;
    if (client) FETCH_PATCH_STATE.client = client;
    return;
  }
  if (!globalThis.fetch) return;

  FETCH_PATCH_STATE.installed = true;
  FETCH_PATCH_STATE.getAuth = getAuth ?? null;
  FETCH_PATCH_STATE.client = client ?? null;

  const baseFetch = getBaseFetch();

  const patchedFetch = async (input, init) => {
    const requestUrl = extractUrl(input);

    if (!requestUrl || requestUrl.hostname !== "api.anthropic.com") {
      return baseFetch(input, init);
    }

    let auth = null;
    try {
      auth = await ensureOAuthAccess(FETCH_PATCH_STATE.getAuth, FETCH_PATCH_STATE.client);
    } catch (error) {
      debugLog("installAnthropicFetchPatch.ensureOAuthAccess", error);
      auth = null;
    }

    const requestHeaders = mergeHeaders(input instanceof Request ? input : null, init);
    const authorization = requestHeaders.get("authorization") ?? "";
    const shouldPatch = auth?.type === "oauth" || authorization.includes("sk-ant-oat");

    if (!shouldPatch) {
      return baseFetch(input, init);
    }

    return handleAnthropicRequest(input, init, auth, baseFetch);
  };

  patchedFetch.__opencodeAnthropicPatched = true;
  globalThis.fetch = patchedFetch;
}

// ============================================================================
// OAuth Flow
// ============================================================================

async function authorize(mode) {
  const pkce = await generatePKCE();
  const url = new URL(
    `https://${mode === "console" ? "console.anthropic.com" : "claude.ai"}/oauth/authorize`,
    import.meta.url,
  );

  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", "https://console.anthropic.com/oauth/code/callback");
  url.searchParams.set("scope", "org:create_api_key user:profile user:inference");
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", pkce.verifier);

  return { url: url.toString(), verifier: pkce.verifier };
}

async function exchange(code, verifier) {
  // Safely parse code#state format - handle missing or multiple # characters
  const hashIndex = code.indexOf("#");
  const authCode = hashIndex >= 0 ? code.slice(0, hashIndex) : code;
  const state = hashIndex >= 0 ? code.slice(hashIndex + 1) : undefined;
  
  // Use baseFetch to avoid infinite loop if global fetch is already patched
  const baseFetch = getBaseFetch();
  const result = await baseFetch("https://console.anthropic.com/v1/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: authCode,
      state,
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      redirect_uri: "https://console.anthropic.com/oauth/code/callback",
      code_verifier: verifier,
    }),
  });

  if (!result.ok) return { type: "failed" };

  const json = await result.json();
  return {
    type: "success",
    refresh: json.refresh_token,
    access: json.access_token,
    expires: Date.now() + json.expires_in * 1000,
  };
}

// ============================================================================
// Plugin Export
// ============================================================================

/** @type {import('@opencode-ai/plugin').Plugin} */
export async function AnthropicAuthPlugin({ client }) {
  return {
    auth: {
      provider: "anthropic",

      async loader(getAuth, provider) {
        const auth = await getAuth();

        if (auth.type === "oauth") {
          installAnthropicFetchPatch(getAuth, client);

          // Zero out cost for max plan (mutates provider.models intentionally
          // as OpenCode expects this side effect for cost tracking)
          for (const model of Object.values(provider.models)) {
            model.cost = { input: 0, output: 0, cache: { read: 0, write: 0 } };
          }

          return {
            apiKey: "",
            async fetch(input, init) {
              const auth = await getAuth();
              if (auth.type !== "oauth") return fetch(input, init);

              const baseFetch = getBaseFetch();

              if (!auth.access || auth.expires < Date.now()) {
                const json = await refreshOAuthToken(auth, baseFetch);
                await client.auth.set({
                  path: { id: "anthropic" },
                  body: {
                    type: "oauth",
                    refresh: json.refresh_token,
                    access: json.access_token,
                    expires: Date.now() + json.expires_in * 1000,
                  },
                });
                auth.access = json.access_token;
              }

              return handleAnthropicRequest(input, init, auth, baseFetch);
            },
          };
        }

        return {};
      },

      methods: [
        {
          label: "Claude Pro/Max",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("max");
            return {
              url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: (code) => exchange(code, verifier),
            };
          },
        },
        {
          label: "Create an API Key",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("console");
            return {
              url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                if (credentials.type === "failed") return credentials;

                // Use baseFetch to avoid patched fetch intercepting this request
                const baseFetch = getBaseFetch();
                const result = await baseFetch(
                  "https://api.anthropic.com/api/oauth/claude_cli/create_api_key",
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      authorization: `Bearer ${credentials.access}`,
                    },
                  },
                ).then((r) => r.json());

                return { type: "success", key: result.raw_key };
              },
            };
          },
        },
        {
          provider: "anthropic",
          label: "Manually enter API Key",
          type: "api",
        },
      ],
    },

    async "chat.params"(input, output) {
      const providerId = input.provider?.id ?? "";
      if (providerId && !providerId.includes("anthropic")) return;

      const options = output.options ?? {};
      output.options = options;

      // Headers
      const headers = options.headers instanceof Headers
        ? options.headers
        : new Headers(options.headers ?? {});

      const betaHeaders = getBetaHeadersForPath("/v1/messages");
      headers.set("anthropic-beta", betaHeaders.join(","));
      applyStainlessHeaders(headers, !!options.stream);

      options.headers = headers;

      // Metadata
      const userId = await resolveMetadataUserId();
      if (userId) {
        options.metadata = { ...(options.metadata ?? {}), user_id: userId };
      }

      // Model
      if (options.model || input.model?.id) {
        options.model = normalizeModelId(options.model ?? input.model?.id);
      }

      // Tools & messages
      if (options.tools) options.tools = normalizeTools(options.tools);
      if (Array.isArray(options.messages)) options.messages = normalizeMessagesForClaude(options.messages);
      // OAuth API does not support tool_choice - remove to prevent API errors
      if (options.tool_choice) delete options.tool_choice;
    },
  };
}
