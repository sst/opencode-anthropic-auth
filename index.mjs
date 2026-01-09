import { generatePKCE } from "@openauthjs/openauth/pkce";

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
let cachedMetadataUserIdPromise;
const BASE_FETCH = globalThis.fetch?.bind(globalThis);
const FETCH_PATCH_STATE = {
  installed: false,
  getAuth: null,
  client: null,
};
const MODEL_ID_OVERRIDES = new Map([
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
const TOOL_NAME_CACHE = new Map();
const TOOL_PREFIX_REGEX = /^(?:oc_|mcp_)/i;

function normalizeToolNameForClaude(name) {
  if (!name) return name;
  const stripped = stripToolPrefix(name);
  const mapped = CLAUDE_CODE_TOOL_NAMES.get(stripped.toLowerCase());
  const pascal = mapped ?? toPascalCase(stripped);
  if (pascal && pascal !== stripped) {
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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripToolPrefix(value) {
  if (!value) return value;
  return value.replace(TOOL_PREFIX_REGEX, "");
}

function normalizeMessagesForClaude(messages) {
  if (!Array.isArray(messages)) return messages;
  return messages.map((message) => {
    if (!message || !Array.isArray(message.content)) return message;
    const content = message.content.map((block) => {
      if (block && block.type === "tool_use" && block.name) {
        return { ...block, name: normalizeToolNameForClaude(block.name) };
      }
      return block;
    });
    return { ...message, content };
  });
}

function replaceToolNamesInText(text) {
  let output = text.replace(
    /"name"\s*:\s*"(?:oc_|mcp_)([^"]+)"/g,
    '"name": "$1"',
  );
  output = output.replace(
    /"name"\s*:\s*"(Bash|Read|Edit|Write|Task|Glob|Grep|WebFetch|WebSearch|TodoWrite)"/g,
    (match, name) => `"name": "${normalizeToolNameForOpenCode(name)}"`,
  );
  for (const [pascal, original] of TOOL_NAME_CACHE.entries()) {
    if (!pascal || pascal === original) continue;
    const pattern = new RegExp(
      `"name"\\s*:\\s*"${escapeRegExp(pascal)}"`,
      "g",
    );
    output = output.replace(pattern, `"name": "${original}"`);
  }
  for (const [full, base] of MODEL_ID_REVERSE_OVERRIDES.entries()) {
    const pattern = new RegExp(
      `"model"\\s*:\\s*"${escapeRegExp(full)}"`,
      "g",
    );
    output = output.replace(pattern, `"model": "${base}"`);
  }
  return output;
}

function normalizeModelId(id) {
  if (!id) return id;
  return MODEL_ID_OVERRIDES.get(id) ?? id;
}

function getBaseFetch() {
  return BASE_FETCH ?? globalThis.fetch;
}

async function ensureOAuthAccess(getAuth, client) {
  if (!getAuth) return null;
  const auth = await getAuth();
  if (!auth || auth.type !== "oauth") return auth ?? null;
  if (auth.access && auth.expires > Date.now()) return auth;

  const baseFetch = getBaseFetch();
  const response = await baseFetch(
    "https://console.anthropic.com/v1/oauth/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token: auth.refresh,
        client_id: CLIENT_ID,
      }),
    },
  );
  if (!response.ok) {
    throw new Error(`Token refresh failed: ${response.status}`);
  }
  const json = await response.json();
  if (client?.auth?.set) {
    await client.auth.set({
      path: {
        id: "anthropic",
      },
      body: {
        type: "oauth",
        refresh: json.refresh_token,
        access: json.access_token,
        expires: Date.now() + json.expires_in * 1000,
      },
    });
  }
  auth.refresh = json.refresh_token;
  auth.access = json.access_token;
  auth.expires = Date.now() + json.expires_in * 1000;
  return auth;
}

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
    let requestUrl = null;
    try {
      if (typeof input === "string" || input instanceof URL) {
        requestUrl = new URL(input.toString());
      } else if (input instanceof Request) {
        requestUrl = new URL(input.url);
      }
    } catch {
      requestUrl = null;
    }

    if (!requestUrl || requestUrl.hostname !== "api.anthropic.com") {
      return baseFetch(input, init);
    }

    const requestInit = init ?? {};
    const requestHeaders = new Headers();
    if (input instanceof Request) {
      input.headers.forEach((value, key) => {
        requestHeaders.set(key, value);
      });
    }
    if (requestInit.headers) {
      if (requestInit.headers instanceof Headers) {
        requestInit.headers.forEach((value, key) => {
          requestHeaders.set(key, value);
        });
      } else if (Array.isArray(requestInit.headers)) {
        for (const [key, value] of requestInit.headers) {
          if (typeof value !== "undefined") {
            requestHeaders.set(key, String(value));
          }
        }
      } else {
        for (const [key, value] of Object.entries(requestInit.headers)) {
          if (typeof value !== "undefined") {
            requestHeaders.set(key, String(value));
          }
        }
      }
    }

    let auth = null;
    try {
      auth = await ensureOAuthAccess(
        FETCH_PATCH_STATE.getAuth,
        FETCH_PATCH_STATE.client,
      );
    } catch {
      auth = null;
    }

    const authorization = requestHeaders.get("authorization") ?? "";
    const shouldPatch =
      auth?.type === "oauth" || authorization.includes("sk-ant-oat");
    if (!shouldPatch) {
      return baseFetch(input, init);
    }

    const incomingBeta = requestHeaders.get("anthropic-beta") || "";
    const incomingBetasList = incomingBeta
      .split(",")
      .map((b) => b.trim())
      .filter(Boolean);
    let mergedBetasList = [...incomingBetasList];

    if (requestUrl.pathname === "/v1/messages") {
      mergedBetasList = [
        "oauth-2025-04-20",
        "interleaved-thinking-2025-05-14",
      ];
    } else if (requestUrl.pathname === "/v1/messages/count_tokens") {
      mergedBetasList = [
        "claude-code-20250219",
        "oauth-2025-04-20",
        "interleaved-thinking-2025-05-14",
        "token-counting-2024-11-01",
      ];
    } else if (
      requestUrl.pathname.startsWith("/api/") &&
      requestUrl.pathname !== "/api/hello"
    ) {
      mergedBetasList = ["oauth-2025-04-20"];
    }

    if (auth?.type === "oauth" && auth.access) {
      requestHeaders.set("authorization", `Bearer ${auth.access}`);
    }
    if (mergedBetasList.length > 0) {
      requestHeaders.set("anthropic-beta", mergedBetasList.join(","));
    } else {
      requestHeaders.delete("anthropic-beta");
    }
    requestHeaders.set("user-agent", "claude-cli/2.1.2 (external, cli)");
    requestHeaders.set("x-app", "cli");
    requestHeaders.set("anthropic-dangerous-direct-browser-access", "true");

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

    requestHeaders.set(
      "x-stainless-arch",
      env.OPENCODE_STAINLESS_ARCH ?? globalThis.process?.arch ?? "x64",
    );
    requestHeaders.set("x-stainless-lang", env.OPENCODE_STAINLESS_LANG ?? "js");
    requestHeaders.set("x-stainless-os", os);
    requestHeaders.set(
      "x-stainless-package-version",
      env.OPENCODE_STAINLESS_PACKAGE_VERSION ?? "0.70.0",
    );
    requestHeaders.set(
      "x-stainless-runtime",
      env.OPENCODE_STAINLESS_RUNTIME ?? "node",
    );
    requestHeaders.set(
      "x-stainless-runtime-version",
      env.OPENCODE_STAINLESS_RUNTIME_VERSION ??
        globalThis.process?.version ??
        "v24.3.0",
    );
    requestHeaders.set(
      "x-stainless-retry-count",
      env.OPENCODE_STAINLESS_RETRY_COUNT ?? "0",
    );
    requestHeaders.set(
      "x-stainless-timeout",
      env.OPENCODE_STAINLESS_TIMEOUT ?? "600",
    );
    requestHeaders.delete("x-api-key");

    let body = requestInit.body;
    if (!body && input instanceof Request) {
      try {
        body = await input.clone().text();
      } catch {
        body = requestInit.body;
      }
    }

    let shouldSetHelperMethod = false;
    if (body && typeof body === "string") {
      try {
        const parsed = JSON.parse(body);
        if (parsed.model) {
          parsed.model = normalizeModelId(parsed.model);
        }
        if (parsed.tools && Array.isArray(parsed.tools)) {
          parsed.tools = parsed.tools.map((tool) => ({
            ...tool,
            name: tool.name ? normalizeToolNameForClaude(tool.name) : tool.name,
          }));
        } else if (parsed.tools && typeof parsed.tools === "object") {
          const mappedTools = {};
          for (const [key, value] of Object.entries(parsed.tools)) {
            const mappedKey = normalizeToolNameForClaude(key);
            const mappedValue =
              value && typeof value === "object"
                ? {
                    ...value,
                    name: value.name
                      ? normalizeToolNameForClaude(value.name)
                      : mappedKey,
                  }
                : value;
            mappedTools[mappedKey] = mappedValue;
          }
          parsed.tools = mappedTools;
        }
        if (parsed.messages && Array.isArray(parsed.messages)) {
          parsed.messages = normalizeMessagesForClaude(parsed.messages);
        }
        if (parsed.tool_choice) {
          delete parsed.tool_choice;
        }

        if (requestUrl.pathname === "/v1/messages") {
          const metadataUserId = await resolveMetadataUserId();
          if (metadataUserId) {
            if (!parsed.metadata || typeof parsed.metadata !== "object") {
              parsed.metadata = {};
            }
            if (!parsed.metadata.user_id) {
              parsed.metadata.user_id = metadataUserId;
            }
          }
        }

        if (parsed.stream) shouldSetHelperMethod = true;
        body = JSON.stringify(parsed);
      } catch {
        // ignore parse errors
      }
    }

    if (shouldSetHelperMethod) {
      requestHeaders.set("x-stainless-helper-method", "stream");
    }

    if (
      (requestUrl.pathname === "/v1/messages" ||
        requestUrl.pathname === "/v1/messages/count_tokens") &&
      !requestUrl.searchParams.has("beta")
    ) {
      requestUrl.searchParams.set("beta", "true");
    }

    let requestInput = requestUrl;
    let requestInitOut = {
      ...requestInit,
      headers: requestHeaders,
      body,
    };

    if (input instanceof Request) {
      requestInput = new Request(requestUrl.toString(), {
        ...requestInit,
        headers: requestHeaders,
        body,
      });
      requestInitOut = undefined;
    }

    const response = await baseFetch(requestInput, requestInitOut);
    if (response.body) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();

      const stream = new ReadableStream({
        async pull(controller) {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            return;
          }

          let text = decoder.decode(value, { stream: true });
          text = replaceToolNamesInText(text);
          controller.enqueue(encoder.encode(text));
        },
      });

      return new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    }

    return response;
  };

  patchedFetch.__opencodeAnthropicPatched = true;
  globalThis.fetch = patchedFetch;
}

async function resolveMetadataUserId() {
  const env = globalThis.process?.env ?? {};
  const direct =
    env.OPENCODE_ANTHROPIC_USER_ID ??
    env.CLAUDE_CODE_USER_ID ??
    env.ANTHROPIC_USER_ID;
  if (direct) return direct;
  if (cachedMetadataUserIdPromise) return cachedMetadataUserIdPromise;

  cachedMetadataUserIdPromise = (async () => {
    const home = env.HOME ?? env.USERPROFILE;
    if (!home) return undefined;
    const configPath = env.OPENCODE_CLAUDE_CONFIG ?? `${home}/.claude.json`;
    try {
      const { readFile } = await import("node:fs/promises");
      const raw = await readFile(configPath, "utf8");
      const data = JSON.parse(raw);
      const userId = data?.userID;
      const accountUuid = data?.oauthAccount?.accountUuid;
      let sessionId = undefined;
      const cwd = globalThis.process?.cwd?.();
      if (cwd && data?.projects?.[cwd]?.lastSessionId) {
        sessionId = data.projects[cwd].lastSessionId;
      } else if (data?.projects && typeof data.projects === "object") {
        for (const value of Object.values(data.projects)) {
          if (value && typeof value === "object" && value.lastSessionId) {
            sessionId = value.lastSessionId;
            break;
          }
        }
      }

      if (userId && accountUuid && sessionId) {
        return `user_${userId}_account_${accountUuid}_session_${sessionId}`;
      }
    } catch {
      return undefined;
    }
    return undefined;
  })();

  return cachedMetadataUserIdPromise;
}

/**
 * @param {"max" | "console"} mode
 */
async function authorize(mode) {
  const pkce = await generatePKCE();

  const url = new URL(
    `https://${mode === "console" ? "console.anthropic.com" : "claude.ai"}/oauth/authorize`,
    import.meta.url,
  );
  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set(
    "redirect_uri",
    "https://console.anthropic.com/oauth/code/callback",
  );
  url.searchParams.set(
    "scope",
    "org:create_api_key user:profile user:inference",
  );
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", pkce.verifier);
  return {
    url: url.toString(),
    verifier: pkce.verifier,
  };
}

/**
 * @param {string} code
 * @param {string} verifier
 */
async function exchange(code, verifier) {
  const splits = code.split("#");
  const result = await fetch("https://console.anthropic.com/v1/oauth/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      code: splits[0],
      state: splits[1],
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      redirect_uri: "https://console.anthropic.com/oauth/code/callback",
      code_verifier: verifier,
    }),
  });
  if (!result.ok)
    return {
      type: "failed",
    };
  const json = await result.json();
  return {
    type: "success",
    refresh: json.refresh_token,
    access: json.access_token,
    expires: Date.now() + json.expires_in * 1000,
  };
}

/**
 * @type {import('@opencode-ai/plugin').Plugin}
 */
export async function AnthropicAuthPlugin({ client }) {
  return {
    auth: {
      provider: "anthropic",
      async loader(getAuth, provider) {
        const auth = await getAuth();
        if (auth.type === "oauth") {
          installAnthropicFetchPatch(getAuth, client);
          // zero out cost for max plan
          for (const model of Object.values(provider.models)) {
            model.cost = {
              input: 0,
              output: 0,
              cache: {
                read: 0,
                write: 0,
              },
            };
          }
          return {
            apiKey: "",
            /**
             * @param {any} input
             * @param {any} init
             */
            async fetch(input, init) {
              const auth = await getAuth();
              if (auth.type !== "oauth") return fetch(input, init);
              const baseFetch = getBaseFetch();
              if (!auth.access || auth.expires < Date.now()) {
                const response = await baseFetch(
                  "https://console.anthropic.com/v1/oauth/token",
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                      grant_type: "refresh_token",
                      refresh_token: auth.refresh,
                      client_id: CLIENT_ID,
                    }),
                  },
                );
                if (!response.ok) {
                  throw new Error(`Token refresh failed: ${response.status}`);
                }
                const json = await response.json();
                await client.auth.set({
                  path: {
                    id: "anthropic",
                  },
                  body: {
                    type: "oauth",
                    refresh: json.refresh_token,
                    access: json.access_token,
                    expires: Date.now() + json.expires_in * 1000,
                  },
                });
                auth.access = json.access_token;
              }
              const requestInit = init ?? {};

              const requestHeaders = new Headers();
              if (input instanceof Request) {
                input.headers.forEach((value, key) => {
                  requestHeaders.set(key, value);
                });
              }
              if (requestInit.headers) {
                if (requestInit.headers instanceof Headers) {
                  requestInit.headers.forEach((value, key) => {
                    requestHeaders.set(key, value);
                  });
                } else if (Array.isArray(requestInit.headers)) {
                  for (const [key, value] of requestInit.headers) {
                    if (typeof value !== "undefined") {
                      requestHeaders.set(key, String(value));
                    }
                  }
                } else {
                  for (const [key, value] of Object.entries(requestInit.headers)) {
                    if (typeof value !== "undefined") {
                      requestHeaders.set(key, String(value));
                    }
                  }
                }
              }

              let requestInput = input;
              let requestUrl = null;
              try {
                if (typeof input === "string" || input instanceof URL) {
                  requestUrl = new URL(input.toString());
                } else if (input instanceof Request) {
                  requestUrl = new URL(input.url);
                }
              } catch {
                requestUrl = null;
              }

              const incomingBeta = requestHeaders.get("anthropic-beta") || "";
              const incomingBetasList = incomingBeta
                .split(",")
                .map((b) => b.trim())
                .filter(Boolean);

              let mergedBetasList = [...incomingBetasList];

              if (requestUrl && requestUrl.hostname === "api.anthropic.com") {
                if (requestUrl.pathname === "/v1/messages") {
                  mergedBetasList = [
                    "oauth-2025-04-20",
                    "interleaved-thinking-2025-05-14",
                  ];
                } else if (requestUrl.pathname === "/v1/messages/count_tokens") {
                  mergedBetasList = [
                    "claude-code-20250219",
                    "oauth-2025-04-20",
                    "interleaved-thinking-2025-05-14",
                    "token-counting-2024-11-01",
                  ];
                } else if (
                  requestUrl.pathname.startsWith("/api/") &&
                  requestUrl.pathname !== "/api/hello"
                ) {
                  mergedBetasList = ["oauth-2025-04-20"];
                }
              }

              requestHeaders.set("authorization", `Bearer ${auth.access}`);
              if (mergedBetasList.length > 0) {
                requestHeaders.set("anthropic-beta", mergedBetasList.join(","));
              } else {
                requestHeaders.delete("anthropic-beta");
              }
              requestHeaders.set(
                "user-agent",
                "claude-cli/2.1.2 (external, cli)",
              );
              if (requestUrl && requestUrl.hostname === "api.anthropic.com") {
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

                if (!requestHeaders.has("x-app")) {
                  requestHeaders.set("x-app", "cli");
                }
                if (!requestHeaders.has("anthropic-dangerous-direct-browser-access")) {
                  requestHeaders.set(
                    "anthropic-dangerous-direct-browser-access",
                    "true",
                  );
                }
                if (!requestHeaders.has("x-stainless-arch")) {
                  requestHeaders.set(
                    "x-stainless-arch",
                    env.OPENCODE_STAINLESS_ARCH ??
                      globalThis.process?.arch ??
                      "x64",
                  );
                }
                if (!requestHeaders.has("x-stainless-lang")) {
                  requestHeaders.set(
                    "x-stainless-lang",
                    env.OPENCODE_STAINLESS_LANG ?? "js",
                  );
                }
                if (!requestHeaders.has("x-stainless-os")) {
                  requestHeaders.set("x-stainless-os", os);
                }
                if (!requestHeaders.has("x-stainless-package-version")) {
                  requestHeaders.set(
                    "x-stainless-package-version",
                    env.OPENCODE_STAINLESS_PACKAGE_VERSION ?? "0.70.0",
                  );
                }
                if (!requestHeaders.has("x-stainless-runtime")) {
                  requestHeaders.set(
                    "x-stainless-runtime",
                    env.OPENCODE_STAINLESS_RUNTIME ?? "node",
                  );
                }
                if (!requestHeaders.has("x-stainless-runtime-version")) {
                  requestHeaders.set(
                    "x-stainless-runtime-version",
                    env.OPENCODE_STAINLESS_RUNTIME_VERSION ??
                      globalThis.process?.version ??
                      "v24.3.0",
                  );
                }
                if (!requestHeaders.has("x-stainless-retry-count")) {
                  requestHeaders.set(
                    "x-stainless-retry-count",
                    env.OPENCODE_STAINLESS_RETRY_COUNT ?? "0",
                  );
                }
                if (!requestHeaders.has("x-stainless-timeout")) {
                  requestHeaders.set(
                    "x-stainless-timeout",
                    env.OPENCODE_STAINLESS_TIMEOUT ?? "600",
                  );
                }
              }
              requestHeaders.delete("x-api-key");

              let body = requestInit.body;
              if (body && typeof body === "string") {
                try {
                  const parsed = JSON.parse(body);
                  const isMessagesRequest =
                    requestUrl &&
                    requestUrl.hostname === "api.anthropic.com" &&
                    requestUrl.pathname === "/v1/messages";
                  let shouldSetHelperMethod = false;
                  if (parsed.tools && Array.isArray(parsed.tools)) {
                    parsed.tools = parsed.tools.map((tool) => ({
                      ...tool,
                      name: tool.name
                        ? normalizeToolNameForClaude(tool.name)
                        : tool.name,
                    }));
                  } else if (parsed.tools && typeof parsed.tools === "object") {
                    const mappedTools = {};
                    for (const [key, value] of Object.entries(parsed.tools)) {
                      const mappedKey = normalizeToolNameForClaude(key);
                      const mappedValue =
                        value && typeof value === "object"
                          ? {
                              ...value,
                              name: value.name
                                ? normalizeToolNameForClaude(value.name)
                                : mappedKey,
                            }
                          : value;
                      mappedTools[mappedKey] = mappedValue;
                    }
                    parsed.tools = mappedTools;
                  }
                  if (parsed.messages && Array.isArray(parsed.messages)) {
                    parsed.messages = normalizeMessagesForClaude(parsed.messages);
                  }
                  if (parsed.tool_choice) {
                    delete parsed.tool_choice;
                  }
                  if (isMessagesRequest) {
                    const metadataUserId = await resolveMetadataUserId();
                    if (!parsed.metadata || typeof parsed.metadata !== "object") {
                      parsed.metadata = {};
                    }
                    if (metadataUserId && !parsed.metadata.user_id) {
                      parsed.metadata.user_id = metadataUserId;
                    }
                  }
                  if (parsed.model) {
                    parsed.model = normalizeModelId(parsed.model);
                  }
                  if (parsed.stream) shouldSetHelperMethod = true;

                  body = JSON.stringify(parsed);
                  if (
                    shouldSetHelperMethod &&
                    !requestHeaders.has("x-stainless-helper-method")
                  ) {
                    requestHeaders.set("x-stainless-helper-method", "stream");
                  }
                } catch (e) {
                  // ignore parse errors
                }
              }

              if (
                requestUrl &&
                (requestUrl.pathname === "/v1/messages" ||
                  requestUrl.pathname === "/v1/messages/count_tokens") &&
                !requestUrl.searchParams.has("beta")
              ) {
                requestUrl.searchParams.set("beta", "true");
                requestInput =
                  input instanceof Request
                    ? new Request(requestUrl.toString(), input)
                    : requestUrl;
              }

              const response = await baseFetch(requestInput, {
                ...requestInit,
                body,
                headers: requestHeaders,
              });

              // Transform streaming response to rename tools back
              if (response.body) {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                const encoder = new TextEncoder();

                const stream = new ReadableStream({
                  async pull(controller) {
                    const { done, value } = await reader.read();
                    if (done) {
                      controller.close();
                      return;
                    }

                    let text = decoder.decode(value, { stream: true });
                    text = replaceToolNamesInText(text);
                    controller.enqueue(encoder.encode(text));
                  },
                });

                return new Response(stream, {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                });
              }

              return response;
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
              url: url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                return credentials;
              },
            };
          },
        },
        {
          label: "Create an API Key",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("console");
            return {
              url: url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                if (credentials.type === "failed") return credentials;
                const result = await fetch(
                  `https://api.anthropic.com/api/oauth/claude_cli/create_api_key`,
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

      const existingHeaders = options.headers;
      const headers =
        existingHeaders instanceof Headers
          ? new Headers(existingHeaders)
          : { ...(existingHeaders ?? {}) };

      const getHeader = (name) => {
        if (headers instanceof Headers) return headers.get(name);
        const lower = name.toLowerCase();
        for (const [key, value] of Object.entries(headers)) {
          if (key.toLowerCase() === lower) return value;
        }
        return undefined;
      };

      const setHeader = (name, value) => {
        if (!value) return;
        if (headers instanceof Headers) {
          headers.set(name, value);
          return;
        }
        headers[name] = value;
      };

      const incomingBeta = getHeader("anthropic-beta") || "";
      const incomingBetasList = incomingBeta
        .split(",")
        .map((b) => b.trim())
        .filter(Boolean);
      const mergedBetasList = incomingBetasList.filter((beta) =>
        [
          "oauth-2025-04-20",
          "interleaved-thinking-2025-05-14",
          "claude-code-20250219",
        ].includes(beta),
      );
      if (!mergedBetasList.includes("oauth-2025-04-20")) {
        mergedBetasList.push("oauth-2025-04-20");
      }
      if (!mergedBetasList.includes("interleaved-thinking-2025-05-14")) {
        mergedBetasList.push("interleaved-thinking-2025-05-14");
      }
      if (mergedBetasList.length > 0) {
        setHeader("anthropic-beta", mergedBetasList.join(","));
      }

      setHeader("user-agent", "claude-cli/2.1.2 (external, cli)");
      setHeader("x-app", "cli");
      setHeader("anthropic-dangerous-direct-browser-access", "true");
      setHeader(
        "x-stainless-arch",
        env.OPENCODE_STAINLESS_ARCH ?? globalThis.process?.arch ?? "x64",
      );
      setHeader("x-stainless-lang", env.OPENCODE_STAINLESS_LANG ?? "js");
      setHeader("x-stainless-os", os);
      setHeader(
        "x-stainless-package-version",
        env.OPENCODE_STAINLESS_PACKAGE_VERSION ?? "0.70.0",
      );
      setHeader(
        "x-stainless-runtime",
        env.OPENCODE_STAINLESS_RUNTIME ?? "node",
      );
      setHeader(
        "x-stainless-runtime-version",
        env.OPENCODE_STAINLESS_RUNTIME_VERSION ??
          globalThis.process?.version ??
          "v24.3.0",
      );
      setHeader(
        "x-stainless-retry-count",
        env.OPENCODE_STAINLESS_RETRY_COUNT ?? "0",
      );
      setHeader(
        "x-stainless-timeout",
        env.OPENCODE_STAINLESS_TIMEOUT ?? "600",
      );
      if (options.stream && !getHeader("x-stainless-helper-method")) {
        setHeader("x-stainless-helper-method", "stream");
      }

      options.headers = headers;

      const metadataUserId = await resolveMetadataUserId();
      if (metadataUserId) {
        const metadata =
          options.metadata && typeof options.metadata === "object"
            ? { ...options.metadata }
            : {};
        if (!metadata.user_id) metadata.user_id = metadataUserId;
        options.metadata = metadata;
      }

      const selectedModel = options.model ?? input.model?.id;
      if (selectedModel) {
        options.model = normalizeModelId(selectedModel);
      }

      if (Array.isArray(options.tools)) {
        options.tools = options.tools.map((tool) => ({
          ...tool,
          name: tool?.name ? normalizeToolNameForClaude(tool.name) : tool?.name,
        }));
      } else if (options.tools && typeof options.tools === "object") {
        const mappedTools = {};
        for (const [key, value] of Object.entries(options.tools)) {
          const mappedKey = normalizeToolNameForClaude(key);
          const mappedValue =
            value && typeof value === "object"
              ? {
                  ...value,
                  name: value.name
                    ? normalizeToolNameForClaude(value.name)
                    : mappedKey,
                }
              : value;
          mappedTools[mappedKey] = mappedValue;
        }
        options.tools = mappedTools;
      }
      if (Array.isArray(options.messages)) {
        options.messages = normalizeMessagesForClaude(options.messages);
      }
      if (options.tool_choice) {
        delete options.tool_choice;
      }
    },
  };
}
