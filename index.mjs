import { generatePKCE } from "@openauthjs/openauth/pkce";

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const TOOL_PREFIX = "mcp_";
const TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";
const REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback";
const OAUTH_SCOPE = "org:create_api_key user:profile user:inference";
const ANTHROPIC_BETAS = "oauth-2025-04-20,interleaved-thinking-2025-05-14,claude-code-20250219";
const USER_AGENT = "claude-cli/2.1.2 (external, cli)";

const API_KEY_URL = "https://api.anthropic.com/api/oauth/claude_cli/create_api_key";
const AUTH_INSTRUCTIONS = "Paste the authorization code here: ";

/**
 * @param {"max" | "console"} mode
 */
async function authorize(mode) {
  const pkce = await generatePKCE();
  const host = mode === "console" ? "console.anthropic.com" : "claude.ai";
  const url = new URL(`https://${host}/oauth/authorize`);

  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", OAUTH_SCOPE);
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", pkce.verifier);

  return { url: url.toString(), verifier: pkce.verifier };
}

/**
 * @param {string} code
 * @param {string} verifier
 */
async function exchange(code, verifier) {
  const [authCode, state] = code.split("#");
  const result = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code: authCode,
      state,
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }),
  });

  if (!result.ok) {
    return { type: "failed" };
  }

  const json = await result.json();
  return {
    type: "success",
    refresh: json.refresh_token,
    access: json.access_token,
    expires: Date.now() + json.expires_in * 1000,
  };
}

/**
 * Merge headers from various sources into a Headers object
 * @param {Request | null} request
 * @param {RequestInit["headers"]} initHeaders
 * @returns {Headers}
 */
function mergeHeaders(request, initHeaders) {
  const headers = new Headers();

  if (request instanceof Request) {
    request.headers.forEach((v, k) => headers.set(k, v));
  }

  if (!initHeaders) return headers;

  if (initHeaders instanceof Headers) {
    initHeaders.forEach((v, k) => headers.set(k, v));
  } else if (Array.isArray(initHeaders)) {
    for (const [k, v] of initHeaders) {
      if (v !== undefined) headers.set(k, String(v));
    }
  } else {
    for (const [k, v] of Object.entries(initHeaders)) {
      if (v !== undefined) headers.set(k, String(v));
    }
  }

  return headers;
}

/**
 * Prefix tool name with TOOL_PREFIX
 * @param {string | undefined} name
 * @returns {string | undefined}
 */
function prefixToolName(name) {
  return name ? `${TOOL_PREFIX}${name}` : name;
}

/**
 * Add mcp_ prefix to tool names in request body
 * @param {string} body
 * @returns {string}
 */
function prefixToolsInBody(body) {
  try {
    const parsed = JSON.parse(body);

    if (Array.isArray(parsed.tools)) {
      parsed.tools = parsed.tools.map((t) => ({
        ...t,
        name: prefixToolName(t.name),
      }));
    }

    if (Array.isArray(parsed.messages)) {
      parsed.messages = parsed.messages.map((msg) => {
        if (Array.isArray(msg.content)) {
          msg.content = msg.content.map((block) => {
            if (block.type === "tool_use" && block.name) {
              return { ...block, name: prefixToolName(block.name) };
            }
            return block;
          });
        }
        return msg;
      });
    }

    return JSON.stringify(parsed);
  } catch {
    return body;
  }
}

/**
 * Strip mcp_ prefix from tool names in streaming response
 * @param {ReadableStream} responseBody
 * @returns {ReadableStream}
 */
function stripToolPrefixFromStream(responseBody) {
  const reader = responseBody.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  return new ReadableStream({
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        controller.close();
        return;
      }
      let text = decoder.decode(value, { stream: true });
      text = text.replace(/"name"\s*:\s*"mcp_([^"]+)"/g, '"name": "$1"');
      controller.enqueue(encoder.encode(text));
    },
  });
}

/**
 * Parse URL from various input types
 * @param {RequestInfo | URL} input
 * @returns {URL | null}
 */
function parseRequestUrl(input) {
  try {
    if (typeof input === "string" || input instanceof URL) {
      return new URL(input.toString());
    }
    if (input instanceof Request) {
      return new URL(input.url);
    }
  } catch {
    // Invalid URL
  }
  return null;
}

/**
 * Get token from auth object based on type
 * @param {{ type: string, access?: string, key?: string, apiKey?: string }} auth
 * @returns {string}
 */
function getToken(auth) {
  if (auth.type === "oauth") {
    return auth.access || "";
  }
  if (auth.type === "api") {
    return auth.key || auth.apiKey || "";
  }
  return "";
}

/**
 * @type {import('@opencode-ai/plugin').Plugin}
 */
export async function AnthropicAuthPlugin({ client }) {
  return {
    auth: {
      provider: "anthropic",
      async loader(getAuth, provider) {
        // Zero out cost for all modes
        for (const model of Object.values(provider.models)) {
          model.cost = {
            input: 0,
            output: 0,
            cache: { read: 0, write: 0 },
          };
        }

        return {
          apiKey: "",
          async fetch(input, init) {
            const auth = await getAuth();

            // Refresh OAuth token if expired
            if (auth.type === "oauth" && (!auth.access || auth.expires < Date.now())) {
              const response = await fetch(TOKEN_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  grant_type: "refresh_token",
                  refresh_token: auth.refresh,
                  client_id: CLIENT_ID,
                }),
              });
              if (!response.ok) {
                throw new Error(`Token refresh failed: ${response.status}`);
              }
              const json = await response.json();
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

            // Prepare headers with official client signatures
            const requestInit = init ?? {};
            const requestHeaders = mergeHeaders(
              input instanceof Request ? input : null,
              requestInit.headers,
            );

            const token = getToken(auth);
            if (token) requestHeaders.set("authorization", `Bearer ${token}`);
            requestHeaders.set("anthropic-beta", ANTHROPIC_BETAS);
            requestHeaders.set("user-agent", USER_AGENT);
            requestHeaders.delete("x-api-key");

            // Prefix tool names in request body
            let body = requestInit.body;
            if (body && typeof body === "string") {
              body = prefixToolsInBody(body);
            }

            // Add beta param to messages endpoint
            let requestInput = input;
            const requestUrl = parseRequestUrl(input);
            if (requestUrl?.pathname.endsWith("/messages") && !requestUrl.searchParams.has("beta")) {
              requestUrl.searchParams.set("beta", "true");
              requestInput = input instanceof Request
                ? new Request(requestUrl.toString(), input)
                : requestUrl;
            }

            // Execute request
            const response = await fetch(requestInput, {
              ...requestInit,
              body,
              headers: requestHeaders,
            });

            // Transform streaming response to strip tool name prefixes
            if (response.body) {
              return new Response(stripToolPrefixFromStream(response.body), {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
              });
            }

            return response;
          },
        };
      },
      methods: [
        {
          label: "Claude Pro/Max",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("max");
            return {
              url,
              instructions: AUTH_INSTRUCTIONS,
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
              instructions: AUTH_INSTRUCTIONS,
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                if (credentials.type === "failed") return credentials;

                const result = await fetch(API_KEY_URL, {
                  method: "POST",
                  headers: {
                    "Content-Type": "application/json",
                    authorization: `Bearer ${credentials.access}`,
                  },
                }).then((r) => r.json());

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
  };
}
