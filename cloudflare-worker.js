const DEFAULT_BACKEND_ORIGIN = "http://217.160.125.128:14254";
const API_PATH = "/api/oauth/callback";
const HEALTH_PATH = "/healthz";
const DEFAULT_ALLOWED_ORIGINS = [
  "https://relixaudios.github.io",
  "http://localhost:14254",
  "http://127.0.0.1:14254",
  "http://localhost:8080",
  "http://127.0.0.1:8080"
];

function getAllowedOrigins(env) {
  const raw = env.ALLOWED_ORIGINS || DEFAULT_ALLOWED_ORIGINS.join(",");
  return raw
    .split(",")
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean);
}

function isAllowedOrigin(origin, env) {
  if (!origin) {
    return true;
  }

  return getAllowedOrigins(env).includes(origin.replace(/\/$/, ""));
}

function corsHeaders(origin, env) {
  if (!origin || !isAllowedOrigin(origin, env)) {
    return {};
  }

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
    "Vary": "Origin"
  };
}

function jsonResponse(payload, status, origin, env) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...corsHeaders(origin, env)
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (url.pathname === HEALTH_PATH) {
      return jsonResponse({ status: "ok" }, 200, origin, env);
    }

    if (url.pathname !== API_PATH) {
      return jsonResponse({ ok: false, message: "Not found." }, 404, origin, env);
    }

    if (!isAllowedOrigin(origin, env)) {
      return jsonResponse({ ok: false, message: "Origin not allowed." }, 403, origin, env);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin, env)
      });
    }

    if (request.method !== "POST") {
      return jsonResponse({ ok: false, message: "Method not allowed." }, 405, origin, env);
    }

    const backendOrigin = (env.BACKEND_ORIGIN || DEFAULT_BACKEND_ORIGIN).replace(/\/$/, "");
    const backendUrl = `${backendOrigin}${API_PATH}`;
    const headers = new Headers({
      "Accept": "application/json",
      "Content-Type": request.headers.get("Content-Type") || "application/json"
    });

    let backendResponse;

    try {
      backendResponse = await fetch(backendUrl, {
        method: "POST",
        headers,
        body: request.body,
        redirect: "manual"
      });
    } catch (err) {
      return jsonResponse(
        { ok: false, message: "Verification backend is not reachable." },
        502,
        origin,
        env
      );
    }

    const contentType = backendResponse.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return jsonResponse(
        { ok: false, message: `Verification backend returned ${backendResponse.status}.` },
        502,
        origin,
        env
      );
    }

    const responseHeaders = new Headers(backendResponse.headers);
    responseHeaders.delete("Set-Cookie");
    responseHeaders.set("Cache-Control", "no-store");

    for (const [key, value] of Object.entries(corsHeaders(origin, env))) {
      responseHeaders.set(key, value);
    }

    return new Response(backendResponse.body, {
      status: backendResponse.status,
      statusText: backendResponse.statusText,
      headers: responseHeaders
    });
  }
};
