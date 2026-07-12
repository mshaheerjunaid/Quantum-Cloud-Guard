// Same-origin API client. The KMS serves this UI, so cookies flow automatically.

async function req(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!res.ok) {
    const msg = (data && (data.detail || data.error)) || `HTTP ${res.status}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}

export const api = {
  needsSetup: () => req("GET", "/api/needs-setup"),
  setup: (username, password) => req("POST", "/api/setup", { username, password }),
  register: (username, password) => req("POST", "/api/register", { username, password }),
  forgotPassword: (username) => req("POST", "/api/password/forgot", { username }),
  changePassword: (currentPassword, newPassword) =>
    req("POST", "/api/password/change",
        { current_password: currentPassword || null, new_password: newPassword }),
  login: (username, password, otp) => req("POST", "/api/login", { username, password, otp: otp || null }),
  logout: () => req("POST", "/api/logout"),
  me: () => req("GET", "/api/me"),

  // MFA (TOTP)
  mfaEnroll: () => req("POST", "/api/mfa/enroll"),
  mfaActivate: (otp) => req("POST", "/api/mfa/activate", { otp }),

  // keys
  listKeys: () => req("GET", "/api/keys"),
  generateKey: (name) => req("POST", "/api/keys", { name }),
  rotateKey: (name) => req("POST", `/api/keys/${encodeURIComponent(name)}/rotate`),
  deleteKey: (name) => req("DELETE", `/api/keys/${encodeURIComponent(name)}`),
  publicKey: (name) => req("GET", `/api/keys/${encodeURIComponent(name)}/public`),
  signingKey: () => req("GET", "/api/signing-key"),

  // server-side crypto (small secrets)
  encrypt: (key, plaintext, aad) =>
    req("POST", "/api/encrypt", { key, plaintext, aad: aad || null }),
  decrypt: (envelope, aad) =>
    req("POST", "/api/decrypt", { envelope, aad: aad || null }),

  // api keys (machine / laptop credentials)
  listApiKeys: () => req("GET", "/api/apikeys"),
  createApiKey: (label, owner) => req("POST", "/api/apikeys", { label, owner: owner || null }),
  deleteApiKey: (label) => req("DELETE", `/api/apikeys/${encodeURIComponent(label)}`),

  // employee management
  listUsers: () => req("GET", "/api/users"),
  createUser: (username, password, role, isAdmin) =>
    req("POST", "/api/users", { username, password, role, is_admin: !!isAdmin }),
  changeRole: (username, role) =>
    req("PATCH", `/api/users/${encodeURIComponent(username)}/role`, { role }),
  deleteUser: (username) => req("DELETE", `/api/users/${encodeURIComponent(username)}`),
  approveUser: (username) => req("POST", `/api/users/${encodeURIComponent(username)}/approve`),
  resetPassword: (username) =>
    req("POST", `/api/users/${encodeURIComponent(username)}/reset-password`),
  listRoles: () => req("GET", "/api/roles"),

  // Admin monitoring dashboard (proxied to Sentinel Gate server-side).
  monitor: (recent) => req("GET", `/api/admin/monitor?recent=${recent || 100}`),
  // Filtered connection history from the on-disk store (date ranges, filters).
  monitorHistory: (qs) => req("GET", `/api/admin/monitor/history?${qs || "range=24h"}`),
  // Distinct countries for the filter dropdown.
  monitorCountries: () => req("GET", "/api/admin/monitor/countries"),

  // per-key access grants
  listGrants: (key) => req("GET", `/api/keys/${encodeURIComponent(key)}/grants`),
  grantKey: (key, username) => req("POST", `/api/keys/${encodeURIComponent(key)}/grant`, { username }),
  revokeKey: (key, username) =>
    req("DELETE", `/api/keys/${encodeURIComponent(key)}/grant/${encodeURIComponent(username)}`),

  // oversight
  listLeases: () => req("GET", "/api/leases?only_open=true"),
  audit: (limit) => req("GET", `/api/audit?limit=${limit || 50}`),
  auditVerify: () => req("GET", "/api/audit/verify"),
};
