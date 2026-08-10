const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const app = express();

const PORT = Number(process.env.PORT || 80);
const APP_NAME = process.env.APP_NAME || 'chempboard';
const APP_LABEL = process.env.APP_LABEL || 'ChempBoard';
const AUTH_SERVICE_URL = cleanBaseUrl(process.env.AUTH_SERVICE_URL || 'http://auth-service:3100');
const AUTH_SERVICE_PUBLIC_URL = cleanBaseUrl(process.env.AUTH_SERVICE_PUBLIC_URL || AUTH_SERVICE_URL);
const AUTH_DISABLED = parseBool(process.env.AUTH_DISABLED);
const JWT_SECRET = process.env.JWT_SECRET || '';
const SESSION_MAX_AGE_MS = Number(process.env.SESSION_MAX_AGE_DAYS || 30) * 24 * 60 * 60 * 1000;
const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || `${APP_NAME}_auth_token`;
const LEGACY_AUTH_COOKIE_NAME = 'auth_token';
const DATA_DIR = process.env.DATA_DIR || (process.env.NODE_ENV === 'production' ? '/data' : path.join(__dirname, 'data'));
const SITES_FILE = process.env.SITES_FILE || path.join(DATA_DIR, 'sites.json');
const API_TIMEOUT_MS = clampInt(process.env.API_TIMEOUT_MS, 6500, 1000, 60000);
const SITE_TIMEOUT_MS = clampInt(process.env.SITE_TIMEOUT_MS, 4500, 1000, 60000);
const SITE_CHECK_INSECURE = parseBool(process.env.SITE_CHECK_INSECURE);
const NAS_PROC_PATH = process.env.NAS_PROC_PATH || (fs.existsSync('/host/proc/uptime') ? '/host/proc' : '/proc');
const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';
const HA_LOGBOOK_HOURS = clampInt(process.env.HA_LOGBOOK_HOURS, 24, 1, 168);
const HA_LOW_BATTERY = clampInt(process.env.HA_LOW_BATTERY, 20, 1, 90);
const UNIFI_SITE = process.env.UNIFI_SITE || 'default';
const UNIFI_INSECURE = parseBool(process.env.UNIFI_INSECURE, true);
const LOG_LINE_LIMIT = clampInt(process.env.LOG_LINE_LIMIT, 120, 20, 500);

if (!AUTH_DISABLED && !JWT_SECRET) {
  console.warn('[auth] WARNING: JWT_SECRET is not set. Shared auth will reject all tokens.');
}

fs.mkdirSync(DATA_DIR, { recursive: true });

app.disable('x-powered-by');
app.use(express.json({ limit: '768kb' }));
app.use(cookieParser());

function parseBool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function clampInt(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(number)));
}

function cleanBaseUrl(value) {
  return String(value || '').replace(/\/+$/, '');
}

function resolveUrl(baseUrl, pathname) {
  return new URL(pathname, `${cleanBaseUrl(baseUrl)}/`).toString();
}

function parseList(value) {
  return String(value || '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
}

function parseUniFiPrefixes() {
  if (process.env.UNIFI_API_PREFIXES === undefined) return ['/proxy/network', ''];
  return String(process.env.UNIFI_API_PREFIXES)
    .split(',')
    .map(item => item.trim())
    .map(item => item === '/' ? '' : item);
}

function asText(value, maxLength = 240) {
  return String(value ?? '').trim().slice(0, maxLength);
}

function safeId(value) {
  const id = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 56);
  return id || crypto.randomUUID();
}

function publicForwardHeaders(req) {
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return { 'X-Forwarded-Proto': proto, 'X-Forwarded-Host': host };
}

function getPublicBaseUrl(req) {
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return host ? `${proto}://${host}` : `http://localhost:${PORT}`;
}

function isSecureRequest(req) {
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || '').split(',')[0].trim();
  return proto === 'https' || parseBool(process.env.SECURE_COOKIES);
}

function authCookieOptions(req) {
  return { httpOnly: true, secure: isSecureRequest(req), sameSite: 'lax', path: '/' };
}

function getToken(req) {
  const bearer = req.headers.authorization?.startsWith('Bearer ')
    ? req.headers.authorization.slice('Bearer '.length)
    : '';
  return req.cookies?.[AUTH_COOKIE_NAME] || req.cookies?.[LEGACY_AUTH_COOKIE_NAME] || bearer || '';
}

function setAuthCookie(res, req, token) {
  res.cookie(AUTH_COOKIE_NAME, token, { ...authCookieOptions(req), maxAge: SESSION_MAX_AGE_MS });
  res.clearCookie(LEGACY_AUTH_COOKIE_NAME, authCookieOptions(req));
}

function clearAuthCookies(res, req) {
  res.clearCookie(AUTH_COOKIE_NAME, authCookieOptions(req));
  res.clearCookie(LEGACY_AUTH_COOKIE_NAME, authCookieOptions(req));
}

function verifyLocalToken(token) {
  if (AUTH_DISABLED) return devUser();
  if (!token || !JWT_SECRET) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function tokenClaimsAppAccess(payload) {
  return Array.isArray(payload?.apps) && payload.apps.includes(APP_NAME);
}

function publicUserFromClaims(payload) {
  return {
    id: payload.sub || payload.id || payload.username || 'unknown',
    sub: payload.sub || payload.id || '',
    username: payload.username || 'unknown',
    display_name: payload.display_name || payload.username || 'Unknown user',
    is_admin: !!payload.is_admin,
    apps: Array.isArray(payload.apps) ? payload.apps : [],
  };
}

function devUser() {
  return {
    id: 'dev',
    sub: 'dev',
    username: 'dev',
    display_name: 'Development user',
    is_admin: true,
    apps: [APP_NAME],
  };
}

async function checkCurrentAppAccess(token) {
  if (AUTH_DISABLED) return devUser();

  let response;
  try {
    response = await fetch(`${AUTH_SERVICE_URL}/api/auth/session-status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ app: APP_NAME }),
    });
  } catch {
    const err = new Error('Authentication service unavailable');
    err.authServiceUnavailable = true;
    throw err;
  }

  if (response.status === 400 || response.status === 401 || response.status === 403) return null;
  if (!response.ok) {
    const err = new Error(`AuthService returned ${response.status}`);
    err.authServiceUnavailable = true;
    throw err;
  }

  const data = await response.json().catch(() => null);
  return data?.valid ? publicUserFromClaims(data.user || {}) : null;
}

function wantsJson(req) {
  return req.path.startsWith('/api/') || req.accepts(['html', 'json']) === 'json';
}

async function requireAuth(req, res, next) {
  if (AUTH_DISABLED) {
    req.user = devUser();
    return next();
  }

  const token = getToken(req);
  const payload = verifyLocalToken(token);
  if (!payload) {
    clearAuthCookies(res, req);
    if (wantsJson(req)) return res.status(401).json({ error: 'Not authenticated' });
    return res.redirect('/login');
  }

  if (!tokenClaimsAppAccess(payload)) {
    clearAuthCookies(res, req);
    if (wantsJson(req)) return res.status(403).json({ error: 'No access to this app' });
    return res.redirect('/login');
  }

  try {
    const currentUser = await checkCurrentAppAccess(token);
    if (!currentUser) {
      clearAuthCookies(res, req);
      if (wantsJson(req)) return res.status(403).json({ error: 'No access to this app' });
      return res.redirect('/login');
    }
    req.user = currentUser;
    return next();
  } catch (err) {
    if (err?.authServiceUnavailable) {
      console.warn('[auth] AuthService unavailable; accepting valid local JWT for now.');
      req.user = publicUserFromClaims(payload);
      return next();
    }
    clearAuthCookies(res, req);
    if (wantsJson(req)) return res.status(401).json({ error: 'Invalid session' });
    return res.redirect('/login');
  }
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
  return next();
}

async function proxyAuthJson(pathname, body, req) {
  const response = await fetch(`${AUTH_SERVICE_URL}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...publicForwardHeaders(req) },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  return { response, data };
}

function requestBuffer(urlString, options = {}) {
  const method = options.method || 'GET';
  const headers = { ...(options.headers || {}) };
  const body = options.body == null ? null : Buffer.isBuffer(options.body) ? options.body : Buffer.from(String(options.body));
  const timeoutMs = options.timeoutMs || API_TIMEOUT_MS;
  const maxBytes = options.maxBytes || 512 * 1024;

  if (body && !Object.keys(headers).some(name => name.toLowerCase() === 'content-length')) {
    headers['Content-Length'] = String(body.length);
  }

  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch {
      reject(new Error(`Invalid URL: ${urlString}`));
      return;
    }

    const client = url.protocol === 'https:' ? https : http;
    const requestOptions = {
      method,
      headers,
      timeout: timeoutMs,
    };
    if (url.protocol === 'https:' && options.insecure) requestOptions.rejectUnauthorized = false;

    const req = client.request(url, requestOptions, res => {
      const chunks = [];
      let received = 0;
      res.on('data', chunk => {
        received += chunk.length;
        if (received > maxBytes) {
          req.destroy(new Error(`Response exceeded ${maxBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        resolve({
          status: res.statusCode || 0,
          headers: res.headers || {},
          body: Buffer.concat(chunks),
        });
      });
    });

    req.setTimeout(timeoutMs, () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function requestText(urlString, options = {}) {
  const response = await requestBuffer(urlString, options);
  return { ...response, text: response.body.toString('utf8') };
}

async function requestJson(urlString, options = {}) {
  const headers = { Accept: 'application/json', ...(options.headers || {}) };
  let body = options.body;
  if (options.json !== undefined) {
    body = JSON.stringify(options.json);
    headers['Content-Type'] = 'application/json';
  }

  const response = await requestBuffer(urlString, { ...options, headers, body });
  let json = null;
  if (response.body.length) {
    try {
      json = JSON.parse(response.body.toString('utf8'));
    } catch (err) {
      const parseError = new Error('Invalid JSON response');
      parseError.cause = err;
      parseError.status = response.status;
      throw parseError;
    }
  }
  return { ...response, json };
}

function httpStatusError(label, response) {
  const err = new Error(`${label} returned HTTP ${response.status}`);
  err.status = response.status;
  return err;
}

function writeJsonAtomic(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmpFile = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpFile, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmpFile, filePath);
}

function parseSitesSeed() {
  const seeded = [];
  if (process.env.STATUS_SITES) {
    try {
      const parsed = JSON.parse(process.env.STATUS_SITES);
      const rows = Array.isArray(parsed) ? parsed : parsed.sites;
      if (Array.isArray(rows)) seeded.push(...rows);
    } catch (err) {
      console.warn(`[sites] STATUS_SITES could not be parsed: ${err.message}`);
    }
  }

  if (process.env.NAS_PUBLIC_URL) {
    seeded.push({ name: 'NAS', url: process.env.NAS_PUBLIC_URL, group: 'Home', kind: 'nas' });
  }
  if (process.env.HOME_ASSISTANT_URL) {
    seeded.push({ name: 'Home Assistant', url: process.env.HOME_ASSISTANT_URL, group: 'Home', kind: 'homeassistant' });
  }
  if (process.env.UNIFI_URL) {
    seeded.push({ name: 'UniFi Network', url: process.env.UNIFI_URL, group: 'Network', kind: 'unifi' });
  }

  const used = new Set();
  return seeded
    .map(site => {
      try {
        const normalized = normalizeSite(site);
        if (used.has(normalized.id)) return null;
        used.add(normalized.id);
        return normalized;
      } catch (err) {
        console.warn(`[sites] Skipping invalid seed site: ${err.message}`);
        return null;
      }
    })
    .filter(Boolean);
}

function normalizeTags(value) {
  const raw = Array.isArray(value) ? value : String(value || '').split(',');
  return [...new Set(raw.map(tag => asText(tag, 32)).filter(Boolean))].slice(0, 10);
}

function normalizeUrl(value) {
  const url = asText(value, 600);
  if (!url) throw new Error('URL is required');
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('URL is invalid');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('URL must be HTTP or HTTPS');
  return parsed.toString();
}

function normalizeSite(raw = {}, existing = {}, options = {}) {
  const now = new Date().toISOString();
  const name = asText(raw.name ?? existing.name, 100);
  if (!name) throw new Error('Site name is required');
  const method = String(raw.method ?? existing.method ?? 'GET').toUpperCase();
  if (!['GET', 'HEAD'].includes(method)) throw new Error('Site method must be GET or HEAD');

  const createdAt = existing.createdAt || raw.createdAt || now;
  return {
    id: existing.id || safeId(raw.id || name),
    name,
    url: normalizeUrl(raw.url ?? existing.url),
    group: asText(raw.group ?? existing.group ?? 'General', 80) || 'General',
    kind: asText(raw.kind ?? existing.kind ?? 'site', 40) || 'site',
    method,
    timeoutMs: clampInt(raw.timeoutMs ?? existing.timeoutMs, SITE_TIMEOUT_MS, 1000, 60000),
    tags: normalizeTags(raw.tags ?? existing.tags),
    enabled: raw.enabled === undefined ? existing.enabled !== false : !!raw.enabled,
    createdAt,
    updatedAt: options.touch === false ? (raw.updatedAt || existing.updatedAt || createdAt) : now,
  };
}

function publicSite(site) {
  return {
    id: site.id,
    name: site.name,
    url: site.url,
    group: site.group,
    kind: site.kind,
    method: site.method,
    timeoutMs: site.timeoutMs,
    tags: site.tags,
    enabled: site.enabled,
    createdAt: site.createdAt,
    updatedAt: site.updatedAt,
  };
}

function loadSites() {
  if (!fs.existsSync(SITES_FILE)) {
    const seeded = parseSitesSeed();
    writeSites(seeded);
    return seeded;
  }

  const parsed = JSON.parse(fs.readFileSync(SITES_FILE, 'utf8') || '[]');
  const rows = Array.isArray(parsed) ? parsed : parsed.sites;
  if (!Array.isArray(rows)) return [];
  return rows
    .map(site => {
      try {
        return normalizeSite(site, {}, { touch: false });
      } catch (err) {
        console.warn(`[sites] Skipping invalid site: ${err.message}`);
        return null;
      }
    })
    .filter(Boolean);
}

function writeSites(sites) {
  writeJsonAtomic(SITES_FILE, sites);
}

function uniqueSiteId(sites, desiredId) {
  const used = new Set(sites.map(site => site.id));
  const base = safeId(desiredId);
  if (!used.has(base)) return base;
  for (let index = 2; index < 1000; index += 1) {
    const next = `${base}-${index}`;
    if (!used.has(next)) return next;
  }
  return crypto.randomUUID();
}

async function checkSite(site) {
  const checkedAt = new Date().toISOString();
  if (!site.enabled) {
    return { ...publicSite(site), state: 'disabled', ok: false, checkedAt, latencyMs: null, httpStatus: null, error: '' };
  }

  const started = Date.now();
  try {
    let response = await requestBuffer(site.url, {
      method: site.method || 'GET',
      timeoutMs: site.timeoutMs || SITE_TIMEOUT_MS,
      maxBytes: 64 * 1024,
      insecure: SITE_CHECK_INSECURE,
      headers: { 'User-Agent': `${APP_LABEL}/1.0` },
    });
    if ((site.method || 'GET') === 'HEAD' && response.status === 405) {
      response = await requestBuffer(site.url, {
        method: 'GET',
        timeoutMs: site.timeoutMs || SITE_TIMEOUT_MS,
        maxBytes: 64 * 1024,
        insecure: SITE_CHECK_INSECURE,
        headers: { 'User-Agent': `${APP_LABEL}/1.0` },
      });
    }

    const protectedOk = response.status === 401 || response.status === 403;
    const ok = (response.status >= 200 && response.status < 400) || protectedOk;
    return {
      ...publicSite(site),
      state: ok ? (protectedOk ? 'protected' : 'up') : 'down',
      ok,
      checkedAt,
      latencyMs: Date.now() - started,
      httpStatus: response.status,
      error: '',
    };
  } catch (err) {
    return {
      ...publicSite(site),
      state: 'down',
      ok: false,
      checkedAt,
      latencyMs: Date.now() - started,
      httpStatus: null,
      error: err.message,
    };
  }
}

async function checkAllSites() {
  const sites = loadSites();
  const results = await Promise.all(sites.map(site => checkSite(site)));
  return {
    total: results.length,
    up: results.filter(site => site.state === 'up' || site.state === 'protected').length,
    down: results.filter(site => site.state === 'down').length,
    disabled: results.filter(site => site.state === 'disabled').length,
    sites: results,
  };
}

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

function parseUptime(procRoot) {
  const text = readFileSafe(path.join(procRoot, 'uptime')).trim();
  if (!text) return null;
  const seconds = Number(text.split(/\s+/)[0]);
  if (!Number.isFinite(seconds)) return null;
  return {
    seconds,
    bootedAt: new Date(Date.now() - seconds * 1000).toISOString(),
  };
}

function parseLoad(procRoot) {
  const text = readFileSafe(path.join(procRoot, 'loadavg')).trim();
  const parts = text.split(/\s+/).map(Number);
  if (parts.length < 3 || parts.some(value => !Number.isFinite(value))) return null;
  return { one: parts[0], five: parts[1], fifteen: parts[2] };
}

function parseMeminfo(procRoot) {
  const text = readFileSafe(path.join(procRoot, 'meminfo'));
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([^:]+):\s+(\d+)/);
    if (match) values[match[1]] = Number(match[2]) * 1024;
  }
  const total = values.MemTotal || 0;
  const available = values.MemAvailable || values.MemFree || 0;
  const used = total && available ? total - available : 0;
  const swapTotal = values.SwapTotal || 0;
  const swapFree = values.SwapFree || 0;
  return {
    total,
    available,
    used,
    usedPercent: total ? Math.round((used / total) * 1000) / 10 : null,
    swapTotal,
    swapUsed: swapTotal ? swapTotal - swapFree : 0,
  };
}

function parseCpu(procRoot) {
  const text = readFileSafe(path.join(procRoot, 'cpuinfo'));
  const models = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^model name\s+:\s+(.+)$/);
    if (match) models.push(match[1]);
  }
  return {
    cores: models.length || null,
    model: models[0] || '',
  };
}

function parseNetwork(procRoot) {
  const text = readFileSafe(path.join(procRoot, 'net/dev'));
  return text
    .split(/\r?\n/)
    .slice(2)
    .map(line => {
      const [namePart, dataPart] = line.split(':');
      if (!dataPart) return null;
      const name = namePart.trim();
      const values = dataPart.trim().split(/\s+/).map(Number);
      return {
        name,
        rxBytes: values[0] || 0,
        rxPackets: values[1] || 0,
        txBytes: values[8] || 0,
        txPackets: values[9] || 0,
      };
    })
    .filter(row => row && (row.name !== 'lo' || row.rxBytes || row.txBytes))
    .sort((a, b) => (b.rxBytes + b.txBytes) - (a.rxBytes + a.txBytes))
    .slice(0, 12);
}

async function collectDiskUsage() {
  const paths = parseList(process.env.NAS_DISK_PATHS || '/data,/host/mnt,/');
  const seen = new Set();
  const rows = [];

  for (const diskPath of paths) {
    if (seen.has(diskPath) || !fs.existsSync(diskPath)) continue;
    seen.add(diskPath);
    try {
      const { stdout } = await execFileAsync('df', ['-Pk', diskPath], { timeout: 3000, maxBuffer: 128 * 1024 });
      const line = stdout.trim().split(/\r?\n/).slice(-1)[0] || '';
      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) continue;
      const mount = parts[parts.length - 1];
      const capacity = parts[parts.length - 2];
      const availableKb = Number(parts[parts.length - 3]);
      const usedKb = Number(parts[parts.length - 4]);
      const sizeKb = Number(parts[parts.length - 5]);
      const filesystem = parts.slice(0, -5).join(' ');
      rows.push({
        path: diskPath,
        filesystem,
        mount,
        sizeBytes: sizeKb * 1024,
        usedBytes: usedKb * 1024,
        availableBytes: availableKb * 1024,
        usedPercent: Number(capacity.replace('%', '')) || null,
      });
    } catch (err) {
      rows.push({ path: diskPath, error: err.message });
    }
  }

  return rows;
}

function requestDockerJson(socketPath, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath, path: pathname, method: 'GET', timeout: 3500 }, res => {
      const chunks = [];
      let received = 0;
      res.on('data', chunk => {
        received += chunk.length;
        if (received > 1024 * 1024) {
          req.destroy(new Error('Docker response exceeded 1MB'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        try {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({ status: res.statusCode || 0, json: text ? JSON.parse(text) : null });
        } catch (err) {
          reject(err);
        }
      });
    });
    req.setTimeout(3500, () => req.destroy(new Error('Docker request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function collectDockerContainers() {
  if (!DOCKER_SOCKET || !fs.existsSync(DOCKER_SOCKET)) {
    return { configured: false, socket: DOCKER_SOCKET, total: 0, running: 0, containers: [] };
  }
  try {
    const response = await requestDockerJson(DOCKER_SOCKET, '/containers/json?all=1');
    if (response.status >= 400) throw httpStatusError('Docker', response);
    const containers = Array.isArray(response.json) ? response.json : [];
    const mapped = containers.map(container => ({
      id: String(container.Id || '').slice(0, 12),
      names: Array.isArray(container.Names) ? container.Names.map(name => name.replace(/^\//, '')) : [],
      image: container.Image || '',
      state: container.State || '',
      status: container.Status || '',
      created: container.Created ? new Date(container.Created * 1000).toISOString() : null,
      ports: Array.isArray(container.Ports) ? container.Ports.slice(0, 6) : [],
    }));
    return {
      configured: true,
      socket: DOCKER_SOCKET,
      total: mapped.length,
      running: mapped.filter(container => container.state === 'running').length,
      exited: mapped.filter(container => container.state === 'exited').length,
      containers: mapped.slice(0, 100),
    };
  } catch (err) {
    return { configured: true, ok: false, socket: DOCKER_SOCKET, error: err.message, total: 0, running: 0, containers: [] };
  }
}

function defaultNasLogFiles() {
  return [
    '/host/var/log/syslog',
    '/host/var/log/messages',
    '/host/var/log/system.log',
    '/host/var/log/docker.log',
    '/var/log/syslog',
    '/var/log/messages',
    '/var/log/system.log',
  ];
}

function tailFile(filePath, maxLines = LOG_LINE_LIMIT, maxBytes = 180 * 1024) {
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) return [];
  const start = Math.max(0, stat.size - maxBytes);
  const length = stat.size - start;
  const fd = fs.openSync(filePath, 'r');
  try {
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, start);
    return buffer.toString('utf8').split(/\r?\n/).filter(Boolean).slice(-maxLines);
  } finally {
    fs.closeSync(fd);
  }
}

function collectNasLogs() {
  const files = parseList(process.env.NAS_LOG_FILES).length ? parseList(process.env.NAS_LOG_FILES) : defaultNasLogFiles();
  const seen = new Set();
  return files
    .filter(file => {
      if (seen.has(file)) return false;
      seen.add(file);
      return fs.existsSync(file);
    })
    .slice(0, 12)
    .map(file => {
      try {
        const stat = fs.statSync(file);
        return {
          path: file,
          label: path.basename(file),
          sizeBytes: stat.size,
          modifiedAt: stat.mtime.toISOString(),
          lines: tailFile(file),
        };
      } catch (err) {
        return { path: file, label: path.basename(file), error: err.message, lines: [] };
      }
    });
}

async function collectNasSnapshot() {
  const procRoot = fs.existsSync(path.join(NAS_PROC_PATH, 'uptime')) ? NAS_PROC_PATH : '/proc';
  const [disks, docker] = await Promise.all([collectDiskUsage(), collectDockerContainers()]);
  return {
    configured: true,
    ok: true,
    collectedAt: new Date().toISOString(),
    procPath: procRoot,
    uptime: parseUptime(procRoot),
    load: parseLoad(procRoot),
    memory: parseMeminfo(procRoot),
    cpu: parseCpu(procRoot),
    network: parseNetwork(procRoot),
    disks,
    docker,
    logs: collectNasLogs(),
  };
}

async function haJson(pathname, maxBytes = 1024 * 1024) {
  const baseUrl = cleanBaseUrl(process.env.HOME_ASSISTANT_URL || '');
  const token = process.env.HOME_ASSISTANT_TOKEN || '';
  const response = await requestJson(resolveUrl(baseUrl, pathname), {
    headers: { Authorization: `Bearer ${token}` },
    timeoutMs: API_TIMEOUT_MS,
    maxBytes,
  });
  if (response.status >= 400) throw httpStatusError(`Home Assistant ${pathname}`, response);
  return response.json;
}

async function haText(pathname, maxBytes = 512 * 1024) {
  const baseUrl = cleanBaseUrl(process.env.HOME_ASSISTANT_URL || '');
  const token = process.env.HOME_ASSISTANT_TOKEN || '';
  const response = await requestText(resolveUrl(baseUrl, pathname), {
    headers: { Authorization: `Bearer ${token}` },
    timeoutMs: API_TIMEOUT_MS,
    maxBytes,
  });
  if (response.status >= 400) throw httpStatusError(`Home Assistant ${pathname}`, response);
  return response.text;
}

function endpointResult(name, settled) {
  if (settled.status === 'fulfilled') return { name, ok: true };
  return { name, ok: false, error: settled.reason?.message || 'Request failed', status: settled.reason?.status || null };
}

function settledValue(settled, fallback) {
  return settled.status === 'fulfilled' ? settled.value : fallback;
}

function summarizeHomeAssistantStates(states) {
  const counts = new Map();
  const problems = [];
  for (const entity of states) {
    const entityId = String(entity.entity_id || '');
    const domain = entityId.split('.')[0] || 'unknown';
    counts.set(domain, (counts.get(domain) || 0) + 1);

    const state = String(entity.state || '').toLowerCase();
    const batteryValue = Number(entity.state);
    const isLowBattery = entity.attributes?.device_class === 'battery' && Number.isFinite(batteryValue) && batteryValue <= HA_LOW_BATTERY;
    if (['unavailable', 'unknown', 'problem'].includes(state) || isLowBattery) {
      problems.push({
        entity_id: entityId,
        name: entity.attributes?.friendly_name || entityId,
        state: entity.state,
        reason: isLowBattery ? `Battery ${batteryValue}%` : entity.state,
        last_changed: entity.last_changed,
      });
    }
  }
  return {
    domains: [...counts.entries()]
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 24),
    problems: problems.slice(0, 80),
  };
}

function tailText(text, maxLines = LOG_LINE_LIMIT) {
  return String(text || '').split(/\r?\n/).filter(Boolean).slice(-maxLines);
}

async function collectHomeAssistant() {
  const baseUrl = cleanBaseUrl(process.env.HOME_ASSISTANT_URL || '');
  const token = process.env.HOME_ASSISTANT_TOKEN || '';
  if (!baseUrl || !token) {
    return {
      configured: false,
      ok: false,
      baseUrl,
      error: !baseUrl ? 'HOME_ASSISTANT_URL is not set' : 'HOME_ASSISTANT_TOKEN is not set',
      endpoints: [],
      states: { total: 0, domains: [], problems: [] },
      logbook: [],
      errorLog: [],
    };
  }

  const now = new Date();
  const start = new Date(now.getTime() - HA_LOGBOOK_HOURS * 60 * 60 * 1000).toISOString();
  const end = now.toISOString();
  const logbookPath = `/api/logbook/${encodeURIComponent(start)}?end_time=${encodeURIComponent(end)}`;

  const names = ['api', 'config', 'states', 'events', 'services', 'system_health', 'logbook', 'error_log'];
  const calls = await Promise.allSettled([
    haJson('/api/'),
    haJson('/api/config'),
    haJson('/api/states', 5 * 1024 * 1024),
    haJson('/api/events'),
    haJson('/api/services', 2 * 1024 * 1024),
    haJson('/api/system_health/info'),
    haJson(logbookPath, 2 * 1024 * 1024),
    haText('/api/error_log', 512 * 1024),
  ]);

  const config = settledValue(calls[1], {});
  const states = Array.isArray(settledValue(calls[2], [])) ? settledValue(calls[2], []) : [];
  const events = Array.isArray(settledValue(calls[3], [])) ? settledValue(calls[3], []) : [];
  const services = Array.isArray(settledValue(calls[4], [])) ? settledValue(calls[4], []) : [];
  const systemHealth = settledValue(calls[5], null);
  const logbook = Array.isArray(settledValue(calls[6], [])) ? settledValue(calls[6], []) : [];
  const errorLogText = typeof settledValue(calls[7], '') === 'string' ? settledValue(calls[7], '') : '';
  const stateSummary = summarizeHomeAssistantStates(states);
  const endpoints = names.map((name, index) => endpointResult(name, calls[index]));
  const ok = endpoints.some(endpoint => endpoint.ok);

  return {
    configured: true,
    ok,
    baseUrl,
    collectedAt: new Date().toISOString(),
    config: {
      version: config.version || '',
      location_name: config.location_name || '',
      time_zone: config.time_zone || '',
      unit_system: config.unit_system || null,
    },
    states: {
      total: states.length,
      unavailable: stateSummary.problems.filter(item => ['unavailable', 'unknown'].includes(String(item.state).toLowerCase())).length,
      domains: stateSummary.domains,
      problems: stateSummary.problems,
    },
    eventsCount: events.length,
    servicesCount: services.length,
    systemHealth,
    logbook: logbook.slice(0, 120).map(entry => ({
      when: entry.when || entry.time || entry.created,
      name: entry.name || entry.entity_id || '',
      message: entry.message || '',
      entity_id: entry.entity_id || '',
      domain: entry.domain || '',
    })),
    errorLog: tailText(errorLogText),
    endpoints,
  };
}

function createCookieJar() {
  const cookies = new Map();
  return {
    add(setCookieHeaders) {
      const values = Array.isArray(setCookieHeaders) ? setCookieHeaders : setCookieHeaders ? [setCookieHeaders] : [];
      for (const header of values) {
        const pair = String(header).split(';')[0];
        const index = pair.indexOf('=');
        if (index <= 0) continue;
        cookies.set(pair.slice(0, index), pair.slice(index + 1));
      }
    },
    header() {
      return [...cookies.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
    },
  };
}

function headerValue(headers, name) {
  const value = headers[String(name).toLowerCase()] || headers[name];
  return Array.isArray(value) ? value[0] : value || '';
}

function unifiData(json) {
  if (Array.isArray(json?.data)) return json.data;
  if (json?.data && typeof json.data === 'object') return [json.data];
  if (Array.isArray(json)) return json;
  return [];
}

function unifiMessage(json) {
  return json?.meta?.msg || json?.meta?.rc || json?.message || '';
}

function slimUnifiDevice(device) {
  return {
    name: device.name || device.hostname || device.model || device.mac || '',
    type: device.type || device.device_type || '',
    model: device.model || '',
    mac: device.mac || '',
    ip: device.ip || device.ip_address || '',
    state: device.state,
    version: device.version || '',
    uptime: device.uptime || null,
    adopted: device.adopted,
  };
}

function slimUnifiClient(client) {
  return {
    name: client.hostname || client.name || client.mac || '',
    mac: client.mac || '',
    ip: client.ip || '',
    network: client.network || client.network_name || '',
    radio: client.radio || '',
    essid: client.essid || '',
    uptime: client.uptime || null,
    rxBytes: client.rx_bytes || client.bytes_r || 0,
    txBytes: client.tx_bytes || client.bytes_t || 0,
  };
}

function slimUnifiEvent(event) {
  const seconds = Number(event.time || event.datetime || 0);
  return {
    time: Number.isFinite(seconds) && seconds > 100000 ? new Date(seconds * 1000).toISOString() : event.time || '',
    message: event.msg || event.message || event.key || event.event_type || '',
    subsystem: event.subsystem || event.category || '',
    device: event.hostname || event.ap || event.sw || event.gw || event.user || '',
  };
}

async function collectUniFi() {
  const baseUrl = cleanBaseUrl(process.env.UNIFI_URL || '');
  const username = process.env.UNIFI_USERNAME || '';
  const password = process.env.UNIFI_PASSWORD || '';
  const apiKey = process.env.UNIFI_API_KEY || '';
  if (!baseUrl || (!apiKey && (!username || !password))) {
    return {
      configured: false,
      ok: false,
      baseUrl,
      site: UNIFI_SITE,
      error: !baseUrl ? 'UNIFI_URL is not set' : 'UniFi credentials are not set',
      endpoints: [],
      health: [],
      devices: { total: 0, offline: 0, rows: [] },
      clients: { total: 0, rows: [] },
      events: [],
      alarms: [],
    };
  }

  const cookieJar = createCookieJar();
  let csrfToken = '';
  const authHeaders = {};
  if (apiKey) {
    authHeaders['X-API-KEY'] = apiKey;
    authHeaders.Authorization = `Bearer ${apiKey}`;
  }

  if (username && password) {
    const loginPaths = parseList(process.env.UNIFI_LOGIN_PATHS || '/api/auth/login,/api/login');
    let loggedIn = false;
    let lastError = '';
    for (const loginPath of loginPaths) {
      try {
        const response = await requestJson(resolveUrl(baseUrl, loginPath), {
          method: 'POST',
          json: { username, password, remember: true },
          timeoutMs: API_TIMEOUT_MS,
          maxBytes: 512 * 1024,
          insecure: UNIFI_INSECURE,
          headers: authHeaders,
        });
        cookieJar.add(response.headers['set-cookie']);
        csrfToken = headerValue(response.headers, 'x-csrf-token') || csrfToken;
        if (response.status < 400 && response.json?.meta?.rc !== 'error') {
          loggedIn = true;
          break;
        }
        lastError = unifiMessage(response.json) || `HTTP ${response.status}`;
      } catch (err) {
        lastError = err.message;
      }
    }
    if (!loggedIn && !apiKey) {
      return { configured: true, ok: false, baseUrl, site: UNIFI_SITE, error: `UniFi login failed: ${lastError}`, endpoints: [] };
    }
  }

  function currentHeaders() {
    const headers = { ...authHeaders };
    const cookie = cookieJar.header();
    if (cookie) headers.Cookie = cookie;
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    return headers;
  }

  async function callUniFi(resource, options = {}) {
    const prefixes = parseUniFiPrefixes();
    const methods = options.body ? ['POST', 'GET'] : ['GET'];
    let lastError = null;

    for (const prefix of prefixes) {
      const prefixClean = prefix.replace(/\/+$/, '');
      const pathname = `${prefixClean}/api/s/${encodeURIComponent(UNIFI_SITE)}/${resource}`.replace(/^\/?/, '/');
      for (const method of methods) {
        try {
          const response = await requestJson(resolveUrl(baseUrl, pathname), {
            method,
            json: method === 'POST' ? options.body : undefined,
            headers: currentHeaders(),
            timeoutMs: API_TIMEOUT_MS,
            maxBytes: options.maxBytes || 2 * 1024 * 1024,
            insecure: UNIFI_INSECURE,
          });
          cookieJar.add(response.headers['set-cookie']);
          csrfToken = headerValue(response.headers, 'x-csrf-token') || csrfToken;
          if (response.status >= 400 || response.json?.meta?.rc === 'error') throw httpStatusError(`UniFi ${pathname}`, response);
          return { path: pathname, json: response.json };
        } catch (err) {
          lastError = err;
        }
      }
    }
    throw lastError || new Error(`UniFi ${resource} failed`);
  }

  const names = ['health', 'sysinfo', 'devices', 'clients', 'events', 'alarms'];
  const calls = await Promise.allSettled([
    callUniFi('stat/health'),
    callUniFi('stat/sysinfo'),
    callUniFi('stat/device'),
    callUniFi('stat/sta'),
    callUniFi('stat/event', { body: { _limit: 120, _sort: '-time' } }),
    callUniFi('stat/alarm', { body: { _limit: 120, _sort: '-time' } }),
  ]);

  const health = unifiData(settledValue(calls[0], {}).json || settledValue(calls[0], {}));
  const sysinfo = unifiData(settledValue(calls[1], {}).json || settledValue(calls[1], {}))[0] || null;
  const devices = unifiData(settledValue(calls[2], {}).json || settledValue(calls[2], {})).map(slimUnifiDevice);
  const clients = unifiData(settledValue(calls[3], {}).json || settledValue(calls[3], {})).map(slimUnifiClient);
  const events = unifiData(settledValue(calls[4], {}).json || settledValue(calls[4], {})).map(slimUnifiEvent).slice(0, 120);
  const alarms = unifiData(settledValue(calls[5], {}).json || settledValue(calls[5], {})).map(slimUnifiEvent).slice(0, 120);
  const endpoints = names.map((name, index) => endpointResult(name, calls[index]));
  const ok = endpoints.some(endpoint => endpoint.ok);

  return {
    configured: true,
    ok,
    baseUrl,
    site: UNIFI_SITE,
    collectedAt: new Date().toISOString(),
    sysinfo,
    health,
    devices: {
      total: devices.length,
      offline: devices.filter(device => device.state !== 1 && device.state !== '1').length,
      rows: devices.slice(0, 100),
    },
    clients: {
      total: clients.length,
      rows: clients.slice(0, 100),
    },
    events,
    alarms,
    endpoints,
  };
}

async function collectDashboard() {
  const [nas, homeAssistant, unifi, sites] = await Promise.all([
    collectNasSnapshot().catch(err => ({ configured: true, ok: false, error: err.message })),
    collectHomeAssistant().catch(err => ({ configured: true, ok: false, error: err.message })),
    collectUniFi().catch(err => ({ configured: true, ok: false, error: err.message })),
    checkAllSites().catch(err => ({ total: 0, up: 0, down: 0, disabled: 0, sites: [], error: err.message })),
  ]);

  return {
    app: { name: APP_NAME, label: APP_LABEL },
    collectedAt: new Date().toISOString(),
    nas,
    homeAssistant,
    unifi,
    sites,
  };
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, app: APP_NAME, label: APP_LABEL });
});

app.get('/login', (req, res) => {
  const payload = verifyLocalToken(getToken(req));
  if (payload && tokenClaimsAppAccess(payload)) return res.redirect('/');
  return res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/forgot-password', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'password-reset.html'));
});

app.get('/reset-password', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'password-reset.html'));
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  try {
    const { response, data } = await proxyAuthJson('/api/auth/login', {
      username,
      password,
      app: APP_NAME,
    }, req);

    if (!response.ok) return res.status(response.status).json(data);

    if (data.must_change_password) {
      const returnUrl = `${getPublicBaseUrl(req)}/api/auth/token-login`;
      return res.json({
        must_change_password: true,
        change_token: data.change_token,
        redirect: `${AUTH_SERVICE_PUBLIC_URL}/change-password?t=${encodeURIComponent(data.change_token)}&return=${encodeURIComponent(returnUrl)}`,
      });
    }

    if (!data.token) return res.status(502).json({ error: 'Auth service did not return a token' });
    setAuthCookie(res, req, data.token);
    return res.json({
      ok: true,
      username: data.username,
      display_name: data.display_name,
      is_admin: !!data.is_admin,
    });
  } catch (err) {
    console.error('[auth] AuthService login failed:', err.message);
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookies(res, req);
  res.json({ ok: true });
});

app.post('/api/auth/complete-password-setup', async (req, res) => {
  const { change_token, new_password } = req.body || {};
  if (!change_token || !new_password) return res.status(400).json({ error: 'Missing password setup data' });

  try {
    const { response, data } = await proxyAuthJson('/api/auth/complete-password-setup', {
      change_token,
      new_password,
    }, req);
    if (!response.ok) return res.status(response.status).json(data);
    if (!data.token) return res.status(502).json({ error: 'Auth service did not return a token' });
    setAuthCookie(res, req, data.token);
    return res.json({ ok: true, username: data.username, display_name: data.display_name });
  } catch (err) {
    console.error('[auth] AuthService password setup failed:', err.message);
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
});

app.post('/api/auth/request-password-reset', async (req, res) => {
  const identifier = asText(req.body?.identifier, 120);
  if (!identifier) return res.status(400).json({ error: 'Username or email required' });

  try {
    const { response, data } = await proxyAuthJson('/api/auth/request-password-reset', {
      identifier,
      app: APP_NAME,
    }, req);
    return res.status(response.status).json(data);
  } catch (err) {
    console.error('[auth] AuthService password reset request failed:', err.message);
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
});

app.post('/api/auth/complete-password-reset', async (req, res) => {
  const { reset_token, new_password } = req.body || {};
  if (!reset_token || !new_password) return res.status(400).json({ error: 'Missing password reset data' });

  try {
    const { response, data } = await proxyAuthJson('/api/auth/complete-password-reset', {
      reset_token,
      new_password,
    }, req);
    return res.status(response.status).json(data);
  } catch (err) {
    console.error('[auth] AuthService password reset failed:', err.message);
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
});

app.get('/api/auth/token-login', (req, res) => {
  const token = String(req.query.t || '');
  const payload = verifyLocalToken(token);
  if (!payload || !tokenClaimsAppAccess(payload)) return res.redirect('/login');
  setAuthCookie(res, req, token);
  return res.redirect('/');
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user, app: { name: APP_NAME, label: APP_LABEL } });
});

app.get('/api/dashboard', requireAuth, async (_req, res) => {
  res.json(await collectDashboard());
});

app.get('/api/nas', requireAuth, async (_req, res) => {
  res.json(await collectNasSnapshot());
});

app.get('/api/home-assistant', requireAuth, async (_req, res) => {
  res.json(await collectHomeAssistant());
});

app.get('/api/unifi', requireAuth, async (_req, res) => {
  res.json(await collectUniFi());
});

app.get('/api/sites', requireAuth, (_req, res) => {
  res.json({ sites: loadSites().map(publicSite) });
});

app.get('/api/sites/status', requireAuth, async (_req, res) => {
  res.json(await checkAllSites());
});

app.post('/api/sites', requireAuth, requireAdmin, (req, res) => {
  try {
    const sites = loadSites();
    const site = normalizeSite(req.body);
    site.id = uniqueSiteId(sites, req.body?.id || site.name);
    sites.push(site);
    writeSites(sites);
    res.status(201).json({ site: publicSite(site) });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Could not create site' });
  }
});

app.put('/api/sites/:id', requireAuth, requireAdmin, (req, res) => {
  try {
    const sites = loadSites();
    const index = sites.findIndex(site => site.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Site not found' });
    const site = normalizeSite({ ...sites[index], ...req.body, id: sites[index].id }, sites[index]);
    sites[index] = site;
    writeSites(sites);
    return res.json({ site: publicSite(site) });
  } catch (err) {
    return res.status(400).json({ error: err.message || 'Could not update site' });
  }
});

app.delete('/api/sites/:id', requireAuth, requireAdmin, (req, res) => {
  const sites = loadSites();
  const nextSites = sites.filter(site => site.id !== req.params.id);
  if (nextSites.length === sites.length) return res.status(404).json({ error: 'Site not found' });
  writeSites(nextSites);
  return res.json({ ok: true });
});

app.get('/api/logs', requireAuth, async (_req, res) => {
  const [nas, homeAssistant, unifi] = await Promise.all([
    collectNasSnapshot().catch(err => ({ logs: [], error: err.message })),
    collectHomeAssistant().catch(err => ({ logbook: [], errorLog: [], error: err.message })),
    collectUniFi().catch(err => ({ events: [], alarms: [], error: err.message })),
  ]);
  res.json({
    collectedAt: new Date().toISOString(),
    nas: nas.logs || [],
    homeAssistant: {
      logbook: homeAssistant.logbook || [],
      errorLog: homeAssistant.errorLog || [],
      error: homeAssistant.error || '',
    },
    unifi: {
      events: unifi.events || [],
      alarms: unifi.alarms || [],
      error: unifi.error || '',
    },
  });
});

app.get(['/', '/nas', '/home-assistant', '/unifi', '/sites', '/logs'], requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  return res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`[chempboard] ${APP_LABEL} running on port ${PORT}`);
});
