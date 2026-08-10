const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const dgram = require('dgram');
const net = require('net');
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
const SETTINGS_FILE = process.env.SETTINGS_FILE || path.join(DATA_DIR, 'settings.json');
const SITES_FILE = process.env.SITES_FILE || path.join(DATA_DIR, 'sites.json');
const WOL_DEVICES_FILE = process.env.WOL_DEVICES_FILE || path.join(DATA_DIR, 'wol-devices.json');
const WAKE_LOG_FILE = process.env.WAKE_LOG_FILE || path.join(DATA_DIR, 'wake-log.json');
const API_TIMEOUT_MS = clampInt(process.env.API_TIMEOUT_MS, 6500, 1000, 60000);
const SITE_TIMEOUT_MS = clampInt(process.env.SITE_TIMEOUT_MS, 4500, 1000, 60000);
const SITE_CHECK_INSECURE = parseBool(process.env.SITE_CHECK_INSECURE);
const NAS_PROC_PATH = process.env.NAS_PROC_PATH || (fs.existsSync('/host/proc/uptime') ? '/host/proc' : '/proc');
const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';
const HA_LOW_BATTERY = clampInt(process.env.HA_LOW_BATTERY, 20, 1, 90);
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

function parsePort(value, fallback) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 0 && port <= 65535 ? port : fallback;
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
  const settings = loadSettings();
  if (process.env.UNIFI_API_PREFIXES === undefined && !Object.prototype.hasOwnProperty.call(settings, 'unifiApiPrefixes')) {
    return ['/proxy/network', ''];
  }
  return String(settingValue('unifiApiPrefixes', 'UNIFI_API_PREFIXES', '/proxy/network,'))
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

function loadSettings() {
  try {
    if (!fs.existsSync(SETTINGS_FILE)) return {};
    const parsed = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8') || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (err) {
    console.warn(`[settings] Could not load settings: ${err.message}`);
    return {};
  }
}

function writeSettings(settings) {
  writeJsonAtomic(SETTINGS_FILE, settings);
}

function settingValue(key, envName, fallback = '') {
  const settings = loadSettings();
  if (Object.prototype.hasOwnProperty.call(settings, key)) return settings[key];
  return process.env[envName] ?? fallback;
}

function stringSetting(key, envName, fallback = '', maxLength = 1000) {
  return asText(settingValue(key, envName, fallback), maxLength);
}

function boolSetting(key, envName, fallback = false) {
  return parseBool(settingValue(key, envName, fallback ? 'true' : 'false'), fallback);
}

function intSetting(key, envName, fallback, min, max) {
  return clampInt(settingValue(key, envName, String(fallback)), fallback, min, max);
}

function publicSettings() {
  const settings = loadSettings();
  const hasWolBindPort = process.env.WOL_BIND_PORT !== undefined || Object.prototype.hasOwnProperty.call(settings, 'wolBindPort');
  return {
    nasPublicUrl: stringSetting('nasPublicUrl', 'NAS_PUBLIC_URL', '', 600),
    nasDiskPaths: stringSetting('nasDiskPaths', 'NAS_DISK_PATHS', '/data,/host/mnt', 1200),
    nasLogFiles: stringSetting('nasLogFiles', 'NAS_LOG_FILES', '', 2000),
    homeAssistantUrl: stringSetting('homeAssistantUrl', 'HOME_ASSISTANT_URL', '', 600),
    hasHomeAssistantToken: !!stringSetting('homeAssistantToken', 'HOME_ASSISTANT_TOKEN', '', 4000),
    haLogbookHours: intSetting('haLogbookHours', 'HA_LOGBOOK_HOURS', 24, 1, 168),
    unifiUrl: stringSetting('unifiUrl', 'UNIFI_URL', '', 600),
    unifiUsername: stringSetting('unifiUsername', 'UNIFI_USERNAME', '', 160),
    hasUnifiPassword: !!stringSetting('unifiPassword', 'UNIFI_PASSWORD', '', 1000),
    hasUnifiApiKey: !!stringSetting('unifiApiKey', 'UNIFI_API_KEY', '', 4000),
    unifiSite: stringSetting('unifiSite', 'UNIFI_SITE', 'default', 120) || 'default',
    unifiHostId: stringSetting('unifiHostId', 'UNIFI_HOST_ID', '', 220),
    unifiSiteId: stringSetting('unifiSiteId', 'UNIFI_SITE_ID', '', 180),
    unifiInsecure: boolSetting('unifiInsecure', 'UNIFI_INSECURE', true),
    unifiLoginPaths: stringSetting('unifiLoginPaths', 'UNIFI_LOGIN_PATHS', '/api/auth/login,/api/login', 500),
    unifiApiPrefixes: stringSetting('unifiApiPrefixes', 'UNIFI_API_PREFIXES', '/proxy/network,', 500),
    wolDefaultBroadcast: stringSetting('wolDefaultBroadcast', 'WOL_DEFAULT_BROADCAST', '255.255.255.255', 120) || '255.255.255.255',
    wolDefaultPort: intSetting('wolDefaultPort', 'WOL_DEFAULT_PORT', 9, 0, 65535),
    wolExtraBroadcasts: stringSetting('wolExtraBroadcasts', 'WOL_EXTRA_BROADCASTS', '', 1200),
    wolRepeatCount: intSetting('wolRepeatCount', 'WOL_REPEAT_COUNT', 3, 1, 10),
    wolBindAddress: stringSetting('wolBindAddress', 'WOL_BIND_ADDRESS', '', 120),
    wolBindPort: hasWolBindPort ? intSetting('wolBindPort', 'WOL_BIND_PORT', 0, 0, 65535) : '',
  };
}

function updateSettings(raw = {}) {
  const current = loadSettings();
  const next = { ...current };
  const textFields = [
    ['nasPublicUrl', 600],
    ['nasDiskPaths', 1200],
    ['nasLogFiles', 2000],
    ['homeAssistantUrl', 600],
    ['unifiUrl', 600],
    ['unifiUsername', 160],
    ['unifiSite', 120],
    ['unifiHostId', 220],
    ['unifiSiteId', 180],
    ['unifiLoginPaths', 500],
    ['unifiApiPrefixes', 500],
    ['wolDefaultBroadcast', 120],
    ['wolExtraBroadcasts', 1200],
    ['wolBindAddress', 120],
  ];

  for (const [key, maxLength] of textFields) {
    if (raw[key] !== undefined) next[key] = asText(raw[key], maxLength);
  }

  if (raw.haLogbookHours !== undefined) next.haLogbookHours = intSettingFromRaw(raw.haLogbookHours, 24, 1, 168);
  if (raw.unifiInsecure !== undefined) next.unifiInsecure = parseBool(raw.unifiInsecure, true);
  if (raw.wolDefaultPort !== undefined) next.wolDefaultPort = parsePort(raw.wolDefaultPort, 9);
  if (raw.wolRepeatCount !== undefined) next.wolRepeatCount = clampInt(raw.wolRepeatCount, 3, 1, 10);
  if (raw.wolBindPort !== undefined) {
    const bindPortText = asText(raw.wolBindPort, 12);
    next.wolBindPort = bindPortText === '' ? '' : parsePort(bindPortText, 0);
  }

  updateSecretSetting(next, raw, 'homeAssistantToken', 'clearHomeAssistantToken', 4000);
  updateSecretSetting(next, raw, 'unifiPassword', 'clearUnifiPassword', 1000);
  updateSecretSetting(next, raw, 'unifiApiKey', 'clearUnifiApiKey', 4000);

  next.updatedAt = new Date().toISOString();
  writeSettings(next);
  return publicSettings();
}

function intSettingFromRaw(value, fallback, min, max) {
  return clampInt(value, fallback, min, max);
}

function updateSecretSetting(next, raw, key, clearKey, maxLength) {
  if (raw[clearKey]) {
    next[key] = '';
    return;
  }
  if (raw[key] !== undefined && asText(raw[key], maxLength)) {
    next[key] = asText(raw[key], maxLength);
  }
}

function normalizeMac(value) {
  const compact = String(value || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  if (compact.length !== 12) return '';
  return compact.match(/.{2}/g).join(':');
}

function macToBuffer(mac) {
  const normalized = normalizeMac(mac);
  if (!normalized) throw new Error('Invalid MAC address');
  return Buffer.from(normalized.split(':').map(part => parseInt(part, 16)));
}

function normalizeDevice(raw = {}, existing = {}, options = {}) {
  const now = new Date().toISOString();
  const defaultBroadcast = stringSetting('wolDefaultBroadcast', 'WOL_DEFAULT_BROADCAST', '255.255.255.255', 120) || '255.255.255.255';
  const defaultPort = intSetting('wolDefaultPort', 'WOL_DEFAULT_PORT', 9, 0, 65535);
  const mac = normalizeMac(raw.mac ?? existing.mac);
  if (!mac) throw new Error('A valid MAC address is required');

  const name = asText(raw.name ?? existing.name, 100);
  if (!name) throw new Error('Device name is required');

  const createdAt = existing.createdAt || raw.createdAt || now;
  return {
    id: existing.id || safeId(raw.id || name || mac),
    name,
    mac,
    broadcast: asText(raw.broadcast ?? existing.broadcast ?? defaultBroadcast, 120) || defaultBroadcast,
    port: parsePort(raw.port ?? existing.port, defaultPort),
    description: asText(raw.description ?? existing.description, 280),
    tags: normalizeTags(raw.tags ?? existing.tags),
    enabled: raw.enabled === undefined ? existing.enabled !== false : !!raw.enabled,
    createdAt,
    updatedAt: options.touch === false ? (raw.updatedAt || existing.updatedAt || createdAt) : now,
    lastWakeAt: raw.lastWakeAt || existing.lastWakeAt || null,
    lastWakeBy: raw.lastWakeBy || existing.lastWakeBy || '',
  };
}

function parseDeviceSeed() {
  if (!process.env.WOL_DEVICES) return [];
  const parsed = JSON.parse(process.env.WOL_DEVICES);
  const devices = Array.isArray(parsed) ? parsed : parsed.devices;
  if (!Array.isArray(devices)) throw new Error('WOL_DEVICES must be a JSON array or { "devices": [] }');
  return devices.map(device => normalizeDevice(device));
}

function loadWakeDevices() {
  if (!fs.existsSync(WOL_DEVICES_FILE)) {
    const seeded = parseDeviceSeed();
    writeWakeDevices(seeded);
    return seeded;
  }

  const parsed = JSON.parse(fs.readFileSync(WOL_DEVICES_FILE, 'utf8') || '[]');
  const devices = Array.isArray(parsed) ? parsed : parsed.devices;
  if (!Array.isArray(devices)) return [];

  return devices
    .map(device => {
      try {
        return normalizeDevice(device, {}, { touch: false });
      } catch (err) {
        console.warn(`[wol] Skipping invalid device: ${err.message}`);
        return null;
      }
    })
    .filter(Boolean);
}

function writeWakeDevices(devices) {
  writeJsonAtomic(WOL_DEVICES_FILE, devices);
}

function uniqueWakeDeviceId(devices, desiredId) {
  const used = new Set(devices.map(device => device.id));
  const base = safeId(desiredId);
  if (!used.has(base)) return base;
  for (let index = 2; index < 1000; index += 1) {
    const next = `${base}-${index}`;
    if (!used.has(next)) return next;
  }
  return crypto.randomUUID();
}

function publicWakeDevice(device) {
  const wakeTargets = wakeTargetsForDevice(device);
  const targets = [...new Set(wakeTargets.map(target => target.target))];
  return {
    id: device.id,
    name: device.name,
    mac: device.mac,
    broadcast: device.broadcast,
    port: device.port,
    targets,
    wakeTargets,
    check: wakeCheckTargetForDevice(device),
    description: device.description,
    tags: device.tags,
    enabled: device.enabled,
    createdAt: device.createdAt,
    updatedAt: device.updatedAt,
    lastWakeAt: device.lastWakeAt,
    lastWakeBy: device.lastWakeBy,
  };
}

function buildMagicPacket(mac) {
  const macBuffer = macToBuffer(mac);
  const packet = Buffer.alloc(6 + (16 * macBuffer.length), 0xff);
  for (let index = 0; index < 16; index += 1) {
    macBuffer.copy(packet, 6 + (index * macBuffer.length));
  }
  return packet;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function inferDirectedBroadcast(target) {
  const octets = String(target || '').trim().split('.');
  if (octets.length !== 4) return '';
  const values = octets.map(part => Number(part));
  if (!values.every(value => Number.isInteger(value) && value >= 0 && value <= 255)) return '';
  if (values[3] === 255 || target === '255.255.255.255') return '';
  return `${values[0]}.${values[1]}.${values[2]}.255`;
}

function isIpv4Address(target) {
  const parts = String(target || '').trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    if (!/^\d+$/.test(part)) return false;
    const value = Number(part);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
}

function isBroadcastTarget(target) {
  const text = String(target || '').trim();
  return text === '255.255.255.255' || (isIpv4Address(text) && text.endsWith('.255'));
}

function isUnicastTarget(target) {
  const text = String(target || '').trim();
  if (!isIpv4Address(text)) return false;
  if (text === '0.0.0.0' || isBroadcastTarget(text)) return false;
  return true;
}

function wakeTargetsForDevice(device) {
  const extraTargets = parseList(stringSetting('wolExtraBroadcasts', 'WOL_EXTRA_BROADCASTS', '', 1200).replace(/\n/g, ','));
  const defaultBroadcast = stringSetting('wolDefaultBroadcast', 'WOL_DEFAULT_BROADCAST', '255.255.255.255', 120) || '255.255.255.255';
  const targetTexts = [device.broadcast, inferDirectedBroadcast(device.broadcast), defaultBroadcast, ...extraTargets]
    .map(target => asText(target, 120))
    .filter(Boolean);
  const targets = [];
  const seen = new Set();

  function add(target, mode) {
    const key = `${target}|${mode}`;
    if (seen.has(key)) return;
    seen.add(key);
    targets.push({ target, mode });
  }

  for (const target of targetTexts) {
    if (isUnicastTarget(target)) {
      add(target, 'unicast');
      add(target, 'legacy');
    } else {
      add(target, 'broadcast');
    }
  }

  return targets;
}

function wakeCheckTargetForDevice(device) {
  if (!isUnicastTarget(device.broadcast)) return null;
  return {
    host: device.broadcast,
    port: device.port,
    label: `TCP ${device.port}`,
  };
}

function sendWakePacketToTarget(device, target, mode) {
  const packet = buildMagicPacket(device.mac);
  const socket = dgram.createSocket('udp4');
  const bindOptions = {};
  const bindAddress = stringSetting('wolBindAddress', 'WOL_BIND_ADDRESS', '', 120);
  const bindPort = intSetting('wolBindPort', 'WOL_BIND_PORT', 0, 0, 65535);
  if (bindAddress) bindOptions.address = bindAddress;
  if (bindPort) bindOptions.port = bindPort;

  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => finish(new Error('Wake request timed out')), 5000);

    function finish(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.close();
      if (err) reject(err);
      else resolve();
    }

    socket.on('error', finish);
    socket.bind(bindOptions, () => {
      if (mode !== 'unicast') {
        try {
          socket.setBroadcast(true);
        } catch (err) {
          finish(err);
          return;
        }
      }
      socket.send(packet, 0, packet.length, device.port, target, finish);
    });
  });
}

function checkTcpPort(host, port, timeoutMs = 1400) {
  return new Promise(resolve => {
    const checkedAt = new Date().toISOString();
    const startedAt = Date.now();
    const socket = net.createConnection({ host, port });
    let settled = false;

    function finish(open, error = '') {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        host,
        port,
        open,
        checkedAt,
        latencyMs: Date.now() - startedAt,
        error,
      });
    }

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'timeout'));
    socket.once('error', err => finish(false, err.code || err.message));
  });
}

async function checkWakeDevice(device) {
  const checkTarget = wakeCheckTargetForDevice(device);
  if (!checkTarget) return { configured: false, open: false, checkedAt: new Date().toISOString() };
  return { configured: true, label: checkTarget.label, ...(await checkTcpPort(checkTarget.host, checkTarget.port)) };
}

async function sendWakePacket(device) {
  const repeatCount = intSetting('wolRepeatCount', 'WOL_REPEAT_COUNT', 3, 1, 10);
  const targets = wakeTargetsForDevice(device);
  const attempts = [];

  for (const { target, mode } of targets) {
    for (let index = 0; index < repeatCount; index += 1) {
      const attempt = {
        target,
        mode,
        port: device.port,
        index: index + 1,
        ok: false,
        at: new Date().toISOString(),
      };
      try {
        await sendWakePacketToTarget(device, target, mode);
        attempt.ok = true;
      } catch (err) {
        attempt.error = err.message;
      }
      attempts.push(attempt);
      if (index < repeatCount - 1) await delay(120);
    }
  }

  if (!attempts.some(attempt => attempt.ok)) {
    const err = new Error(attempts[0]?.error || 'No wake packet could be sent');
    err.attempts = attempts;
    throw err;
  }

  return attempts;
}

function readWakeLog(limit = 100) {
  try {
    if (!fs.existsSync(WAKE_LOG_FILE)) return [];
    const parsed = JSON.parse(fs.readFileSync(WAKE_LOG_FILE, 'utf8') || '[]');
    return Array.isArray(parsed) ? parsed.slice(0, limit) : [];
  } catch {
    return [];
  }
}

function appendWakeLog(entry) {
  const log = readWakeLog(200);
  log.unshift(entry);
  writeJsonAtomic(WAKE_LOG_FILE, log.slice(0, 200));
}

async function collectWakeSnapshot() {
  const rawDevices = loadWakeDevices();
  const devices = await Promise.all(rawDevices.map(async device => ({
    ...publicWakeDevice(device),
    status: await checkWakeDevice(device),
  })));
  const enabled = devices.filter(device => device.enabled).length;
  const lastWakeAt = devices
    .map(device => device.lastWakeAt)
    .filter(Boolean)
    .sort()
    .at(-1) || null;
  return {
    total: devices.length,
    enabled,
    disabled: devices.length - enabled,
    lastWakeAt,
    devices,
    log: readWakeLog(80),
  };
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

  const nasPublicUrl = stringSetting('nasPublicUrl', 'NAS_PUBLIC_URL', '', 600);
  const homeAssistantUrl = stringSetting('homeAssistantUrl', 'HOME_ASSISTANT_URL', '', 600);
  const unifiUrl = stringSetting('unifiUrl', 'UNIFI_URL', '', 600);
  if (nasPublicUrl) {
    seeded.push({ name: 'NAS', url: nasPublicUrl, group: 'Home', kind: 'nas' });
  }
  if (homeAssistantUrl) {
    seeded.push({ name: 'Home Assistant', url: homeAssistantUrl, group: 'Home', kind: 'homeassistant' });
  }
  if (unifiUrl) {
    seeded.push({ name: 'UniFi Network', url: unifiUrl, group: 'Network', kind: 'unifi' });
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
  const paths = parseList(stringSetting('nasDiskPaths', 'NAS_DISK_PATHS', '/data,/host/mnt,/', 1200).replace(/\n/g, ','));
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
  const configuredFiles = parseList(stringSetting('nasLogFiles', 'NAS_LOG_FILES', '', 2000).replace(/\n/g, ','));
  const files = configuredFiles.length ? configuredFiles : defaultNasLogFiles();
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
  const baseUrl = cleanBaseUrl(stringSetting('homeAssistantUrl', 'HOME_ASSISTANT_URL', '', 600));
  const token = stringSetting('homeAssistantToken', 'HOME_ASSISTANT_TOKEN', '', 4000);
  const response = await requestJson(resolveUrl(baseUrl, pathname), {
    headers: { Authorization: `Bearer ${token}` },
    timeoutMs: API_TIMEOUT_MS,
    maxBytes,
  });
  if (response.status >= 400) throw httpStatusError(`Home Assistant ${pathname}`, response);
  return response.json;
}

async function haText(pathname, maxBytes = 512 * 1024) {
  const baseUrl = cleanBaseUrl(stringSetting('homeAssistantUrl', 'HOME_ASSISTANT_URL', '', 600));
  const token = stringSetting('homeAssistantToken', 'HOME_ASSISTANT_TOKEN', '', 4000);
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
  const baseUrl = cleanBaseUrl(stringSetting('homeAssistantUrl', 'HOME_ASSISTANT_URL', '', 600));
  const token = stringSetting('homeAssistantToken', 'HOME_ASSISTANT_TOKEN', '', 4000);
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
  const haLogbookHours = intSetting('haLogbookHours', 'HA_LOGBOOK_HOURS', 24, 1, 168);
  const start = new Date(now.getTime() - haLogbookHours * 60 * 60 * 1000).toISOString();
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
  if (Array.isArray(json?.data?.items)) return json.data.items;
  if (Array.isArray(json?.data?.results)) return json.data.results;
  if (Array.isArray(json?.items)) return json.items;
  if (Array.isArray(json?.results)) return json.results;
  if (json?.data && typeof json.data === 'object') return [json.data];
  if (Array.isArray(json)) return json;
  return [];
}

function unifiMessage(json) {
  return json?.meta?.msg || json?.meta?.rc || json?.message || '';
}

function siteManagerApiBaseUrl(baseUrl) {
  try {
    const url = new URL(baseUrl);
    if (url.hostname === 'unifi.ui.com') return 'https://api.ui.com';
    if (url.hostname === 'api.ui.com') return cleanBaseUrl(baseUrl);
  } catch {
    return '';
  }
  return '';
}

function siteManagerApiBaseUrls(baseUrl) {
  const override = cleanBaseUrl(process.env.UNIFI_SITE_MANAGER_URL || '');
  if (override) return [override];
  const urls = [
    siteManagerApiBaseUrl(baseUrl),
    'https://api.ui.com',
  ].filter(Boolean);
  return [...new Set(urls.map(cleanBaseUrl))];
}

function nestedValue(source, paths) {
  for (const pathSpec of paths) {
    const parts = pathSpec.split('.');
    let value = source;
    for (const part of parts) {
      value = value && typeof value === 'object' ? value[part] : undefined;
    }
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return '';
}

function firstFiniteNumber(values, fallback = 0) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return fallback;
}

function uniqueTextValues(values, maxLength = 240) {
  const seen = new Set();
  const rows = [];
  for (const value of values) {
    const text = asText(value, maxLength);
    if (!text || seen.has(text.toLowerCase())) continue;
    seen.add(text.toLowerCase());
    rows.push(text);
  }
  return rows;
}

function normalizeTextKey(value) {
  return asText(value, 240).trim().toLowerCase();
}

function looksLikeUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(asText(value, 180));
}

function networkIntegrationSiteKey(site) {
  return asText(site?.id || site?._id || site?.siteId || site?.site_id || site?.name || site?.internalReference || '', 180);
}

function networkIntegrationSiteIds(site) {
  return uniqueTextValues([
    site?.id,
    site?._id,
    site?.siteId,
    site?.site_id,
  ], 180);
}

function networkIntegrationLegacyRefs(site) {
  return uniqueTextValues([
    site?.internalReference,
    site?.shortname,
    site?.name,
    site?.siteName,
    site?.site_name,
    site?.meta?.name,
  ], 180);
}

function networkIntegrationSiteName(site) {
  return asText(site?.name || site?.meta?.name || site?.siteName || site?.site_name || site?.displayName || site?.description || '', 160);
}

function slimUniFiHost(host) {
  const id = asText(host?.id || host?.hostId || host?.hardwareId || '', 220);
  if (!id) return null;
  const label = asText(nestedValue(host, [
    'name',
    'hostName',
    'hostname',
    'meta.name',
    'meta.desc',
    'userData.name',
    'userData.hostName',
    'userData.hostname',
    'reportedState.name',
    'reportedState.hostName',
    'reportedState.hostname',
    'reportedState.systemInfo.name',
    'reportedState.systemInfo.hostname',
    'hardwareId',
  ]), 180) || id;
  return {
    id,
    label,
    type: asText(host?.type || host?.hostType || '', 80),
  };
}

function slimSiteCounts(site) {
  const counts = nestedValue(site, ['statistics.counts', 'stats.counts', 'counts']);
  if (!counts || typeof counts !== 'object' || Array.isArray(counts)) return {};
  const wanted = [
    'totalClient',
    'wifiClient',
    'wiredClient',
    'guestClient',
    'vpnClient',
    'totalDevice',
    'offlineDevice',
    'gatewayDevice',
    'wifiDevice',
    'wiredDevice',
    'lanConfiguration',
    'wanConfiguration',
    'criticalNotification',
  ];
  const result = {};
  for (const key of wanted) {
    const value = Number(counts[key]);
    if (Number.isFinite(value)) result[key] = value;
  }
  return result;
}

function uniFiSiteKey(site) {
  const hostId = asText(site?.hostId || site?.host_id || site?.host?.id || site?.host?.hostId || '', 220);
  const siteId = asText(site?.siteId || site?.site_id || site?._id || site?.id || site?.meta?.id || '', 180);
  const name = asText(site?.name || site?.siteName || site?.site_name || site?.meta?.name || 'default', 160) || 'default';
  return `${hostId || 'local'}::${siteId || ''}::${name}`;
}

function slimUniFiSite(site) {
  const meta = site?.meta && typeof site.meta === 'object' ? site.meta : {};
  const name = asText(site?.name || meta.name || site?.site_name || site?.siteName || 'default', 160) || 'default';
  const hostId = asText(site?.hostId || site?.host_id || site?.host?.id || site?.host?.hostId || '', 220);
  const siteId = asText(site?.siteId || site?.site_id || site?._id || site?.id || meta.id || '', 180);
  const hostName = asText(site?.hostName || site?.hostLabel || site?.consoleName || nestedValue(site, [
    'host.name',
    'host.displayName',
    'host.hostName',
    'host.meta.name',
    'console.name',
    'console.displayName',
    'meta.hostName',
  ]), 180);
  const siteLabel = asText(site?.desc || meta.desc || site?.description || site?.displayName || name || siteId, 180);
  const label = [hostName, siteLabel].filter(Boolean).join(' / ') || siteLabel || name;
  if (!name && !label) return null;
  return {
    key: uniFiSiteKey({ name, hostId, siteId }),
    name: name || label,
    label: label || name,
    siteId,
    hostId,
    hostName,
    counts: slimSiteCounts(site),
    role: asText(site?.role || site?.permission || '', 80),
    source: asText(site?.source || (site?.meta ? 'site-manager' : 'network'), 80),
  };
}

function uniqueUniFiSites(sites, fallbackSite, fallbackHostId = '', fallbackSiteId = '') {
  const rows = [];
  const seen = new Set();
  for (const site of sites) {
    const normalized = slimUniFiSite(site);
    if (!normalized) continue;
    const key = normalized.key.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push(normalized);
  }
  const fallbackKey = uniFiSiteKey({ name: fallbackSite, hostId: fallbackHostId, siteId: fallbackSiteId });
  if (fallbackSite && !seen.has(fallbackKey.toLowerCase())) {
    rows.unshift({
      key: fallbackKey,
      name: fallbackSite,
      label: fallbackSite,
      siteId: fallbackSiteId,
      hostId: fallbackHostId,
      hostName: '',
      role: '',
      source: 'configured',
    });
  }
  return rows;
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

function slimSiteManagerDevice(device) {
  const status = String(device.status || device.state || '').toLowerCase();
  return {
    name: device.name || device.displayName || device.hostname || device.model || device.mac || '',
    type: device.type || device.deviceType || '',
    model: device.model || device.productLine || '',
    mac: device.mac || device.macAddress || '',
    ip: device.ip || device.ipAddress || '',
    state: ['online', 'connected', '1'].includes(status) ? 1 : 0,
    version: device.version || device.firmwareVersion || '',
    uptime: device.uptime || null,
    adopted: device.adopted,
  };
}

function slimUnifiClient(client) {
  const isWired = client.is_wired === true || client.isWired === true || client.type === 'WIRED' || client.radio === 'wired';
  const network = client.network_name || client.networkName || client.network || client.vlan_name || client.vlanName || client.usergroup_name || client.userGroupName || client.vlan || '';
  const essid = client.essid || client.ssid || client.wlan || client.wlan_name || client.wlanName || '';
  return {
    name: client.hostname || client.name || client.displayName || client.mac || client._id || '',
    mac: client.mac || client.macAddress || '',
    ip: client.ip || client.ip_address || client.ipAddress || '',
    network: network ? String(network) : '',
    radio: client.radio || client.radio_proto || client.radioProto || (isWired ? 'Wired' : essid ? 'Wireless' : ''),
    essid,
    uptime: client.uptime || client._uptime || client.assoc_time || null,
    rxBytes: firstFiniteNumber([
      client.rx_bytes,
      client.rxBytes,
      client.bytes_r,
      client['bytes-r'],
      client.wired_rx_bytes,
      client['wired-rx_bytes'],
      client.downloadBytes,
      nestedValue(client, ['traffic.rxBytes', 'traffic.rx_bytes', 'statistics.rxBytes']),
    ]),
    txBytes: firstFiniteNumber([
      client.tx_bytes,
      client.txBytes,
      client.bytes_t,
      client['bytes-t'],
      client.wired_tx_bytes,
      client['wired-tx_bytes'],
      client.uploadBytes,
      nestedValue(client, ['traffic.txBytes', 'traffic.tx_bytes', 'statistics.txBytes']),
    ]),
  };
}

function slimNetworkIntegrationClient(client) {
  const network = nestedValue(client, ['network.name', 'networkName', 'network.id', 'networkId', 'vlan.name']);
  const wifi = nestedValue(client, ['wifi.ssid', 'wireless.ssid', 'ssid', 'ap.name', 'accessPoint.name']);
  return {
    name: client.name || client.displayName || client.hostname || client.macAddress || client.mac || client.id || '',
    mac: client.macAddress || client.mac || '',
    ip: client.ipAddress || client.ip || nestedValue(client, ['network.ipAddress', 'network.ip']) || '',
    network: network || '',
    radio: client.radio || nestedValue(client, ['wifi.radio', 'wireless.radio', 'connection.type', 'type']) || '',
    essid: wifi || '',
    uptime: client.uptime || client.connectedDuration || null,
    rxBytes: firstFiniteNumber([
      client.rxBytes,
      client.rx_bytes,
      client.downloadBytes,
      client.receivedBytes,
      nestedValue(client, ['traffic.rxBytes', 'traffic.downBytes', 'traffic.downloadBytes', 'statistics.rxBytes']),
    ]),
    txBytes: firstFiniteNumber([
      client.txBytes,
      client.tx_bytes,
      client.uploadBytes,
      client.transmittedBytes,
      nestedValue(client, ['traffic.txBytes', 'traffic.upBytes', 'traffic.uploadBytes', 'statistics.txBytes']),
    ]),
  };
}

function countBy(rows, selector, fallback = 'Unknown') {
  const counts = new Map();
  for (const row of rows || []) {
    const key = asText(selector(row), 100) || fallback;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function findSelectedUniFiSite(sites, selectedSiteKey, siteName, hostId, siteId) {
  const expectedKey = uniFiSiteKey({ name: siteName, hostId, siteId });
  const targetName = normalizeTextKey(siteName);
  return (sites || []).find(site => site.key === selectedSiteKey)
    || (sites || []).find(site => site.key === expectedKey)
    || (sites || []).find(site => site.hostId === hostId && site.siteId === siteId && normalizeTextKey(site.name) === targetName)
    || (sites || []).find(site => site.hostId === hostId && normalizeTextKey(site.name) === targetName)
    || (sites || []).find(site => normalizeTextKey(site.name) === targetName)
    || null;
}

function summarizeSiteClientCounts(site) {
  const counts = site?.counts || {};
  const wifi = firstFiniteNumber([counts.wifiClient], 0);
  const wired = firstFiniteNumber([counts.wiredClient], 0);
  const vpn = firstFiniteNumber([counts.vpnClient], 0);
  const guest = firstFiniteNumber([counts.guestClient], 0);
  const totalFromCounts = firstFiniteNumber([counts.totalClient], NaN);
  const inferredTotal = wifi + wired + vpn;
  const total = Number.isFinite(totalFromCounts) ? totalFromCounts : inferredTotal;
  const rows = [
    { name: 'Wi-Fi', count: wifi },
    { name: 'Wired', count: wired },
    { name: 'VPN', count: vpn },
    { name: 'Guest', count: guest },
  ].filter(item => item.count > 0);
  if (total > inferredTotal) rows.push({ name: 'Other', count: total - inferredTotal });
  return { total, wifi, wired, vpn, guest, rows };
}

function summarizeUniFiOverview({ devices, clients, health, events, alarms, endpoints, sysinfo, clientSource, siteClientSummary }) {
  const onlineDevices = (devices || []).filter(device => device.state === 1 || device.state === '1').length;
  const totalRxBytes = (clients || []).reduce((sum, client) => sum + firstFiniteNumber([client.rxBytes]), 0);
  const totalTxBytes = (clients || []).reduce((sum, client) => sum + firstFiniteNumber([client.txBytes]), 0);
  const clientRows = (clients || []).length;
  const summaryRows = siteClientSummary?.rows || [];
  return {
    clientSource,
    controllerVersion: asText(sysinfo?.version || sysinfo?.build || sysinfo?.system_version || '', 80),
    devicesOnline: onlineDevices,
    devicesOffline: Math.max(0, (devices || []).length - onlineDevices),
    deviceTypes: countBy(devices, device => device.type || device.model).slice(0, 8),
    deviceVersions: countBy(devices, device => device.version).slice(0, 8),
    clientNetworks: countBy(clients, client => client.network || client.essid || client.radio).slice(0, 8),
    clientRadios: clientRows ? countBy(clients, client => client.radio || (client.essid ? 'Wireless' : 'Wired')).slice(0, 8) : summaryRows,
    clientSsids: countBy(clients, client => client.essid).filter(item => item.name !== 'Unknown').slice(0, 8),
    siteClientSummary,
    clientTraffic: { rxBytes: totalRxBytes, txBytes: totalTxBytes },
    healthStatuses: countBy(health, row => row.status || row.state || row.subsystem).slice(0, 8),
    healthSubsystems: countBy(health, row => row.subsystem || row.name || row.status).slice(0, 8),
    eventSources: countBy(events, event => event.subsystem || event.device).slice(0, 8),
    alarmSources: countBy(alarms, alarm => alarm.subsystem || alarm.device).slice(0, 8),
    endpointChecks: {
      total: (endpoints || []).length,
      ok: (endpoints || []).filter(endpoint => endpoint.ok).length,
      failed: (endpoints || []).filter(endpoint => !endpoint.ok).length,
    },
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
  const baseUrl = cleanBaseUrl(stringSetting('unifiUrl', 'UNIFI_URL', '', 600));
  const username = stringSetting('unifiUsername', 'UNIFI_USERNAME', '', 160);
  const password = stringSetting('unifiPassword', 'UNIFI_PASSWORD', '', 1000);
  const apiKey = stringSetting('unifiApiKey', 'UNIFI_API_KEY', '', 4000);
  const unifiSite = stringSetting('unifiSite', 'UNIFI_SITE', 'default', 120) || 'default';
  const unifiHostId = stringSetting('unifiHostId', 'UNIFI_HOST_ID', '', 220);
  const unifiSiteId = stringSetting('unifiSiteId', 'UNIFI_SITE_ID', '', 180);
  const selectedSiteKey = uniFiSiteKey({ name: unifiSite, hostId: unifiHostId, siteId: unifiSiteId });
  const unifiInsecure = boolSetting('unifiInsecure', 'UNIFI_INSECURE', true);
  if (!baseUrl || (!apiKey && (!username || !password))) {
    return {
      configured: false,
      ok: false,
      baseUrl,
      site: unifiSite,
      siteKey: selectedSiteKey,
      hostId: unifiHostId,
      siteId: unifiSiteId,
      sites: uniqueUniFiSites([{ name: unifiSite, desc: unifiSite, hostId: unifiHostId, siteId: unifiSiteId }], unifiSite, unifiHostId, unifiSiteId),
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
    const loginPaths = parseList(stringSetting('unifiLoginPaths', 'UNIFI_LOGIN_PATHS', '/api/auth/login,/api/login', 500));
    let loggedIn = false;
    let lastError = '';
    for (const loginPath of loginPaths) {
      try {
        const response = await requestJson(resolveUrl(baseUrl, loginPath), {
          method: 'POST',
          json: { username, password, remember: true },
          timeoutMs: API_TIMEOUT_MS,
          maxBytes: 512 * 1024,
          insecure: unifiInsecure,
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
      return {
        configured: true,
        ok: false,
        baseUrl,
        site: unifiSite,
        siteKey: selectedSiteKey,
        hostId: unifiHostId,
        siteId: unifiSiteId,
        sites: uniqueUniFiSites([{ name: unifiSite, desc: unifiSite, hostId: unifiHostId, siteId: unifiSiteId }], unifiSite, unifiHostId, unifiSiteId),
        error: `UniFi login failed: ${lastError}`,
        endpoints: [],
      };
    }
  }

  function currentHeaders() {
    const headers = { ...authHeaders };
    const cookie = cookieJar.header();
    if (cookie) headers.Cookie = cookie;
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    return headers;
  }

  async function requestUniFiJson(urlString, options = {}) {
    const response = await requestJson(urlString, {
      method: options.method || 'GET',
      json: options.json,
      headers: currentHeaders(),
      timeoutMs: API_TIMEOUT_MS,
      maxBytes: options.maxBytes || 2 * 1024 * 1024,
      insecure: unifiInsecure,
    });
    cookieJar.add(response.headers['set-cookie']);
    csrfToken = headerValue(response.headers, 'x-csrf-token') || csrfToken;
    if (response.status >= 400 || response.json?.meta?.rc === 'error') throw httpStatusError(options.label || 'UniFi', response);
    return response;
  }

  async function collectUniFiSites() {
    const rows = [];
    const endpoints = [];
    let lastError = null;

    for (const prefix of parseUniFiPrefixes()) {
      const prefixClean = prefix.replace(/\/+$/, '');
      const pathname = `${prefixClean}/api/self/sites`.replace(/^\/?/, '/');
      try {
        const response = await requestUniFiJson(resolveUrl(baseUrl, pathname), { label: `UniFi ${pathname}` });
        const localSites = unifiData(response.json).map(site => ({ ...site, source: 'network' }));
        rows.push(...localSites);
        endpoints.push({ name: 'local sites', ok: true, path: pathname, count: localSites.length });
      } catch (err) {
        lastError = err;
        endpoints.push({ name: 'local sites', ok: false, path: pathname, error: err.message, status: err.status || null });
      }
    }

    if (apiKey) {
      async function requestSiteManagerRows(managerBaseUrl, pathnameBase, label, paged = false) {
        if (!paged) {
          const response = await requestUniFiJson(resolveUrl(managerBaseUrl, pathnameBase), {
            label,
            maxBytes: 4 * 1024 * 1024,
          });
          return {
            rows: unifiData(response.json),
            endpoint: { name: label, ok: true, path: `${managerBaseUrl}${pathnameBase}`, count: unifiData(response.json).length },
          };
        }

        const pageSize = 200;
        const collected = [];
        let nextToken = '';
        let lastPath = pathnameBase;
        for (let page = 0; page < 5; page += 1) {
          const query = new URLSearchParams({ pageSize: String(pageSize) });
          if (nextToken) query.set('nextToken', nextToken);
          const pathname = `${pathnameBase}?${query.toString()}`;
          lastPath = pathname;
          const response = await requestUniFiJson(resolveUrl(managerBaseUrl, pathname), {
            label,
            maxBytes: 4 * 1024 * 1024,
          });
          const pageRows = unifiData(response.json);
          collected.push(...pageRows);
          nextToken = asText(response.json?.nextToken || response.json?.data?.nextToken || '', 600);
          if (!nextToken || pageRows.length < pageSize) break;
        }
        return {
          rows: collected,
          endpoint: { name: label, ok: true, path: `${managerBaseUrl}${lastPath}`, count: collected.length },
        };
      }

      for (const managerBaseUrl of siteManagerApiBaseUrls(baseUrl)) {
        const hostsById = new Map();
        for (const source of [
          { pathname: '/v1/hosts', label: 'site manager hosts', paged: true },
          { pathname: '/ea/hosts', label: 'site manager hosts legacy', paged: false },
        ]) {
          try {
            const result = await requestSiteManagerRows(managerBaseUrl, source.pathname, source.label, source.paged);
            const hosts = result.rows.map(slimUniFiHost).filter(Boolean);
            for (const host of hosts) hostsById.set(host.id, host);
            endpoints.push({ ...result.endpoint, count: hosts.length });
          } catch (err) {
            lastError = err;
            endpoints.push({ name: source.label, ok: false, path: `${managerBaseUrl}${source.pathname}`, error: err.message, status: err.status || null });
          }
        }

        for (const source of [
          { pathname: '/v1/sites', label: 'site manager sites', paged: true },
          { pathname: '/ea/sites', label: 'site manager sites legacy', paged: false },
        ]) {
          try {
            const result = await requestSiteManagerRows(managerBaseUrl, source.pathname, source.label, source.paged);
            const managerSites = result.rows.map(site => {
              const hostId = asText(site?.hostId || site?.host_id || site?.host?.id || site?.host?.hostId || '', 220);
              const host = hostsById.get(hostId);
              return { ...site, hostName: site?.hostName || site?.hostLabel || host?.label || '', source: 'site-manager' };
            });
            rows.push(...managerSites);
            endpoints.push({ ...result.endpoint, count: managerSites.length });
          } catch (err) {
            lastError = err;
            endpoints.push({ name: source.label, ok: false, path: `${managerBaseUrl}${source.pathname}`, error: err.message, status: err.status || null });
          }
        }
      }
    }

    const sites = uniqueUniFiSites(rows, unifiSite, unifiHostId, unifiSiteId);
    return {
      sites,
      endpoints: endpoints.length ? endpoints : [{
        name: 'sites',
        ok: false,
        error: lastError?.message || 'No UniFi sites endpoint was checked',
      }],
    };
  }

  async function collectSiteManagerDevices() {
    if (!apiKey || !unifiHostId) return { devices: [], endpoint: null };
    let lastError = null;

    for (const managerBaseUrl of siteManagerApiBaseUrls(baseUrl)) {
      const query = new URLSearchParams();
      query.append('hostIds[]', unifiHostId);
      const pathname = `/v1/devices?${query.toString()}`;
      try {
        const response = await requestUniFiJson(resolveUrl(managerBaseUrl, pathname), {
          label: 'UniFi Site Manager devices',
          maxBytes: 6 * 1024 * 1024,
        });
        const rows = [];
        for (const item of unifiData(response.json)) {
          if (Array.isArray(item?.devices)) rows.push(...item.devices);
          else rows.push(item);
        }
        return {
          devices: rows.map(slimSiteManagerDevice),
          endpoint: { name: 'site manager devices', ok: true, path: `${managerBaseUrl}${pathname}`, count: rows.length },
        };
      } catch (err) {
        lastError = err;
      }
    }

    return {
      devices: [],
      endpoint: { name: 'site manager devices', ok: false, error: lastError?.message || 'No Site Manager device data', status: lastError?.status || null },
    };
  }

  async function requestNetworkIntegrationClientPages(baseUrlForRequest, pathnameForPage, pathForLabel) {
    const limit = 200;
    const rows = [];
    for (let offset = 0; offset < 1000; offset += limit) {
      const pathname = pathnameForPage(offset, limit);
      const response = await requestUniFiJson(resolveUrl(baseUrlForRequest, pathname), {
        label: 'UniFi Network clients',
        maxBytes: 8 * 1024 * 1024,
      });
      const pageRows = unifiData(response.json);
      rows.push(...pageRows);
      const total = firstFiniteNumber([
        response.json?.total,
        response.json?.count,
        response.json?.totalCount,
        response.json?.data?.total,
        response.json?.data?.count,
        response.json?.data?.totalCount,
        response.json?.pagination?.total,
        response.json?.meta?.total,
      ], NaN);
      if (!pageRows.length || pageRows.length < limit || (Number.isFinite(total) && rows.length >= total)) {
        return {
          clients: rows.map(slimNetworkIntegrationClient),
          endpoint: { name: 'network clients', ok: true, path: pathForLabel || pathname, count: rows.length },
        };
      }
    }

    return {
      clients: rows.map(slimNetworkIntegrationClient),
      endpoint: { name: 'network clients', ok: true, path: pathForLabel || 'network integration clients', count: rows.length },
    };
  }

  async function requestNetworkIntegrationSites(baseUrlForRequest, basePath, pathForLabel) {
    const limit = 200;
    const sites = [];
    let lastPath = basePath;
    for (let offset = 0; offset < 1000; offset += limit) {
      const separator = basePath.includes('?') ? '&' : '?';
      const pathname = `${basePath}${separator}limit=${limit}&offset=${offset}`;
      lastPath = pathname;
      const response = await requestUniFiJson(resolveUrl(baseUrlForRequest, pathname), {
        label: 'UniFi Network sites',
        maxBytes: 4 * 1024 * 1024,
      });
      const pageRows = unifiData(response.json);
      sites.push(...pageRows);
      const total = firstFiniteNumber([
        response.json?.total,
        response.json?.count,
        response.json?.totalCount,
        response.json?.data?.total,
        response.json?.data?.count,
        response.json?.data?.totalCount,
        response.json?.pagination?.total,
        response.json?.meta?.total,
      ], NaN);
      if (!pageRows.length || pageRows.length < limit || (Number.isFinite(total) && sites.length >= total)) break;
    }
    return {
      sites,
      endpoint: { name: 'network sites', ok: true, path: pathForLabel || lastPath, count: sites.length },
    };
  }

  async function collectNetworkIntegrationClients() {
    if (!apiKey) return { clients: [], endpoint: null, legacySiteNames: [] };
    const siteRows = [];
    const endpoints = [];
    const connectorPrefixes = ['network', 'proxy/network'];

    let lastError = null;
    if (unifiHostId) {
      for (const managerBaseUrl of siteManagerApiBaseUrls(baseUrl)) {
        for (const connectorPrefix of connectorPrefixes) {
          const sitesPath = `/v1/connector/consoles/${encodeURIComponent(unifiHostId)}/${connectorPrefix}/integration/v1/sites`;
          try {
            const result = await requestNetworkIntegrationSites(managerBaseUrl, sitesPath, `${managerBaseUrl}${sitesPath}`);
            siteRows.push(...result.sites);
            endpoints.push(result.endpoint);
            if (result.sites.length) break;
          } catch (err) {
            lastError = err;
          }
        }
      }
    }

    for (const prefix of parseUniFiPrefixes()) {
      const prefixClean = prefix.replace(/\/+$/, '');
      const sitesPath = `${prefixClean}/integration/v1/sites`.replace(/^\/?/, '/');
      try {
        const result = await requestNetworkIntegrationSites(baseUrl, sitesPath, sitesPath);
        siteRows.push(...result.sites);
        endpoints.push(result.endpoint);
      } catch (err) {
        lastError = err;
      }
    }

    const selectedTokens = new Set(uniqueTextValues([unifiSite, unifiSiteId, 'default'], 180).map(normalizeTextKey));
    const siteMatchesSelection = site => {
      const identifiers = [
        ...networkIntegrationSiteIds(site),
        ...networkIntegrationLegacyRefs(site),
        networkIntegrationSiteName(site),
      ].map(normalizeTextKey).filter(Boolean);
      return !identifiers.length || identifiers.some(value => selectedTokens.has(value));
    };
    const matchedSites = siteRows.filter(siteMatchesSelection);
    const selectedSiteRows = matchedSites.length ? matchedSites : siteRows.length === 1 ? siteRows : [];
    const networkSiteIds = uniqueTextValues([
      ...(looksLikeUuid(unifiSiteId) ? [unifiSiteId] : []),
      ...selectedSiteRows.flatMap(networkIntegrationSiteIds),
      ...(selectedSiteRows.length ? [] : siteRows.flatMap(networkIntegrationSiteIds)),
    ], 180).filter(looksLikeUuid);
    const legacySiteNames = uniqueTextValues([
      unifiSite,
      'default',
      ...selectedSiteRows.flatMap(networkIntegrationLegacyRefs),
    ], 180).filter(value => value && !looksLikeUuid(value));
    const emptySuccesses = [];

    if (!networkSiteIds.length && siteRows.length) {
      endpoints.push({
        name: 'network clients',
        ok: false,
        error: 'Network sites were discovered, but no UUID site id was available for /v1/sites/{siteId}/clients',
      });
    }

    if (unifiHostId) {
      for (const managerBaseUrl of siteManagerApiBaseUrls(baseUrl)) {
        for (const siteId of networkSiteIds) {
          for (const connectorPrefix of connectorPrefixes) {
            const basePath = `/v1/connector/consoles/${encodeURIComponent(unifiHostId)}/${connectorPrefix}/integration/v1/sites/${encodeURIComponent(siteId)}/clients`;
            try {
              const result = await requestNetworkIntegrationClientPages(
                managerBaseUrl,
                (offset, limit) => `${basePath}?limit=${limit}&offset=${offset}`,
                `${managerBaseUrl}${basePath}`,
              );
              endpoints.push(result.endpoint);
              if (result.clients.length) return { ...result, endpoints, legacySiteNames, networkSiteIds };
              emptySuccesses.push(result);
            } catch (err) {
              lastError = err;
              endpoints.push({ name: 'network clients', ok: false, path: `${managerBaseUrl}${basePath}`, error: err.message, status: err.status || null });
            }
          }
        }
      }
    }

    for (const prefix of parseUniFiPrefixes()) {
      const prefixClean = prefix.replace(/\/+$/, '');
      for (const siteId of networkSiteIds) {
        const basePath = `${prefixClean}/integration/v1/sites/${encodeURIComponent(siteId)}/clients`.replace(/^\/?/, '/');
        try {
          const result = await requestNetworkIntegrationClientPages(
            baseUrl,
            (offset, limit) => `${basePath}?limit=${limit}&offset=${offset}`,
            basePath,
          );
          endpoints.push(result.endpoint);
          if (result.clients.length) return { ...result, endpoints, legacySiteNames, networkSiteIds };
          emptySuccesses.push(result);
        } catch (err) {
          lastError = err;
          endpoints.push({ name: 'network clients', ok: false, path: basePath, error: err.message, status: err.status || null });
        }
      }
    }

    if (emptySuccesses.length) {
      const best = emptySuccesses[0];
      return { ...best, endpoints, legacySiteNames, networkSiteIds };
    }

    return {
      clients: [],
      legacySiteNames,
      networkSiteIds,
      endpoints: endpoints.length ? endpoints : undefined,
      endpoint: {
        name: 'network clients',
        ok: false,
        error: lastError?.message || 'No Network Integration clients endpoint worked',
        status: lastError?.status || null,
      },
    };
  }

  async function collectConnectorLegacyClients(extraSiteNames = []) {
    if (!apiKey || !unifiHostId) return { clients: [], endpoint: null };
    const siteNames = uniqueTextValues([unifiSite, 'default', ...extraSiteNames], 180)
      .filter(value => value && !looksLikeUuid(value));
    const resources = ['stat/sta', 'stat/alluser', 'rest/user', 'list/user'];
    const endpoints = [];
    const emptySuccesses = [];
    let lastError = null;

    for (const managerBaseUrl of siteManagerApiBaseUrls(baseUrl)) {
      for (const siteName of siteNames) {
        for (const connectorPrefix of ['network', 'proxy/network']) {
          for (const resource of resources) {
            const pathname = `/v1/connector/consoles/${encodeURIComponent(unifiHostId)}/${connectorPrefix}/api/s/${encodeURIComponent(siteName)}/${resource}`;
            try {
              const response = await requestUniFiJson(resolveUrl(managerBaseUrl, pathname), {
                label: 'UniFi connector legacy clients',
                maxBytes: 8 * 1024 * 1024,
              });
              const clients = unifiData(response.json).map(slimUnifiClient);
              const endpoint = { name: 'connector legacy clients', ok: true, path: `${managerBaseUrl}${pathname}`, count: clients.length };
              endpoints.push(endpoint);
              if (clients.length) return { clients, endpoint, endpoints };
              emptySuccesses.push({ clients, endpoint });
            } catch (err) {
              lastError = err;
              endpoints.push({ name: 'connector legacy clients', ok: false, path: `${managerBaseUrl}${pathname}`, error: err.message, status: err.status || null });
            }
          }
        }
      }
    }

    if (emptySuccesses.length) {
      const best = emptySuccesses[0];
      return { ...best, endpoints };
    }

    return {
      clients: [],
      endpoints,
      endpoint: { name: 'connector legacy clients', ok: false, error: lastError?.message || 'No connector legacy clients endpoint worked', status: lastError?.status || null },
    };
  }

  async function callUniFi(resource, options = {}) {
    const prefixes = parseUniFiPrefixes();
    const methods = options.body ? ['POST', 'GET'] : ['GET'];
    let lastError = null;

    for (const prefix of prefixes) {
      const prefixClean = prefix.replace(/\/+$/, '');
      const pathname = `${prefixClean}/api/s/${encodeURIComponent(unifiSite)}/${resource}`.replace(/^\/?/, '/');
      for (const method of methods) {
        try {
          const response = await requestUniFiJson(resolveUrl(baseUrl, pathname), {
            method,
            json: method === 'POST' ? options.body : undefined,
            maxBytes: options.maxBytes || 2 * 1024 * 1024,
            label: `UniFi ${pathname}`,
          });
          return { path: pathname, json: response.json };
        } catch (err) {
          lastError = err;
        }
      }
    }
    throw lastError || new Error(`UniFi ${resource} failed`);
  }

  const siteResult = await collectUniFiSites();
  const siteManagerDeviceResult = await collectSiteManagerDevices();
  const networkClientResult = await collectNetworkIntegrationClients();
  const connectorLegacyClientResult = await collectConnectorLegacyClients(networkClientResult.legacySiteNames || []);
  const names = ['health', 'sysinfo', 'devices', 'legacy clients', 'events', 'alarms'];
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
  const localDevices = unifiData(settledValue(calls[2], {}).json || settledValue(calls[2], {})).map(slimUnifiDevice);
  const devices = unifiHostId && siteManagerDeviceResult.endpoint?.ok ? siteManagerDeviceResult.devices : localDevices;
  const legacyClients = unifiData(settledValue(calls[3], {}).json || settledValue(calls[3], {})).map(slimUnifiClient);
  const clients = networkClientResult.clients?.length
    ? networkClientResult.clients
    : connectorLegacyClientResult.clients?.length
      ? connectorLegacyClientResult.clients
      : legacyClients;
  const selectedSite = findSelectedUniFiSite(siteResult.sites, selectedSiteKey, unifiSite, unifiHostId, unifiSiteId);
  const siteClientSummary = summarizeSiteClientCounts(selectedSite);
  const hasSiteClientSummary = !clients.length && siteClientSummary.total > 0;
  const clientSource = networkClientResult.clients?.length
    ? 'network integration'
    : connectorLegacyClientResult.clients?.length
      ? 'connector legacy'
      : legacyClients.length
        ? 'legacy'
        : hasSiteClientSummary
          ? 'site manager summary'
        : networkClientResult.endpoint?.ok
          ? 'network integration'
          : connectorLegacyClientResult.endpoint?.ok
            ? 'connector legacy'
            : 'legacy';
  const events = unifiData(settledValue(calls[4], {}).json || settledValue(calls[4], {})).map(slimUnifiEvent).slice(0, 120);
  const alarms = unifiData(settledValue(calls[5], {}).json || settledValue(calls[5], {})).map(slimUnifiEvent).slice(0, 120);
  const dataEndpoints = names.map((name, index) => endpointResult(name, calls[index]));
  const endpoints = [
    ...siteResult.endpoints,
    ...dataEndpoints,
    ...(siteManagerDeviceResult.endpoint ? [siteManagerDeviceResult.endpoint] : []),
    ...(networkClientResult.endpoints?.length ? networkClientResult.endpoints : networkClientResult.endpoint ? [networkClientResult.endpoint] : []),
    ...(connectorLegacyClientResult.endpoints?.length ? connectorLegacyClientResult.endpoints : connectorLegacyClientResult.endpoint ? [connectorLegacyClientResult.endpoint] : []),
  ];
  const ok = endpoints.some(endpoint => endpoint.ok);
  const overview = summarizeUniFiOverview({ devices, clients, health, events, alarms, endpoints, sysinfo, clientSource, siteClientSummary });
  const clientTotal = clients.length || siteClientSummary.total || 0;

  return {
    configured: true,
    ok,
    baseUrl,
    site: unifiSite,
    siteKey: selectedSiteKey,
    hostId: unifiHostId,
    siteId: unifiSiteId,
    sites: siteResult.sites,
    collectedAt: new Date().toISOString(),
    sysinfo,
    health,
    overview,
    devices: {
      total: devices.length,
      offline: devices.filter(device => device.state !== 1 && device.state !== '1').length,
      rows: devices.slice(0, 100),
    },
    clients: {
      total: clientTotal,
      source: clientSource,
      summary: siteClientSummary,
      rows: clients.slice(0, 100),
    },
    events,
    alarms,
    endpoints,
  };
}

async function collectDashboard() {
  const [nas, homeAssistant, unifi, sites, wake] = await Promise.all([
    collectNasSnapshot().catch(err => ({ configured: true, ok: false, error: err.message })),
    collectHomeAssistant().catch(err => ({ configured: true, ok: false, error: err.message })),
    collectUniFi().catch(err => ({ configured: true, ok: false, error: err.message })),
    checkAllSites().catch(err => ({ total: 0, up: 0, down: 0, disabled: 0, sites: [], error: err.message })),
    Promise.resolve().then(() => collectWakeSnapshot()).catch(err => ({ total: 0, enabled: 0, disabled: 0, devices: [], log: [], error: err.message })),
  ]);

  return {
    app: { name: APP_NAME, label: APP_LABEL },
    collectedAt: new Date().toISOString(),
    nas,
    homeAssistant,
    unifi,
    sites,
    wake,
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

app.get('/api/settings', requireAuth, requireAdmin, (_req, res) => {
  res.json({ settings: publicSettings() });
});

app.put('/api/settings', requireAuth, requireAdmin, (req, res) => {
  try {
    res.json({ settings: updateSettings(req.body || {}) });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Could not save settings' });
  }
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

app.get('/api/wol/devices', requireAuth, (_req, res) => {
  res.json({ devices: loadWakeDevices().map(publicWakeDevice) });
});

app.post('/api/wol/devices', requireAuth, requireAdmin, (req, res) => {
  try {
    const devices = loadWakeDevices();
    const device = normalizeDevice(req.body);
    device.id = uniqueWakeDeviceId(devices, req.body?.id || device.name);
    devices.push(device);
    writeWakeDevices(devices);
    res.status(201).json({ device: publicWakeDevice(device) });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Could not create device' });
  }
});

app.put('/api/wol/devices/:id', requireAuth, requireAdmin, (req, res) => {
  try {
    const devices = loadWakeDevices();
    const index = devices.findIndex(device => device.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Device not found' });
    const device = normalizeDevice({ ...devices[index], ...req.body, id: devices[index].id }, devices[index]);
    devices[index] = device;
    writeWakeDevices(devices);
    return res.json({ device: publicWakeDevice(device) });
  } catch (err) {
    return res.status(400).json({ error: err.message || 'Could not update device' });
  }
});

app.delete('/api/wol/devices/:id', requireAuth, requireAdmin, (req, res) => {
  const devices = loadWakeDevices();
  const nextDevices = devices.filter(device => device.id !== req.params.id);
  if (nextDevices.length === devices.length) return res.status(404).json({ error: 'Device not found' });
  writeWakeDevices(nextDevices);
  return res.json({ ok: true });
});

app.post('/api/wol/devices/:id/wake', requireAuth, async (req, res) => {
  const devices = loadWakeDevices();
  const index = devices.findIndex(device => device.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Device not found' });

  const device = devices[index];
  if (!device.enabled) return res.status(409).json({ error: 'Device is disabled' });

  const logBase = {
    at: new Date().toISOString(),
    deviceId: device.id,
    deviceName: device.name,
    mac: device.mac,
    broadcast: device.broadcast,
    port: device.port,
    username: req.user.username,
    displayName: req.user.display_name || req.user.username,
  };

  try {
    const attempts = await sendWakePacket(device);
    await delay(900);
    const status = await checkWakeDevice(device);
    const updatedAt = new Date().toISOString();
    devices[index] = {
      ...device,
      lastWakeAt: logBase.at,
      lastWakeBy: req.user.display_name || req.user.username,
      updatedAt,
    };
    writeWakeDevices(devices);
    appendWakeLog({ ...logBase, ok: true, attempts, status });
    return res.json({ ok: true, attempts, status, device: { ...publicWakeDevice(devices[index]), status } });
  } catch (err) {
    console.error(`[wol] Failed to wake ${device.name}:`, err.message);
    const attempts = Array.isArray(err.attempts) ? err.attempts : [];
    const status = await checkWakeDevice(device);
    appendWakeLog({ ...logBase, ok: false, error: err.message, attempts, status });
    return res.status(502).json({ error: `Could not send wake packet: ${err.message}`, attempts, status });
  }
});

app.get('/api/wol/wake-log', requireAuth, (_req, res) => {
  res.json({ entries: readWakeLog(100) });
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

app.get(['/', '/nas', '/home-assistant', '/unifi', '/wake', '/sites', '/logs', '/settings'], requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  return res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`[chempboard] ${APP_LABEL} running on port ${PORT}`);
});
