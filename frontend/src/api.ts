import type { AuditEvent, IpRecord, User } from './types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';

interface AuthResponse {
  user: User;
  accessToken: string;
  refreshToken: string;
}

function getStoredAccessToken() {
  return localStorage.getItem('accessToken');
}

function getStoredRefreshToken() {
  return localStorage.getItem('refreshToken');
}

function storeTokens(accessToken: string, refreshToken: string) {
  localStorage.setItem('accessToken', accessToken);
  localStorage.setItem('refreshToken', refreshToken);
}

function storeUser(user: User) {
  localStorage.setItem('user', JSON.stringify(user));
  localStorage.setItem('userRole', user.role);
}

function clearTokens() {
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  localStorage.removeItem('user');
  localStorage.removeItem('userRole');
}

export function getStoredUser(): User | null {
  const stored = localStorage.getItem('user');
  return stored ? (JSON.parse(stored) as User) : null;
}

async function refreshSession() {
  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  const response = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken }),
  });

  if (!response.ok) {
    clearTokens();
    throw new Error('Session refresh failed');
  }

  const payload = (await response.json()) as AuthResponse;
  storeTokens(payload.accessToken, payload.refreshToken);
  return payload.accessToken;
}

const AUTH_ENDPOINTS = ['/api/auth/login', '/api/auth/refresh', '/api/auth/logout'];

async function request<T>(path: string, options: RequestInit = {}, retry = true): Promise<T> {
  const accessToken = getStoredAccessToken();
  const headers = { 'Content-Type': 'application/json', ...(options.headers ?? {}) } as Record<string, string>;
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && retry && !AUTH_ENDPOINTS.some((endpoint) => path.startsWith(endpoint))) {
    const refreshedToken = await refreshSession();
    return request<T>(path, { ...options, headers: { ...headers, Authorization: `Bearer ${refreshedToken}` } }, false);
  }

  if (response.status === 204) {
    return {} as T;
  }

  const responseBody = await response.json();
  if (!response.ok) {
    throw new Error(responseBody.message || 'Request failed');
  }

  return responseBody as T;
}

export async function login(email: string, password: string): Promise<User> {
  const payload = await request<AuthResponse>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  storeTokens(payload.accessToken, payload.refreshToken);
  storeUser(payload.user);
  return payload.user;
}

export async function logout(): Promise<void> {
  const refreshToken = getStoredRefreshToken();
  if (refreshToken) {
    await request('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    });
  }
  clearTokens();
}

export async function refreshTokenIfNeeded(): Promise<User> {
  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  const response = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken }),
  });

  if (!response.ok) {
    clearTokens();
    throw new Error('Session refresh failed');
  }

  const payload = (await response.json()) as AuthResponse;
  storeTokens(payload.accessToken, payload.refreshToken);
  storeUser(payload.user);
  return payload.user;
}

export async function fetchIpRecords(): Promise<IpRecord[]> {
  return request<IpRecord[]>('/api/ips');
}

export async function addIpRecord(ip: string, label: string, comment: string): Promise<IpRecord> {
  return request<IpRecord>('/api/ips', {
    method: 'POST',
    body: JSON.stringify({ ip, label, comment }),
  });
}

export async function updateIpLabel(id: number, label: string): Promise<IpRecord> {
  return request<IpRecord>(`/api/ips/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ label }),
  });
}

export async function deleteIpRecord(id: number): Promise<void> {
  await request(`/api/ips/${id}`, { method: 'DELETE' });
}

export async function fetchAuditLog(): Promise<AuditEvent[]> {
  return request<AuditEvent[]>('/api/audit');
}

export function getStoredUserRole(): string {
  return localStorage.getItem('userRole') ?? '';
}

export function storeUserRole(role: string): void {
  localStorage.setItem('userRole', role);
}
