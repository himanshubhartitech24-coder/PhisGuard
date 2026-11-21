/**
 * PhishGuard Unified API & Hybrid Detection Client.
 * Communicates with the Python Flask backend whenever available,
 * and seamlessly provides full client-side evaluation fallback
 * for standalone cloud/Vercel deployments.
 */

import { 
  localAnalyzeEmail, 
  localAnalyzeUrl, 
  localGetStats, 
  localGetHistory 
} from './localEngine';

const API_BASE_URL = import.meta.env.VITE_API_URL || 
  (typeof window !== 'undefined' && window.location.hostname && window.location.port !== '5050'
    ? `http://${window.location.hostname}:5050/api` 
    : '/api');

export async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${API_BASE_URL}/health`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return { status: "standalone", mode: "Client Hybrid Engine Active", version: "1.0.0" };
  }
}

export async function analyzeEmailContent(payload) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // Backend offline or unreachable: use client-side detection engine
  }

  // Instant local evaluation
  return localAnalyzeEmail(payload);
}

export async function scanUrlEndpoint(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`${API_BASE_URL}/scan-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // Fallback to local lexical engine
  }

  return localAnalyzeUrl(url);
}

export async function getDashboardStats() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${API_BASE_URL}/stats`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // Fallback
  }

  return localGetStats();
}

export async function getScanHistory(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', params.limit);
    if (params.offset) query.set('offset', params.offset);
    if (params.filter && params.filter !== 'all') query.set('filter', params.filter);
    if (params.search) query.set('search', params.search);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${API_BASE_URL}/history?${query.toString()}`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // Fallback
  }

  return localGetHistory(params);
}

export async function getScanById(scanId) {
  try {
    const res = await fetch(`${API_BASE_URL}/history/${scanId}`);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // Fallback
  }

  const { items } = localGetHistory();
  return items.find(i => i.id == scanId) || null;
}

export async function deleteScanRecord(scanId) {
  try {
    const res = await fetch(`${API_BASE_URL}/history/${scanId}`, { method: 'DELETE' });
    if (res.ok) return await res.json();
  } catch (e) {}

  try {
    const existing = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
    const filtered = existing.filter(i => i.id != scanId);
    localStorage.setItem('phishguard_history', JSON.stringify(filtered));
  } catch (e) {}

  return { success: true };
}

export async function clearAllHistoryRecords() {
  try {
    await fetch(`${API_BASE_URL}/history`, { method: 'DELETE' });
  } catch (e) {}

  try {
    localStorage.removeItem('phishguard_history');
  } catch (e) {}

  return { success: true };
}
