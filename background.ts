import { saveLog } from './lib/log-storage';
import { scanScriptForAnomalies } from './background/script-analyzer';

// Suspicious patterns in URLs
const SUSPICIOUS_PARAMS = ['redirect', 'aff_id', 'token', 'base64', 'track', 'click', 'session'];
const TRACKER_DOMAINS = ['doubleclick.net', 'adnxs.com', 'google-analytics.com', 'tracking', 'pixel', 'affiliate'];

// 1️⃣ Watch outgoing web requests
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const url = details.url.toLowerCase();
    let riskLevel = 'low';
    let reason = '';

    // Detect trackers or suspicious parameters
    if (SUSPICIOUS_PARAMS.some(param => url.includes(param))) {
      riskLevel = 'medium';
      reason = 'Suspicious query parameter in URL.';
    }
    if (TRACKER_DOMAINS.some(domain => url.includes(domain))) {
      riskLevel = 'medium';
      reason = 'Known tracking or ad network detected.';
    }
    if (url.startsWith('http:')) {
      riskLevel = 'high';
      reason = 'Unsecured HTTP site detected.';
    }

    if (riskLevel !== 'low') {
      await saveLog({
        type: 'url_threat',
        severity: riskLevel,
        url,
        details: reason,
        detection_source: 'network_monitor'
      });
      console.log(⚠ [URL Threat] ${reason} → ${url});
    }
  },
  { urls: ["<all_urls>"] }
);

// 2️⃣ Optional: Script analysis for inline scripts
chrome.webNavigation.onCompleted.addListener(async (details) => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) return;
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        return Array.from(document.scripts).map(s => s.innerText).join('\n');
      }
    });
    const allScripts = result || '';
    const isSuspicious = scanScriptForAnomalies(allScripts, details.url);
    if (isSuspicious) {
      await saveLog({
        type: 'script_anomaly',
        severity: 'high',
        page: details.url,
        details: 'Detected high-risk script content.',
        detection_source: 'static_analysis'
      });
      console.log(🚨 [Script Analyzer] High-risk script detected at ${details.url});
    }
  } catch (err) {
    console.error('Script scan failed:', err);
  }
});