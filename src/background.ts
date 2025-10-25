// background.ts
// The main Background Service Worker (The Brain) for SafeSurfers.
// This file initializes all monitoring services.

// --- T1's Core Utilities (Imports from src/lib) ---
import { saveLog } from './lib/log-storage';

// --- T2/T4's Security Modules (Imports from src/background) ---
// NOTE: T2 will create/integrate these files later. We import them to start the functions.
import { startNetworkMonitoring } from './background/network-monitor';
import { runConflictCheck } from './background/conflict-checker';
import { scanScriptForAnomalies } from './background/script-analyser';


// --- Rule Definitions for Initial URL Scanner ---
const SUSPICIOUS_PARAMS = ['redirect', 'aff_id', 'token', 'base64', 'track', 'click', 'session'];
const TRACKER_DOMAINS = ['doubleclick.net', 'adnxs.com', 'google-analytics.com', 'tracking', 'pixel', 'affiliate'];


// ==========================================================
// 1. Core Monitoring Logic (Immediate Setup)
// ==========================================================

// 1.1 URL and Simple Tracker Scanner (Runs on every request)
chrome.webRequest.onBeforeRequest.addListener(
    async (details) => {
        const url = details.url.toLowerCase();
        let riskLevel = 'low';
        let reason = '';

        // Check 1: Suspicious Query Parameters
        if (SUSPICIOUS_PARAMS.some(param => url.includes(param))) {
            riskLevel = 'medium';
            reason = 'Suspicious query parameter detected.';
        }
        // Check 2: Unsecured HTTP Site
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
            console.log('https://en.wikipedia.org/wiki/Threat_%28computer_security%29', reason, '->', url);
        }
    },
    { urls: ["<all_urls>"] }
);


// 1.2 Script Analyzer Trigger (Runs on page load completion)
chrome.webNavigation.onCompleted.addListener(async (details) => {
    try {
        // Only run on the active, main frame
        if (details.frameId !== 0) return;
        
        // Use tabs.query to get the active tab ID
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.id) return;

        // Execute function to scrape the innerText of all inline scripts (T2/T4's "Eyes")
        const [{ result }] = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
                // Return all script content on the page for AST analysis
                return Array.from(document.scripts).map(s => s.innerText).join('\n');
            }
        });
        
        const allScripts = result || '';
        
        // Pass the scraped code to the powerful AST analyzer
        const isSuspicious = scanScriptForAnomalies(allScripts, details.url); 

        if (isSuspicious) {
            await saveLog({
                type: 'script_anomaly',
                severity: 'high',
                page: details.url,
                details: 'Detected high-risk obfuscated script content.',
                detection_source: 'static_analysis'
            });
            console.log('[Script Analyzer] High-risk script detected at', details.url);
        }
    } catch (err) {
        // Suppress benign errors, but log major ones
        if (err instanceof Error) {
            console.error('Script scan failed:', err.message);
        } else {
            console.error('Script scan failed:', err);
        }
    }
});


// ==========================================================
// 2. SERVICE INITIALIZATION (The Master Switch)
// ==========================================================

/**
 * Initializes all monitoring and checking services.
 * This runs immediately when the Service Worker starts.
 */
function initializeServices() {
    console.log("--- SAFESURFERS Core Services Initialized ---");
    
    // Start T2's Network Monitor (Upload volume checks, 5-second timers)
    // NOTE: This function is defined in src/background/network-monitor.ts
    startNetworkMonitoring(); 
    
    // Start T2's Extension Conflict Checker
    // NOTE: This function is defined in src/background/conflict-checker.ts
    runConflictCheck(); 
}

// Call the initialization function to start the entire extension
initializeServices();