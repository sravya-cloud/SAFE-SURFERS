// src/background/network-monitor.ts
// Monitors network traffic volume (upload bytes) and checks for simple URL anomalies.
// T2's core monitoring logic.

// --- T1's Core Utility Imports ---
import { saveLog } from '../lib/log-storage';
// --- T4's Anomaly Scoring Import ---
// NOTE: This assumes anomaly-scoring.ts exists in src/lib/ and exports getRiskLevel
import { getRiskLevel } from '../lib/anomaly-scoring'; 

// Define the expected structure of network request details for type safety
interface RequestDetails extends chrome.webRequest.WebRequestBodyDetails {
    url: string;
    requestHeaders: chrome.webRequest.HttpHeader[];
}

// Global Map to store total BYTES uploaded for each hostname
let hostUploadBytes = new Map<string, number>(); 

// Common affiliate query parameter patterns
const AFFILIATE_PATTERNS = [ 
    /(\?|&)affiliate_id=([^&]+)/i,
    /(\?|&)tag=([^&]+)/i,
    /(\?|&)partner_ref=([^&]+)/i,
    /(\?|&)ref=([^&]+)/i,
]; // <-- CRITICAL FIX: Added semicolon to terminate the const array declaration
;


/**
 * Logs the total bytes uploaded for each host and resets the counter.
 * Executed every 5 seconds by setInterval.
 */
function logAndResetUploadBytes(): void { 
    if (hostUploadBytes.size === 0) return;

    // Log all stored hostname byte counts
    for (let [host, bytes] of hostUploadBytes.entries()) {
        
        // Prepare T4's AI Inputs (using placeholders)
        const finalSeverity = getRiskLevel({
            requestCount: 0, 
            domainRepScore: 5, 
            obfuscationDetected: false, 
            dataExfilSize: bytes 
        });
        
        // Save the log with the final AI severity
        saveLog({
            type: 'network_statistic_upload',
            detection_source: 'upload_byte_counter',
            severity: finalSeverity, 
            timestamp: new Date().toISOString(),
            details: `Total bytes uploaded to ${host} in the last 5s: ${bytes}`,
            host: host,
            bytes_uploaded: bytes,
        }); 
    }

    // Reset the Map for the next 5-second window
    hostUploadBytes = new Map<string, number>(); 
    console.log("[5-Second Byte Count] Host-specific upload volume logged and reset."); 
}


/**
 * Sets up the listener to track uploaded bytes and check for affiliate tags.
 */
function setupNetworkMonitor(): void { 
    // Use onBeforeSendHeaders to get details about the request body size
    chrome.webRequest.onBeforeSendHeaders.addListener(
        (details: RequestDetails) => {
            // Ignore internal extension requests
            if (details.url.startsWith('chrome-extension://')) return { requestHeaders: details.requestHeaders };

            let destinationHost = '';
            try {
                destinationHost = new URL(details.url).hostname;
            } catch (e) {
                return { requestHeaders: details.requestHeaders };
            }

            // 1. Upload Volume Counter: Track total bytes uploaded
            const contentLengthHeader = details.requestHeaders.find(h => h.name.toLowerCase() === 'content-length');
            const uploadedBytes = contentLengthHeader ? parseInt(contentLengthHeader.value as string) : 0;

            if (uploadedBytes > 0) {
                const currentBytes = hostUploadBytes.get(destinationHost) || 0;
                hostUploadBytes.set(destinationHost, currentBytes + uploadedBytes);
            }

            // 2. Anomaly Check: Look for affiliate tag rewrites
            for (const pattern of AFFILIATE_PATTERNS) {
                const match = details.url.match(pattern);
                if (match) {
                    saveLog({
                        type: 'network_anomaly',
                        detection_source: 'webRequest_url',
                        url: details.url,
                        destination_host: destinationHost,
                        severity: 'HIGH', 
                        timestamp: new Date().toISOString(),
                        details: `Affiliate tag detected: ${match[0]}`,
                        rewritten_value: match[2],
                    });
                    break; 
                }
            }

            // onBeforeSendHeaders requires returning the headers object
            return { requestHeaders: details.requestHeaders };
        },
        { urls: ["<all_urls>"] },
        // 'blocking' is required to read headers synchronously
        ['requestHeaders']
    );
}

// Calls the monitor function and starts the 5-second timer
export function startNetworkMonitoring(): void { 
    setupNetworkMonitor(); 

    // Start the timer to log and reset the host byte counts every 5000 milliseconds (5 seconds)
    setInterval(logAndResetUploadBytes, 5000); 

    console.log("Network Upload Monitoring Active (5-Second Byte Counter Running)."); 
}
