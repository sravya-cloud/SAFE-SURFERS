// src/background/network-monitor.js
// Monitors network traffic volume and checks for affiliate tag rewriting.
import { saveLog } from '../lib/log-storage';
import { getRiskLevel } from '../lib/anomaly-scoring';

// NOTE: We assume the script analysis functions are now located here:
// import { scanScriptForAnomalies } from '../analysis/script-analyzer.js';

// Global Map to store total BYTES uploaded for each hostname
let hostUploadBytes = new Map();

// Common affiliate query parameter patterns
const AFFILIATE_PATTERNS = [
  /(\?|&)affiliate_id=([^&]+)/i,
  /(\?|&)tag=([^&]+)/i,
  /(\?|&)partner_ref=([^&]+)/i,
  /(\?|&)ref=([^&]+)/i,
];

/**
 * Logs the total bytes uploaded for each host and resets the counter.
 * Executed every 5 seconds by setInterval.
 */
function logAndResetUploadBytes() {
  if (hostUploadBytes.size === 0) return;

  // Log all stored hostname byte counts
  for (let [host, bytes] of hostUploadBytes.entries()) {
    // Flag a WARNING if a host uploads more than a set threshold (e.g., 5MB in 5 seconds)
    const threshold = 5 * 1024 * 1024; // 5 MB threshold
    const severity = (bytes >threshold) ? 'warning' : 'info';
    
    saveLog({
      type: 'network_statistic_upload',
      detection_source: 'upload_byte_counter',
      severity: severity,
      timestamp: new Date().toISOString(),
      details: Total bytes uploaded to ${host} in the last 5s: ${bytes},
      host: host,
      bytes_uploaded: bytes,
    });
  }
  
  // Reset the Map for the next 5-second window
  hostUploadBytes = new Map();
  console.log("[5-Second Byte Count] Host-specific upload volume logged and reset.");
}


/**
 * Sets up the listener to track uploaded bytes and check for affiliate tags.
 */
function setupNetworkMonitor() {
  // Use onBeforeSendHeaders to get details about the request body size
  chrome.webRequest.onBeforeSendHeaders.addListener(
    (details) => {
      // Ignore internal extension requests
      if (details.url.startsWith('chrome-extension://')) return;
      
      let destinationHost = '';
      try {
        destinationHost = new URL(details.url).hostname;
      } catch (e) {
        // Return headers even if URL parsing fails
        return { requestHeaders: details.requestHeaders }; 
      }
      
      // 1. Upload Volume Counter: Track total bytes uploaded
      // Look for the Content-Length header to estimate data size
      const contentLengthHeader = details.requestHeaders.find(h => h.name.toLowerCase() === 'content-length');
      const uploadedBytes = contentLengthHeader ? parseInt(contentLengthHeader.value) : 0;
      
      if (uploadedBytes > 0) {
        const currentBytes = hostUploadBytes.get(destinationHost) || 0;
        hostUploadBytes.set(destinationHost, currentBytes + uploadedBytes);
      }

      // 2. Anomaly Check: Look for affiliate tag rewrites
      for (const pattern of AFFILIATE_PATTERNS) {
        const match = details.url.match(pattern);
        if (match) {
          // Log a high-severity event for suspicious tag injection/rewrite
          saveLog({
            type: 'network_anomaly',
            detection_source: 'webRequest_url',
            url: details.url,
            destination_host: destinationHost,
            severity: 'high',
            timestamp: new Date().toISOString(),
            details: Affiliate tag detected: ${match[0]},
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
    ['requestHeaders', 'blocking'] 
  );
  
  // NOTE on Script Analysis:
  // To use scanScriptForAnomalies here, you would need to retrieve the script content first.
  // This typically requires a different listener (like webRequest.onResponseStarted) 
  // and complicated stream handling, which is beyond the scope of this file.
  // The function is best called from a Content Script or an Analysis Worker 
  // once the script content is successfully captured.
}

// Calls the monitor function and starts the 5-second timer
export function startNetworkMonitoring() {
    setupNetworkMonitor();
    
    // Start the timer to log and reset the host byte counts every 5000 milliseconds (5 seconds)
    setInterval(logAndResetUploadBytes, 5000);

    console.log("Network Upload Monitoring Active (5-Second Byte Counter Running).");
}