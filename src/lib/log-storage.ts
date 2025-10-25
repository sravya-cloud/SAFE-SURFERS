// File: src/lib/log-storage.ts
const LOG_KEY = 'security_logs'; 

// T2 uses this to save a new security event
export async function saveLog(newLogEntry: any) {
  const { [LOG_KEY]: currentLogs } = await chrome.storage.local.get(LOG_KEY);
  const logsArray = Array.isArray(currentLogs) ? currentLogs : [];
  const fullLog = { ...newLogEntry, timestamp: Date.now() }; 
  const updatedLogs = [fullLog, ...logsArray]; 
  await chrome.storage.local.set({ [LOG_KEY]: updatedLogs });
}

// T3 and T4 use this to retrieve all logs
export async function getLogs() {
  const { [LOG_KEY]: logs } = await chrome.storage.local.get(LOG_KEY);
  return Array.isArray(logs) ? logs : [];
}