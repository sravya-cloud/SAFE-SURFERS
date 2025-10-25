// background.ts
import { saveLog } from './lib/log-storage'
import { startNetworkMonitoring } from './background/network-monitor'
import { runConflictCheck } from './background/conflict-checker'
import { scanScriptForAnomalies } from './background/script-analyser'

// Function to push alert message + persist it
async function triggerAlert(message: string, url?: string) {
  await chrome.storage.local.set({ latest_alert: { message, url, time: Date.now() } })
  chrome.runtime.sendMessage({
    type: "ALERT_TRIGGER",
    message,
    url
  })
  console.log("🚨 ALERT Triggered:", message, url || "")
}

// ----------------- URL & Tracker Scanner -----------------
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const url = details.url.toLowerCase()
    let riskLevel = "low"
    let reason = ""

    if (["redirect", "aff_id", "token", "base64", "track", "click", "session"].some(p => url.includes(p))) {
      riskLevel = "medium"
      reason = "Suspicious query parameter detected."
    }

    if (url.startsWith("http:")) {
      riskLevel = "high"
      reason = "Unsecured HTTP site detected."
    }

    if (riskLevel !== "low") {
      await saveLog({
        type: "url_threat",
        severity: riskLevel,
        url,
        details: reason,
        detection_source: "network_monitor"
      })
      await triggerAlert(`${reason} (Risk: ${riskLevel.toUpperCase()})`, url)
    }
  },
  { urls: ["<all_urls>"] }
)

// ----------------- Script Analyzer -----------------
chrome.webNavigation.onCompleted.addListener(async (details) => {
  try {
    if (details.frameId !== 0) return
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab || !tab.id) return

    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => Array.from(document.scripts).map(s => s.innerText).join("\n")
    })

    const allScripts = result || ""
    const isSuspicious = scanScriptForAnomalies(allScripts, details.url)

    if (isSuspicious) {
      await saveLog({
        type: "script_anomaly",
        severity: "high",
        page: details.url,
        details: "Detected high-risk obfuscated script content.",
        detection_source: "static_analysis"
      })
      await triggerAlert("High-risk script anomaly detected!", details.url)
    }
  } catch (err) {
    console.error("Script scan failed:", err)
  }
})

// ----------------- Initialization -----------------
function initializeServices() {
  console.log("--- SAFESURFERS Core Services Initialized ---")
  startNetworkMonitoring()
  runConflictCheck()
}

initializeServices()
