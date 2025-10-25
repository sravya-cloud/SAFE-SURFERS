import { useEffect, useState } from "react"
import { getLogs } from "../src/lib/log-storage"

function IndexPopup() {
  const [alert, setAlert] = useState<string | null>(null)
  const [logs, setLogs] = useState<any[]>([])

  useEffect(() => {
    const listener = (msg: any) => {
      if (msg.type === "ALERT_TRIGGER") {
        setAlert(msg.message)
        setTimeout(() => setAlert(null), 5000)
      }
    }
    chrome.runtime.onMessage.addListener(listener)

    // Fetch latest alert if one exists
    chrome.storage.local.get("latest_alert").then(({ latest_alert }) => {
      if (latest_alert && Date.now() - latest_alert.time < 60000) { // Show if less than 1 min old
        setAlert(latest_alert.message)
        setTimeout(() => setAlert(null), 5000)
      }
    })

    // Load existing logs
    getLogs().then(setLogs)

    return () => chrome.runtime.onMessage.removeListener(listener)
  }, [])

  return (
    <div style={{ padding: 16, width: 300 }}>
      <h2>SafeSurfers Dashboard</h2>

      {alert && (
        <div
          style={{
            backgroundColor: "red",
            color: "white",
            padding: "10px",
            borderRadius: "8px",
            textAlign: "center",
            marginBottom: "10px",
            fontWeight: "bold"
          }}
        >
          🚨 ALERT! {alert}
        </div>
      )}

      <h3>Recent Logs:</h3>
      <div
        style={{
          maxHeight: 200,
          overflowY: "auto",
          border: "1px solid #444",
          padding: "8px",
          borderRadius: "6px",
          background: "#111",
          color: "white",
          fontSize: "12px"
        }}
      >
        {logs.length === 0 ? (
          <p>No logs yet.</p>
        ) : (
          logs.map((log, i) => (
            <div key={i}>
              <b>{log.type}</b> – {log.severity} <br />
              {log.details}
              <hr />
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default IndexPopup
