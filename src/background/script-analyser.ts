// src/analysis/script-analyzer.ts
// Detects high-risk structural anomalies in script source code using AST analysis.

// NOTE: This file requires 'esprima' to be installed: npm install esprima @types/esprima
// Ensure your TypeScript build handles Node.js 'require' or use dynamic import/bundler setup.
import * as esprima from "esprima"
import { saveLog } from "../lib/log-storage" // Assuming log-storage is also a .ts file

// Define the structure of a LogEntry for clarity and type safety
interface LogEntry {
  type: string
  detection_source: string
  severity: string
  script_id: string
  line_number?: number
  details: string
  timestamp: string
}

// High-Risk Pattern Definitions
const DANGEROUS_CALLS: string[] = ["eval", "Function", "setTimeout", "setInterval", "atob", "btoa"]
const STRING_MANIPULATORS: string[] = ["fromCharCode", "charCodeAt", "substr", "substring", "replace"]

/**
 * Saves a detailed log entry for the detected anomaly.
 */
function logAnomaly(scriptId: string, type: string, line: number): void {
  const logEntry: LogEntry = {
    type: "script_anomaly",
    detection_source: "static_analysis",
    severity: "high",
    script_id: scriptId,
    line_number: line,
    details: `High-risk function: ${type}`,
    timestamp: new Date().toISOString()
  }
  saveLog(logEntry)
}

/**
 * Scans a script's source code for high-risk structural anomalies (AST analysis).
 * @param scriptContent - The source code of the script.
 * @param scriptId - A unique identifier for the script.
 * @returns True if a suspicious pattern is found.
 */
export function scanScriptForAnomalies(scriptContent: string, scriptId: string): boolean {
  let suspicious = false

  try {
    // Parse the script into an Abstract Syntax Tree (AST)
    // We cast the result to 'any' because esprima's AST structure is complex
    const AST: any = esprima.parseScript(scriptContent, { loc: true })

    function traverse(node: any): void {
      if (!node || typeof node !== "object") return

      // Use optional chaining for safer access to line number
      const line: number = node.loc?.start?.line || 0

      // Rule 1: Dangerous calls (eval, atob, etc.)
      if (node.type === "CallExpression" && node.callee?.type === "Identifier") {
        const functionName: string = node.callee.name
        if (DANGEROUS_CALLS.includes(functionName)) {
          suspicious = true
          logAnomaly(scriptId, `Function call to '${functionName}'`, line)
        }
      }

      // Rule 2: Obfuscation methods (fromCharCode, charCodeAt, etc.)
      if (node.type === "MemberExpression" && node.property?.type === "Identifier") {
        const propertyName: string = node.property.name
        if (STRING_MANIPULATORS.includes(propertyName)) {
          suspicious = true
          logAnomaly(scriptId, `Obfuscation method: ${propertyName}`, line)
        }
      }

      // Rule 3: Cookie modification (potential session theft)
      if (
        node.type === "AssignmentExpression" &&
        node.left?.type === "MemberExpression" &&
        node.left.property?.name === "cookie"
      ) {
        suspicious = true
        logAnomaly(scriptId, "Writes to document.cookie", line)
      }

      // Recursive traversal
      for (const key in node) {
        if (node.hasOwnProperty(key)) {
          const child = node[key]
          if (Array.isArray(child)) {
            child.forEach(traverse)
          } else if (typeof child === "object" && child !== null && child.type) {
            traverse(child)
          }
        }
      }
    }

    traverse(AST)
    return suspicious
  } catch (err: any) {
    saveLog({
      type: "script_analysis_error",
      detection_source: "static_analysis",
      severity: "medium",
      script_id: scriptId,
      details: `Failed to parse: ${err.message}`,
      timestamp: new Date().toISOString()
    })
    return false
  }
}
