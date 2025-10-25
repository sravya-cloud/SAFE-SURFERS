// src/analysis/script-analyzer.js
// Detects high-risk structural anomalies in script source code.

// NOTE: This file requires 'esprima' to be installed: npm install esprima
const esprima = require('esprima'); 

// Assume saveLog is imported from the lib directory (as per your existing architecture)
import { saveLog } from '../lib/log-storage.js';

// Define a list of high-risk function calls and methods to flag
const DANGEROUS_CALLS = ['eval', 'Function', 'setTimeout', 'setInterval', 'atob', 'btoa'];
const STRING_MANIPULATORS = ['fromCharCode', 'charCodeAt', 'substr', 'substring', 'replace'];


/**
 * Saves a detailed log entry for the detected anomaly.
 * @param {string} scriptId - Identifier for the analyzed script.
 * @param {string} type - The type of anomaly found.
 * @param {number} line - The line number in the script where it was found.
 */
function logAnomaly(scriptId, type, line) {
    saveLog({
        type: 'script_anomaly',
        detection_source: 'static_analysis',
        severity: 'high',
        script_id: scriptId,
        line_number: line,
        details: `High-risk structural anomaly found: ${type}`,
    });
}

/**
 * Scans a script's source code for high-risk structural anomalies (like eval() or obfuscation).
 * @param {string} scriptContent - The source code of the script to analyze.
 * @param {string} scriptId - A unique identifier for the script (e.g., its URL or hash).
 * @returns {boolean} - True if a suspicious pattern is found.
 */
export function scanScriptForAnomalies(scriptContent, scriptId) {
    let isSuspicious = false;
    
    try {
        // STEP 1: PARSE the script into an Abstract Syntax Tree (AST)
        // loc: true ensures we get line numbers for logging
        const AST = esprima.parseScript(scriptContent, { loc: true });
        
        // STEP 2: TRAVERSE the AST to check for suspicious nodes
        function traverse(node) {
            if (!node || typeof node !== 'object') return;

            const line = node.loc ? node.loc.start.line : 0;

            // --- Rule 1: Check for dangerous function calls (CallExpression) ---
            if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
                const functionName = node.callee.name;

                if (DANGEROUS_CALLS.includes(functionName)) {
                    isSuspicious = true;
                    logAnomaly(scriptId, `Function call to '${functionName}'`, line);
                }
            }
            
            // --- Rule 2: Check for obfuscation methods (MemberExpression) ---
            // e.g., String.fromCharCode(...) or var.charCodeAt(...)
            if (node.type === 'MemberExpression' && node.property && node.property.type === 'Identifier') {
                const propertyName = node.property.name;
                
                if (STRING_MANIPULATORS.includes(propertyName)) {
                    isSuspicious = true;
                    logAnomaly(scriptId, `Obfuscation method detected: ${propertyName}`, line);
                }
            }
            
            // --- Rule 3: Check for code that assigns to document.cookie (Privacy Violation) ---
            if (node.type === 'AssignmentExpression' && 
                node.left.type === 'MemberExpression' && 
                node.left.property && 
                node.left.property.name === 'cookie') {
                 isSuspicious = true;
                 logAnomaly(scriptId, "Direct assignment to 'document.cookie'", line);
            }

            // Recursively check all properties of the node
            for (const key in node) {
                if (node.hasOwnProperty(key)) {
                    const child = node[key];
                    if (Array.isArray(child)) {
                        child.forEach(traverse);
                    } else {
                        traverse(child);
                    }
                }
            }
        }

        traverse(AST);
        return isSuspicious;

    } catch (error) {
        // Log a failure if the script cannot be parsed (often due to highly mangled/malformed code)
        saveLog({
            type: 'script_analysis_error',
            severity: 'medium',
            script_id: scriptId,
            details: `Script parsing failed: ${error.message}`
        });
        return false;
    }
}


/*
// --- Conceptual Usage Example ---

const maliciousScript = `
  var encoded = "Zm9v"; 
  setTimeout(eval(atob(encoded)), 100); 
  document.cookie = 'stolen'; // Privacy risk
`;

const isMalicious = scanScriptForAnomalies(maliciousScript, "injected_script_1"); 

if (isMalicious) {
    console.log("Analysis Complete: Malicious script found and logged.");
}
*/