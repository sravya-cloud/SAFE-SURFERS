import esprima from 'esprima';
import { saveLog } from '../lib/log-storage';

const DANGEROUS_CALLS = ['eval', 'Function', 'setTimeout', 'setInterval', 'atob', 'btoa'];
const STRING_MANIPULATORS = ['fromCharCode', 'charCodeAt', 'substr', 'substring', 'replace'];

function logAnomaly(scriptId: string, type: string, line: number) {
  saveLog({
    type: 'script_anomaly',
    detection_source: 'static_analysis',
    severity: 'high',
    script_id: scriptId,
    line_number: line,
    details: `High-risk function: ${type}`,
  });
}

export function scanScriptForAnomalies(scriptContent: string, scriptId: string): boolean {
  let suspicious = false;
  try {
    const AST = esprima.parseScript(scriptContent, { loc: true });
    function traverse(node) {
      if (!node || typeof node !== 'object') return;
      const line = node.loc?.start?.line || 0;

      // Rule 1: Dangerous calls
      if (node.type === 'CallExpression' && node.callee?.name && DANGEROUS_CALLS.includes(node.callee.name)) {
        suspicious = true;
        logAnomaly(scriptId, `Function call to '${node.callee.name}'`, line);
      }

      // Rule 2: Obfuscation
      if (node.type === 'MemberExpression' && node.property?.name && STRING_MANIPULATORS.includes(node.property.name)) {
        suspicious = true;
        logAnomaly(scriptId, `Obfuscation method: ${node.property.name}`, line);
      }

      // Rule 3: Cookie modification
      if (node.type === 'AssignmentExpression' && node.left?.property?.name === 'cookie') {
        suspicious = true;
        logAnomaly(scriptId, "Writes to document.cookie", line);
      }

      for (const key in node) {
        const child = node[key];
        if (Array.isArray(child)) child.forEach(traverse);
        else traverse(child);
      }
    }
    traverse(AST);
    return suspicious;
  } catch (err) {
    saveLog({
      type: 'script_analysis_error',
      severity: 'medium',
      script_id: scriptId,
      details: `Failed to parse: ${err.message}`,
    });
    return false;
  }
}
