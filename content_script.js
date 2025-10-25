// src/background/conflict-checker.js
import { saveLog } from '../lib/log-storage.js';

// Permissions that pose a high risk
const SENSITIVE_PERMISSIONS = [
  'webRequest',         
  'cookies',            
  'tabs',               
  'scripting',          
  '<all_urls>'          
];

/**
 * Executes a scan of all installed extensions for sensitive permissions (using the management API).
 */
export async function runConflictCheck() {
  try {
    const extensions = await chrome.management.getAll();
    let conflictCount = 0;

    for (const ext of extensions) {
      // Ignore our own extension, themes, apps, and disabled extensions
      if (ext.id === chrome.runtime.id || ext.type !== 'extension' || !ext.enabled) {
        continue;
      }

      const foundPermissions = [];

      for (const perm of SENSITIVE_PERMISSIONS) {
        if (ext.permissions?.includes(perm) || ext.hostPermissions?.includes(perm)) {
          foundPermissions.push(perm);
        }
      }

      if (foundPermissions.length > 0) {
        conflictCount++;
        saveLog({
          type: 'extension_conflict',
          severity: 'medium',
          extension_name: ext.name,
          extension_id: ext.id,
          sensitive_permissions_found: foundPermissions,
          details: `Extension possesses ${foundPermissions.length} sensitive permissions.`
        });
      }
    }
    console.log(`Permission Conflict Check Complete. Found ${conflictCount} potential conflicts.`);
  } catch (error) {
    console.error("Error running conflict check:", error);
  }
}