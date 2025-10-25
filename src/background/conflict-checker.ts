// src/background/conflict-checker.ts

// --- T1's Core Utility Import ---
import { saveLog } from '../lib/log-storage';

// Permissions that pose a high risk
const SENSITIVE_PERMISSIONS: string[] = [
    'webRequest', 
    'cookies', 
    'tabs', 
    'scripting', 
    '<all_urls>',
    'management' // Add management itself, as it's required to run this check
];

/**
 * Executes a scan of all installed extensions for sensitive permissions (using the management API).
 * This detects extensions that may pose a risk due to over-permissioning.
 */
export async function runConflictCheck(): Promise<void> {
    try {
        // NOTE: The manifest must include the 'management' permission for this to work.
        const extensions = await chrome.management.getAll();
        let conflictCount = 0;

        for (const ext of extensions) {
            // Ignore our own extension, apps, themes, and disabled extensions
            if (ext.id === chrome.runtime.id || ext.type !== 'extension' || !ext.enabled) {
                continue;
            }

            const foundPermissions: string[] = [];

            for (const perm of SENSITIVE_PERMISSIONS) {
                // Check both explicit permissions and host permissions
                if (ext.permissions?.includes(perm) || ext.hostPermissions?.includes(perm)) {
                    foundPermissions.push(perm);
                }
            }

            if (foundPermissions.length > 0) {
                conflictCount++;
                // T4's logic assigns a medium severity to this baseline check
                saveLog({
                    type: 'extension_conflict',
                    severity: 'medium',
                    extension_name: ext.name,
                    extension_id: ext.id,
                    sensitive_permissions_found: foundPermissions,
                    details: `Extension possesses ${foundPermissions.length} sensitive permissions.`,
                    timestamp: new Date().toISOString()
                });
            }
        }
        console.log(`Permission Conflict Check Complete. Found ${conflictCount} potential conflicts.`);
    } catch (error) {
        // If the manifest is missing the 'management' permission, this error will fire.
        console.error("Error running conflict check (Check 'management' permission in manifest):", error);
    }
}