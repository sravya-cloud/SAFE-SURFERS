// src/lib/anomaly-scoring.ts
// T4's Core Rules-Based Anomaly Scoring Logic

// Define the expected structure (interface) for the input data
interface AnomalyMetrics {
    requestCount: number; // Input from Network Monitor (T2)
    domainRepScore: number; // Input from Network Monitor (T2)
    obfuscationDetected: boolean; // Input from Script Analyzer (T2)
    // You can add more metrics like 'dataExfilSize' here later
}

/**
 * Calculates a total risk score based on combined behavioral metrics.
 * This function is the "AI" that the Background Worker calls.
 * @param metrics The object containing the measured security inputs.
 * @returns 'CRITICAL', 'HIGH', or 'LOW' risk level string.
 */
export function getRiskLevel(metrics: AnomalyMetrics): 'CRITICAL' | 'HIGH' | 'LOW' {
    // 1. Calculate Base Score
    // Formula: (Request Count * 2) + (Domain Reputation Score * 10)
    // T4 defines the weights (2 and 10)
    const baseScore = (metrics.requestCount * 2) + (metrics.domainRepScore * 10);
    
    // 2. Apply Multiplier (Obfuscation is the critical multiplier)
    const obfuscationMultiplier = metrics.obfuscationDetected ? 2 : 1;
    const finalScore = baseScore * obfuscationMultiplier;
    
    // 3. Determine Final Risk Level (T4's Thresholds)
    if (finalScore > 100) {
        return 'CRITICAL';
    }
    if (finalScore > 50) {
        return 'HIGH';
    }
    
    return 'LOW';
}