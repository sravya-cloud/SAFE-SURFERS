/ src/lib/anomaly-scoring.ts
// Enhanced Multi-Dimensional Contextual Anomaly Scoring System
// Uses behavioral patterns, temporal analysis, and threat fingerprinting

interface AnomalyMetrics {
    // Network Metrics
    requestCount: number;
    domainRepScore: number; // 0-10 scale
    dataExfilSize: number; // bytes
    uploadFrequency?: number; // requests per minute
    
    // Script Analysis Metrics
    obfuscationDetected: boolean;
    dangerousFunctionCount?: number;
    cookieAccessDetected?: boolean;
    
    // Contextual Metrics
    isFirstVisit?: boolean;
    userInteractionOccurred?: boolean;
    timeOfDay?: number; // 0-23 hour
    domainAge?: number; // days since first visit
}

interface ThreatContext {
    behavioralScore: number;
    temporalScore: number;
    structuralScore: number;
    combinedScore: number;
    confidence: number;
    threatVector: string[];
}

/**
 * Calculates behavioral anomaly score based on network activity patterns
 */
function calculateBehavioralScore(metrics: AnomalyMetrics): number {
    let score = 0;
    
    // Request frequency analysis (0-30 points)
    if (metrics.requestCount > 50) score += 30;
    else if (metrics.requestCount > 20) score += 20;
    else if (metrics.requestCount > 10) score += 10;
    
    // Data exfiltration size analysis (0-25 points)
    const exfilMB = metrics.dataExfilSize / (1024 * 1024);
    if (exfilMB > 10) score += 25;
    else if (exfilMB > 5) score += 18;
    else if (exfilMB > 1) score += 10;
    
    // Upload frequency pattern (0-20 points)
    if (metrics.uploadFrequency && metrics.uploadFrequency > 10) {
        score += 20; // Rapid fire uploads are suspicious
    } else if (metrics.uploadFrequency && metrics.uploadFrequency > 5) {
        score += 12;
    }
    
    // Domain reputation (inverted: lower rep = higher score) (0-25 points)
    score += (10 - metrics.domainRepScore) * 2.5;
    
    return Math.min(score, 100);
}

/**
 * Analyzes temporal patterns to detect time-based anomalies
 */
function calculateTemporalScore(metrics: AnomalyMetrics): number {
    let score = 0;
    
    // First visit behavior (suspicious if high activity immediately)
    if (metrics.isFirstVisit) {
        if (metrics.requestCount > 20) score += 25; // Too much activity on first visit
        if (metrics.dataExfilSize > 1024 * 1024) score += 20; // Large upload on first visit
    }
    
    // User interaction correlation (0-30 points)
    if (!metrics.userInteractionOccurred) {
        // Activity without user interaction is highly suspicious
        if (metrics.requestCount > 5) score += 30;
        else if (metrics.requestCount > 0) score += 15;
    }
    
    // Time-based anomalies (0-20 points)
    if (metrics.timeOfDay !== undefined) {
        // Activity during unusual hours (2 AM - 5 AM) is more suspicious
        if (metrics.timeOfDay >= 2 && metrics.timeOfDay <= 5) {
            score += 20;
        }
    }
    
    // Domain age analysis (0-30 points)
    if (metrics.domainAge !== undefined) {
        if (metrics.domainAge === 0) score += 30; // Brand new domain with activity
        else if (metrics.domainAge < 7) score += 20; // Very recent domain
        else if (metrics.domainAge < 30) score += 10; // Recent domain
    }
    
    return Math.min(score, 100);
}

/**
 * Analyzes code structure and permissions for malicious patterns
 */
function calculateStructuralScore(metrics: AnomalyMetrics): number {
    let score = 0;
    
    // Obfuscation detection (0-40 points)
    if (metrics.obfuscationDetected) {
        score += 40;
    }
    
    // Dangerous function usage (0-30 points)
    if (metrics.dangerousFunctionCount !== undefined) {
        if (metrics.dangerousFunctionCount > 10) score += 30;
        else if (metrics.dangerousFunctionCount > 5) score += 20;
        else if (metrics.dangerousFunctionCount > 0) score += 10;
    }
    
    // Cookie/session manipulation (0-30 points)
    if (metrics.cookieAccessDetected) {
        score += 30;
    }
    
    return Math.min(score, 100);
}

/**
 * Identifies specific threat vectors based on metric patterns
 */
function identifyThreatVectors(metrics: AnomalyMetrics, context: ThreatContext): string[] {
    const vectors: string[] = [];
    
    if (metrics.dataExfilSize > 5 * 1024 * 1024) {
        vectors.push('DATA_EXFILTRATION');
    }
    
    if (metrics.obfuscationDetected && metrics.dangerousFunctionCount && metrics.dangerousFunctionCount > 5) {
        vectors.push('OBFUSCATED_MALWARE');
    }
    
    if (metrics.cookieAccessDetected && metrics.dataExfilSize > 0) {
        vectors.push('SESSION_HIJACKING');
    }
    
    if (!metrics.userInteractionOccurred && metrics.requestCount > 10) {
        vectors.push('BACKGROUND_BEACON');
    }
    
    if (metrics.isFirstVisit && (metrics.requestCount > 20 || metrics.dataExfilSize > 1024 * 1024)) {
        vectors.push('ZERO_DAY_ATTACK');
    }
    
    if (metrics.uploadFrequency && metrics.uploadFrequency > 15) {
        vectors.push('RAPID_EXFIL');
    }
    
    return vectors;
}

/**
 * Calculates confidence level based on available data completeness
 */
function calculateConfidence(metrics: AnomalyMetrics): number {
    let dataPoints = 0;
    let availablePoints = 0;
    
    const checks = [
        { value: metrics.requestCount, weight: 1 },
        { value: metrics.domainRepScore, weight: 1 },
        { value: metrics.dataExfilSize, weight: 1 },
        { value: metrics.uploadFrequency, weight: 0.8 },
        { value: metrics.obfuscationDetected, weight: 1 },
        { value: metrics.dangerousFunctionCount, weight: 0.8 },
        { value: metrics.cookieAccessDetected, weight: 0.8 },
        { value: metrics.isFirstVisit, weight: 0.6 },
        { value: metrics.userInteractionOccurred, weight: 0.6 },
        { value: metrics.timeOfDay, weight: 0.4 },
        { value: metrics.domainAge, weight: 0.7 }
    ];
    
    checks.forEach(check => {
        availablePoints += check.weight;
        if (check.value !== undefined && check.value !== null) {
            dataPoints += check.weight;
        }
    });
    
    return Math.round((dataPoints / availablePoints) * 100);
}

/**
 * Main function: Contextual risk assessment using multi-dimensional analysis
 */
export function getRiskLevel(metrics: AnomalyMetrics): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    const context = analyzeContext(metrics);
    
    // Use combined score for primary determination
    if (context.combinedScore >= 75) return 'CRITICAL';
    if (context.combinedScore >= 50) return 'HIGH';
    if (context.combinedScore >= 25) return 'MEDIUM';
    return 'LOW';
}

/**
 * Provides detailed threat context analysis
 */
export function analyzeContext(metrics: AnomalyMetrics): ThreatContext {
    // Calculate individual dimension scores
    const behavioralScore = calculateBehavioralScore(metrics);
    const temporalScore = calculateTemporalScore(metrics);
    const structuralScore = calculateStructuralScore(metrics);
    
    // Weighted combination (behavioral patterns are most important)
    const weights = {
        behavioral: 0.40,
        temporal: 0.30,
        structural: 0.30
    };
    
    let combinedScore = 
        (behavioralScore * weights.behavioral) +
        (temporalScore * weights.temporal) +
        (structuralScore * weights.structural);
    
    // Apply cross-dimensional multipliers for specific threat patterns
    
    // Pattern 1: Obfuscated code + data exfil = critical threat
    if (metrics.obfuscationDetected && metrics.dataExfilSize > 1024 * 1024) {
        combinedScore *= 1.3;
    }
    
    // Pattern 2: First visit + no interaction + high activity = automated attack
    if (metrics.isFirstVisit && !metrics.userInteractionOccurred && metrics.requestCount > 10) {
        combinedScore *= 1.25;
    }
    
    // Pattern 3: Cookie access + rapid uploads = session theft
    if (metrics.cookieAccessDetected && metrics.uploadFrequency && metrics.uploadFrequency > 10) {
        combinedScore *= 1.4;
    }
    
    // Pattern 4: Low rep domain + obfuscation + exfil = malware distribution
    if (metrics.domainRepScore < 3 && metrics.obfuscationDetected && metrics.dataExfilSize > 0) {
        combinedScore *= 1.35;
    }
    
    // Cap combined score at 100
    combinedScore = Math.min(combinedScore, 100);
    
    const confidence = calculateConfidence(metrics);
    
    const context: ThreatContext = {
        behavioralScore,
        temporalScore,
        structuralScore,
        combinedScore,
        confidence,
        threatVector: []
    };
    
    context.threatVector = identifyThreatVectors(metrics, context);
    
    return context;
}

/**
 * Generates human-readable threat explanation
 */
export function explainThreat(context: ThreatContext): string {
    const parts: string[] = [];
    
    parts.push(`Risk Score: ${Math.round(context.combinedScore)}/100`);
    parts.push(`Confidence: ${context.confidence}%`);
    
    if (context.behavioralScore > 50) {
        parts.push(`High behavioral anomaly (${Math.round(context.behavioralScore)}/100)`);
    }
    
    if (context.temporalScore > 50) {
        parts.push(`Suspicious timing patterns (${Math.round(context.temporalScore)}/100)`);
    }
    
    if (context.structuralScore > 50) {
        parts.push(`Malicious code structure detected (${Math.round(context.structuralScore)}/100)`);
    }
    
    if (context.threatVector.length > 0) {
        parts.push(`Threat vectors: ${context.threatVector.join(', ')}`);
    }
    
    return parts.join(' | ');
}