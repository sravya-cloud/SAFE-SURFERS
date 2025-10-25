import React, { useState } from 'react';
import { Shield, AlertTriangle, Activity, Eye, Database, History } from 'lucide-react';

export default function T4ScoringSystem() {
  const [requestCount, setRequestCount] = useState(15);
  const [domainRep, setDomainRep] = useState(3);
  const [obfuscation, setObfuscation] = useState(false);
  const [dataExfil, setDataExfil] = useState(50);
  const [actionTrigger, setActionTrigger] = useState('tabs.query');
  const [historyCheck, setHistoryCheck] = useState(false);

  // Calculate scores
  const baseScore = (requestCount * 2) + (domainRep * 10);
  const finalScore = baseScore * (obfuscation ? 2 : 1);
  
  const getRiskLevel = () => {
    if (finalScore > 100) return { level: 'CRITICAL', color: 'bg-red-600', textColor: 'text-red-600' };
    if (finalScore > 50) return { level: 'HIGH', color: 'bg-orange-500', textColor: 'text-orange-500' };
    return { level: 'LOW', color: 'bg-green-500', textColor: 'text-green-500' };
  };

  const risk = getRiskLevel();

  const metrics = [
    {
      icon: Activity,
      name: 'Request Count (5s)',
      source: 'Background Worker',
      value: requestCount,
      purpose: 'Network Burst Anomaly Detection',
      scoring: 'Primary Input: Higher count = Higher risk (×2)',
      color: 'blue'
    },
    {
      icon: Shield,
      name: 'Domain Reputation',
      source: 'Background Worker',
      value: domainRep,
      purpose: 'Unknown/Suspicious Domain Detection',
      scoring: 'Content Weight: Suspicious domains boost score (×10)',
      color: 'purple'
    },
    {
      icon: Eye,
      name: 'Obfuscation Flags',
      source: 'Content Script',
      value: obfuscation ? 'TRUE' : 'FALSE',
      purpose: 'Detects eval(), atob(), suspicious strings',
      scoring: 'Deception Multiplier: Doubles entire risk score',
      color: 'red'
    },
    {
      icon: Database,
      name: 'Data Exfil Size (KB)',
      source: 'Content Script',
      value: `${dataExfil} KB`,
      purpose: 'Flags Large Hidden Uploads',
      scoring: 'Volume Multiplier: Indicates potential data theft',
      color: 'yellow'
    },
    {
      icon: Activity,
      name: 'Action Trigger',
      source: 'Background Worker',
      value: actionTrigger,
      purpose: 'Identifies Sensitive API Usage',
      scoring: 'Contextual Score: Adds base risk for sensitive APIs',
      color: 'indigo'
    },
    {
      icon: History,
      name: 'User History Check',
      source: 'Log Storage',
      value: historyCheck ? 'FLAGGED' : 'CLEAN',
      purpose: 'Persistent Threat Detection',
      scoring: 'Persistence Score: Escalates for repeat offenders',
      color: 'pink'
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-3">
            <Shield className="w-12 h-12 text-cyan-400" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              T4 Threat Detection System
            </h1>
          </div>
          <p className="text-slate-300 text-lg">Rules-Based Anomaly Scoring Engine</p>
        </div>

        {/* Risk Score Display */}
        <div className="bg-slate-800 rounded-xl p-6 mb-8 border border-slate-700 shadow-xl">
          <div className="grid md:grid-cols-3 gap-6">
            <div className="text-center">
              <p className="text-slate-400 text-sm mb-2">Base Score</p>
              <p className="text-3xl font-bold text-cyan-400">{baseScore}</p>
              <p className="text-xs text-slate-500 mt-1">(requests×2) + (domain×10)</p>
            </div>
            <div className="text-center">
              <p className="text-slate-400 text-sm mb-2">Obfuscation Multiplier</p>
              <p className="text-3xl font-bold text-purple-400">×{obfuscation ? 2 : 1}</p>
              <p className="text-xs text-slate-500 mt-1">{obfuscation ? 'Active' : 'Inactive'}</p>
            </div>
            <div className="text-center">
              <p className="text-slate-400 text-sm mb-2">Final Risk Score</p>
              <p className={`text-4xl font-bold ${risk.textColor}`}>{finalScore}</p>
              <div className={`inline-block ${risk.color} px-4 py-1 rounded-full text-sm font-semibold mt-2`}>
                {risk.level}
              </div>
            </div>
          </div>
        </div>

        {/* Scoring Formula */}
        <div className="bg-gradient-to-r from-cyan-900/30 to-blue-900/30 rounded-xl p-6 mb-8 border border-cyan-700/50">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5" />
            Scoring Algorithm
          </h2>
          <div className="space-y-3 font-mono text-sm">
            <div className="bg-slate-800/50 p-3 rounded">
              <span className="text-slate-400">1. Calculate Base:</span>
              <span className="text-cyan-400 ml-2">Base = (request_count × 2) + (domain_rep × 10)</span>
            </div>
            <div className="bg-slate-800/50 p-3 rounded">
              <span className="text-slate-400">2. Apply Multiplier:</span>
              <span className="text-purple-400 ml-2">Final = Base × (obfuscation ? 2 : 1)</span>
            </div>
            <div className="bg-slate-800/50 p-3 rounded">
              <span className="text-slate-400">3. Determine Level:</span>
              <div className="ml-2 mt-2 space-y-1">
                <div className="text-red-400">• CRITICAL if Final &gt; 100</div>
                <div className="text-orange-400">• HIGH if Final &gt; 50</div>
                <div className="text-green-400">• LOW otherwise</div>
              </div>
            </div>
          </div>
        </div>

        {/* Interactive Controls */}
        <div className="bg-slate-800 rounded-xl p-6 mb-8 border border-slate-700">
          <h2 className="text-xl font-bold mb-4">Interactive Simulator</h2>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-2">
                Request Count (5s): {requestCount}
              </label>
              <input
                type="range"
                min="0"
                max="100"
                value={requestCount}
                onChange={(e) => setRequestCount(Number(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-2">
                Domain Reputation (0-10): {domainRep}
              </label>
              <input
                type="range"
                min="0"
                max="10"
                value={domainRep}
                onChange={(e) => setDomainRep(Number(e.target.value))}
                className="w-full"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-2">Obfuscation Detected</label>
              <button
                onClick={() => setObfuscation(!obfuscation)}
                className={`px-4 py-2 rounded ${obfuscation ? 'bg-red-600' : 'bg-slate-700'}`}
              >
                {obfuscation ? 'TRUE (×2)' : 'FALSE (×1)'}
              </button>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-2">History Check</label>
              <button
                onClick={() => setHistoryCheck(!historyCheck)}
                className={`px-4 py-2 rounded ${historyCheck ? 'bg-pink-600' : 'bg-slate-700'}`}
              >
                {historyCheck ? 'FLAGGED' : 'CLEAN'}
              </button>
            </div>
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid md:grid-cols-2 gap-6">
          {metrics.map((metric, idx) => {
            const Icon = metric.icon;
            const colorMap = {
              blue: 'from-blue-900/30 to-blue-800/30 border-blue-700/50',
              purple: 'from-purple-900/30 to-purple-800/30 border-purple-700/50',
              red: 'from-red-900/30 to-red-800/30 border-red-700/50',
              yellow: 'from-yellow-900/30 to-yellow-800/30 border-yellow-700/50',
              indigo: 'from-indigo-900/30 to-indigo-800/30 border-indigo-700/50',
              pink: 'from-pink-900/30 to-pink-800/30 border-pink-700/50'
            };

            return (
              <div
                key={idx}
                className={`bg-gradient-to-br ${colorMap[metric.color]} rounded-xl p-5 border shadow-lg hover:shadow-xl transition-shadow`}
              >
                <div className="flex items-start gap-3 mb-3">
                  <Icon className="w-6 h-6 mt-1 flex-shrink-0" />
                  <div className="flex-1">
                    <h3 className="font-bold text-lg">{metric.name}</h3>
                    <p className="text-sm text-slate-400">{metric.source}</p>
                  </div>
                  <div className="bg-slate-900/50 px-3 py-1 rounded font-mono text-sm">
                    {metric.value}
                  </div>
                </div>
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-slate-400">Purpose:</span>
                    <p className="text-slate-200">{metric.purpose}</p>
                  </div>
                  <div>
                    <span className="text-slate-400">Scoring:</span>
                    <p className="text-slate-200">{metric.scoring}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Data Flow Diagram */}
        <div className="mt-8 bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-bold mb-4">Data Flow Architecture</h2>
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm">
            <div className="bg-blue-900/30 border border-blue-700/50 rounded-lg p-4 flex-1">
              <p className="font-bold mb-1">T2 Logs</p>
              <p className="text-slate-400 text-xs">Background Worker & Content Script</p>
            </div>
            <div className="text-2xl text-cyan-400">→</div>
            <div className="bg-purple-900/30 border border-purple-700/50 rounded-lg p-4 flex-1">
              <p className="font-bold mb-1">T4 Scoring Engine</p>
              <p className="text-slate-400 text-xs">Rules-Based Analysis</p>
            </div>
            <div className="text-2xl text-cyan-400">→</div>
            <div className={`${risk.color} rounded-lg p-4 flex-1`}>
              <p className="font-bold mb-1">Risk Level</p>
              <p className="text-xs">Critical/High/Low Alert</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}