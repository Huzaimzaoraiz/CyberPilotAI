import React, { useContext } from 'react';
import { DashboardContext } from '../context/DashboardContext';

const AgentSwarmQueue = () => {

    const {
        session, setSession, assets, setAssets, vulnerabilities, setVulnerabilities,
        attackPaths, setAttackPaths, queueTasks, setQueueTasks, elapsedMs, setElapsedMs,
        filter, setFilter, searchQuery, setSearchQuery, autoRefresh, setAutoRefresh,
        countdown, setCountdown, isRefreshing, setIsRefreshing, activeTab, setActiveTab,
        targetDomain, setTargetDomain, targetLayer, setTargetLayer, isAuthorized, setIsAuthorized,
        includeCrownJewel, setIncludeCrownJewel, isSubmittingTarget, setIsSubmittingTarget,
        modalVulnId, setModalVulnId, remediationPlan, setRemediationPlan, remediationLoading, setRemediationLoading,
        remediationError, setRemediationError, copySuccess, setCopySuccess, retestingVulnId, setRetestingVulnId,
        isResetting, setIsResetting, toastMessage, setToastMessage, fetchData, handleTargetSubmit,
        handleResetSession, openRemediation, closeRemediation, copyPatchCode, handleTriggerRetest,
        filteredVulns, filterCounts, severityStats, crownJewelsCount, operationalProgressPct, selectedVuln, activeAgentsSet,
        formatStopwatch, formatDurationHuman, escapeHtml, showToast
    } = useContext(DashboardContext);

    return (
        <>
                        {/* --- 4. Autonomous Agent Swarm & Active Task Queue --- */}
                        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                            
                            {/* Left: Agent Swarm State (7 Cols) */}
                            <div className="lg:col-span-7 bg-dark-900 border border-dark-750 rounded-2xl p-5 sm:p-6 shadow-xl flex flex-col justify-between">
                                <div>
                                    <div className="flex items-center justify-between mb-2">
                                        <h3 className="text-base font-bold text-white flex items-center gap-2">
                                            <i className="fa-solid fa-users-gear text-cyan-400"></i>
                                            Autonomous Agent Swarm
                                        </h3>
                                        <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2.5 py-0.5 rounded-full">
                                            6 Autonomous Nodes
                                        </span>
                                    </div>
                                    <p className="text-xs text-slate-400 mb-4">
                                        Specialized agent workers operate in parallel to discover weaknesses, gather threat intelligence, prove exploitability safely, and synthesize code patches.
                                    </p>

                                    {/* 6 Agent Cards Grid */}
                                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                                        
                                        {/* Agent 1: VAPT */}
                                        <div className={`border rounded-xl p-3.5 transition flex flex-col justify-between ${
                                            activeAgentsSet.has('vapt') 
                                                ? 'bg-cyan-950/30 border-cyan-500/50 shadow-lg shadow-cyan-500/10' 
                                                : 'bg-dark-850 border-dark-700/80'
                                        }`}>
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="font-bold text-slate-100">VAPT Recon</span>
                                                    <i className="fa-solid fa-network-wired text-cyan-400"></i>
                                                </div>
                                                <div className="text-[11px] text-slate-400">Ports & NVD CVEs</div>
                                            </div>
                                            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-bold">
                                                <span className={`h-2 w-2 rounded-full ${activeAgentsSet.has('vapt') ? 'bg-cyan-400 animate-ping' : 'bg-slate-600'}`}></span>
                                                <span className={activeAgentsSet.has('vapt') ? 'text-cyan-300' : 'text-slate-400'}>
                                                    {activeAgentsSet.has('vapt') ? 'RUNNING' : 'STANDBY'}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Agent 2: Threat Intel */}
                                        <div className={`border rounded-xl p-3.5 transition flex flex-col justify-between ${
                                            activeAgentsSet.has('threat_intel') 
                                                ? 'bg-blue-950/30 border-blue-500/50 shadow-lg shadow-blue-500/10' 
                                                : 'bg-dark-850 border-dark-700/80'
                                        }`}>
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="font-bold text-slate-100">Threat Intel</span>
                                                    <i className="fa-solid fa-satellite-dish text-blue-400"></i>
                                                </div>
                                                <div className="text-[11px] text-slate-400">OSINT & HIBP</div>
                                            </div>
                                            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-bold">
                                                <span className={`h-2 w-2 rounded-full ${activeAgentsSet.has('threat_intel') ? 'bg-blue-400 animate-ping' : 'bg-slate-600'}`}></span>
                                                <span className={activeAgentsSet.has('threat_intel') ? 'text-blue-300' : 'text-slate-400'}>
                                                    {activeAgentsSet.has('threat_intel') ? 'RUNNING' : 'STANDBY'}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Agent 3: Sandbox Validation */}
                                        <div className={`border rounded-xl p-3.5 transition flex flex-col justify-between ${
                                            activeAgentsSet.has('validation') 
                                                ? 'bg-emerald-950/30 border-emerald-500/50 shadow-lg shadow-emerald-500/10' 
                                                : 'bg-dark-850 border-dark-700/80'
                                        }`}>
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="font-bold text-slate-100">Validation</span>
                                                    <i className="fa-solid fa-flask text-emerald-400"></i>
                                                </div>
                                                <div className="text-[11px] text-slate-400">Safe PoC Verifier</div>
                                            </div>
                                            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-bold">
                                                <span className={`h-2 w-2 rounded-full ${activeAgentsSet.has('validation') ? 'bg-emerald-400 animate-ping' : 'bg-slate-600'}`}></span>
                                                <span className={activeAgentsSet.has('validation') ? 'text-emerald-300' : 'text-slate-400'}>
                                                    {activeAgentsSet.has('validation') ? 'RUNNING' : 'STANDBY'}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Agent 4: Attack Path */}
                                        <div className={`border rounded-xl p-3.5 transition flex flex-col justify-between ${
                                            activeAgentsSet.has('attack_path') 
                                                ? 'bg-purple-950/30 border-purple-500/50 shadow-lg shadow-purple-500/10' 
                                                : 'bg-dark-850 border-dark-700/80'
                                        }`}>
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="font-bold text-slate-100">Attack Path</span>
                                                    <i className="fa-solid fa-diagram-project text-purple-400"></i>
                                                </div>
                                                <div className="text-[11px] text-slate-400">Pivots & Graph</div>
                                            </div>
                                            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-bold">
                                                <span className={`h-2 w-2 rounded-full ${activeAgentsSet.has('attack_path') ? 'bg-purple-400 animate-ping' : 'bg-slate-600'}`}></span>
                                                <span className={activeAgentsSet.has('attack_path') ? 'text-purple-300' : 'text-slate-400'}>
                                                    {activeAgentsSet.has('attack_path') ? 'RUNNING' : 'STANDBY'}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Agent 5: AI Remediation */}
                                        <div className={`border rounded-xl p-3.5 transition flex flex-col justify-between ${
                                            activeAgentsSet.has('remediation') 
                                                ? 'bg-amber-950/30 border-amber-500/50 shadow-lg shadow-amber-500/10' 
                                                : 'bg-dark-850 border-dark-700/80'
                                        }`}>
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="font-bold text-slate-100">Remediation</span>
                                                    <i className="fa-solid fa-code text-amber-400"></i>
                                                </div>
                                                <div className="text-[11px] text-slate-400">Gemini 3.5 Patches</div>
                                            </div>
                                            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-bold">
                                                <span className={`h-2 w-2 rounded-full ${activeAgentsSet.has('remediation') ? 'bg-amber-400 animate-ping' : 'bg-slate-600'}`}></span>
                                                <span className={activeAgentsSet.has('remediation') ? 'text-amber-300' : 'text-slate-400'}>
                                                    {activeAgentsSet.has('remediation') ? 'RUNNING' : 'STANDBY'}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Agent 6: Closed-loop Retest */}
                                        <div className={`border rounded-xl p-3.5 transition flex flex-col justify-between ${
                                            activeAgentsSet.has('retest') 
                                                ? 'bg-rose-950/30 border-rose-500/50 shadow-lg shadow-rose-500/10' 
                                                : 'bg-dark-850 border-dark-700/80'
                                        }`}>
                                            <div>
                                                <div className="flex items-center justify-between text-xs mb-1">
                                                    <span className="font-bold text-slate-100">Retesting</span>
                                                    <i className="fa-solid fa-vial-circle-check text-rose-400"></i>
                                                </div>
                                                <div className="text-[11px] text-slate-400">Patch Verifier</div>
                                            </div>
                                            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-bold">
                                                <span className={`h-2 w-2 rounded-full ${activeAgentsSet.has('retest') ? 'bg-rose-400 animate-ping' : 'bg-slate-600'}`}></span>
                                                <span className={activeAgentsSet.has('retest') ? 'text-rose-300' : 'text-slate-400'}>
                                                    {activeAgentsSet.has('retest') ? 'RUNNING' : 'STANDBY'}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="mt-4 pt-3 border-t border-dark-750/80 flex items-center justify-between text-xs text-slate-400">
                                    <span><i className="fa-solid fa-bolt text-cyan-400 mr-1.5"></i> Non-blocking event-driven orchestration</span>
                                    <span className="font-mono bg-dark-800 border border-dark-700 px-2.5 py-0.5 rounded text-slate-300">
                                        {queueTasks.length} in-flight
                                    </span>
                                </div>
                            </div>

                            {/* Right: Live Priority Queue (5 Cols) */}
                            <div className="lg:col-span-5 bg-dark-900 border border-dark-750 rounded-2xl p-5 sm:p-6 shadow-xl flex flex-col justify-between">
                                <div>
                                    <div className="flex items-center justify-between mb-2">
                                        <h3 className="text-base font-bold text-white flex items-center gap-2">
                                            <i className="fa-solid fa-list-ol text-emerald-400"></i>
                                            Live Priority Queue
                                        </h3>
                                        <span className="text-[11px] font-mono text-slate-400 uppercase">
                                            Priority Order
                                        </span>
                                    </div>
                                    <p className="text-xs text-slate-400 mb-3">
                                        Tasks sorted dynamically by priority weight (100 = urgent retest, 50 = validation, 30 = discovery).
                                    </p>

                                    <div className="overflow-y-auto max-h-[220px] rounded-xl border border-dark-750 bg-dark-950/80">
                                        <table className="w-full text-left text-xs">
                                            <thead className="bg-dark-850 text-slate-400 sticky top-0 border-b border-dark-750 text-[11px]">
                                                <tr>
                                                    <th className="p-2.5 font-bold">Pri</th>
                                                    <th className="p-2.5 font-bold">Target Agent</th>
                                                    <th className="p-2.5 font-bold text-right">Status</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-dark-750/60 font-mono">
                                                {queueTasks.length === 0 ? (
                                                    <tr>
                                                        <td colSpan="3" className="p-8 text-center text-slate-500 font-sans text-xs">
                                                            Queue idle. Awaiting scan target.
                                                        </td>
                                                    </tr>
                                                ) : (
                                                    queueTasks.slice(0, 7).map(task => {
                                                        const agentClean = task.target_agent.replace('_agent', '').toUpperCase();
                                                        let badgeClass = 'bg-amber-500/10 text-amber-300 border-amber-500/30';
                                                        if (task.status === 'in_progress') {
                                                            badgeClass = 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 animate-pulse font-bold';
                                                        } else if (task.status === 'completed') {
                                                            badgeClass = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
                                                        }
                                                        return (
                                                            <tr key={task.id} className="hover:bg-dark-800/60 transition">
                                                                <td className="p-2.5 font-extrabold text-white">
                                                                    <span className="px-1.5 py-0.5 rounded bg-dark-800 text-[10px] text-cyan-300">
                                                                        {task.priority}
                                                                    </span>
                                                                </td>
                                                                <td className="p-2.5 text-slate-200 font-sans font-medium">
                                                                    {agentClean}
                                                                </td>
                                                                <td className="p-2.5 text-right">
                                                                    <span className={`px-2 py-0.5 rounded text-[10px] border uppercase ${badgeClass}`}>
                                                                        {task.status}
                                                                    </span>
                                                                </td>
                                                            </tr>
                                                        );
                                                    })
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                <div className="mt-4 pt-3 border-t border-dark-750/80 flex items-center justify-between text-[11px] text-slate-400">
                                    <span>Task dispatcher: <strong className="text-slate-200">Asyncio Event Loop</strong></span>
                                    <span>Total: <strong className="text-slate-200">{session.total_tasks_count}</strong></span>
                                </div>
                            </div>
                        </section>


        </>
    );
};
export default AgentSwarmQueue;
