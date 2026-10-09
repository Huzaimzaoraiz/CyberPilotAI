import React, { useContext } from 'react';
import { DashboardContext } from '../context/DashboardContext';

const Header = () => {

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
                    {/* --- 1. Top Global Navigation Header --- */}
                    <header className="bg-dark-900/90 backdrop-blur border-b border-dark-750 sticky top-0 z-40 px-4 sm:px-8 py-3 transition">
                        <div className="max-w-7xl mx-auto flex flex-col lg:flex-row items-center justify-between gap-3">
                            
                            {/* Brand & Identity */}
                            <div className="flex items-center justify-between w-full lg:w-auto">
                                <div className="flex items-center space-x-3">
                                    <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-teal-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-xl shadow-lg shadow-cyan-500/10">
                                        <i className="fa-solid fa-shield-halved"></i>
                                    </div>
                                    <div>
                                        <div className="flex items-center space-x-2">
                                            <h1 className="font-extrabold text-lg tracking-tight text-white">Agent AI</h1>
                                            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                                                AUTONOMOUS ENGINE
                                            </span>
                                        </div>
                                        <p className="text-[11px] text-slate-400">Continuous Multi-Agent Vulnerability Assessment & Patching</p>
                                    </div>
                                </div>

                                {/* Mobile Status Indicator */}
                                <div className="lg:hidden flex items-center gap-2">
                                    <span className={`h-2.5 w-2.5 rounded-full ${session.is_active ? 'bg-cyan-400 animate-ping' : (assets.length ? 'bg-emerald-400' : 'bg-slate-500')}`}></span>
                                    <span className="text-xs font-mono font-bold text-slate-300">{formatStopwatch(elapsedMs)}</span>
                                </div>
                            </div>

                            {/* Center: Precision Scan Stopwatch Widget */}
                            <div className="flex items-center gap-3 bg-dark-850 border border-dark-700/80 px-4 py-2 rounded-2xl shadow-inner">
                                <div className="flex items-center gap-2">
                                    <i className={`fa-solid fa-stopwatch text-base ${session.is_active ? 'text-cyan-400 animate-pulse' : (session.completed_at ? 'text-emerald-400' : 'text-slate-500')}`}></i>
                                    <div className="text-left">
                                        <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-400 flex items-center gap-1">
                                            <span>Scan Stopwatch</span>
                                            {session.is_active && (
                                                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping inline-block"></span>
                                            )}
                                        </div>
                                        <div className="text-base font-black font-mono tracking-wider text-white">
                                            {formatStopwatch(elapsedMs)}
                                        </div>
                                    </div>
                                </div>

                                <div className="h-7 w-[1px] bg-dark-700 mx-1"></div>

                                {/* Status Tag */}
                                <div>
                                    {session.is_active ? (
                                        <div className="text-left">
                                            <span className="px-2 py-0.5 rounded text-[10px] font-extrabold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 inline-flex items-center gap-1">
                                                <i className="fa-solid fa-bolt text-[9px] animate-bounce"></i> ACTIVE SCAN
                                            </span>
                                            <span className="block text-[10px] text-slate-400 font-mono mt-0.5">
                                                {session.active_tasks_count} tasks in flight
                                            </span>
                                        </div>
                                    ) : session.completed_at ? (
                                        <div className="text-left">
                                            <span className="px-2 py-0.5 rounded text-[10px] font-extrabold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 inline-flex items-center gap-1">
                                                <i className="fa-solid fa-check text-[9px]"></i> COMPLETE
                                            </span>
                                            <span className="block text-[10px] text-emerald-400 font-mono mt-0.5">
                                                Duration: {formatDurationHuman(elapsedMs)}
                                            </span>
                                        </div>
                                    ) : (
                                        <div className="text-left">
                                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-dark-750 text-slate-400 border border-dark-700">
                                                STANDBY
                                            </span>
                                            <span className="block text-[10px] text-slate-500 mt-0.5">Awaiting Target</span>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Header Actions: Auto-refresh, Manual Refresh, Reset */}
                            <div className="flex items-center space-x-2.5 w-full lg:w-auto justify-end">
                                
                                {/* Auto-refresh Toggle */}
                                <label className="flex items-center cursor-pointer text-xs text-slate-300 gap-2 bg-dark-850 border border-dark-700/80 px-3 py-1.5 rounded-xl hover:border-dark-600 transition select-none">
                                    <input 
                                        type="checkbox" 
                                        checked={autoRefresh} 
                                        onChange={(e) => setAutoRefresh(e.target.checked)} 
                                        className="sr-only peer" 
                                    />
                                    <div className="w-7 h-3.5 bg-dark-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-2.5 after:w-2.5 after:transition-all peer-checked:bg-cyan-500"></div>
                                    <span className="hidden sm:inline font-medium">Live ({autoRefresh ? `${countdown}s` : 'Paused'})</span>
                                </label>

                                {/* Refresh Button */}
                                <button 
                                    onClick={() => fetchData(false)} 
                                    disabled={isRefreshing}
                                    title="Fetch latest data"
                                    className="px-3 py-1.5 text-xs bg-dark-850 hover:bg-dark-750 text-slate-200 border border-dark-700/80 rounded-xl transition flex items-center gap-1.5 shadow-sm active:scale-95">
                                    <i className={`fa-solid fa-arrows-rotate text-cyan-400 ${isRefreshing ? 'fa-spin' : ''}`}></i>
                                    <span className="hidden sm:inline font-medium">Sync</span>
                                </button>

                                {/* Export Reports: PDF & JSON */}
                                <a 
                                    href="/api/v1/report/pdf" 
                                    download="Security_Assessment_Report.pdf"
                                    title="Download Executive & Technical PDF Report"
                                    className="px-3 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-xl transition flex items-center gap-1.5 shadow-md shadow-cyan-900/30 active:scale-95">
                                    <i className="fa-solid fa-file-pdf"></i>
                                    <span className="hidden sm:inline">PDF Report</span>
                                </a>

                                <a 
                                    href="/api/v1/report/json" 
                                    download="Security_Assessment_Report.json"
                                    target="_blank"
                                    rel="noreferrer"
                                    title="Export Assessment Summary JSON"
                                    className="px-3 py-1.5 text-xs bg-dark-850 hover:bg-dark-750 text-slate-200 border border-dark-700/80 rounded-xl transition flex items-center gap-1.5 shadow-sm active:scale-95">
                                    <i className="fa-solid fa-file-code text-cyan-400"></i>
                                    <span className="hidden sm:inline">JSON</span>
                                </a>

                                {/* Reset Engine Button */}
                                <button 
                                    onClick={handleResetSession}
                                    disabled={isResetting}
                                    title="Reset engine and return to Standby"
                                    className="px-3 py-1.5 text-xs bg-dark-850 hover:bg-rose-950/30 hover:border-rose-500/40 text-slate-300 hover:text-rose-300 border border-dark-700/80 rounded-xl transition flex items-center gap-1.5 active:scale-95">
                                    <i className="fa-solid fa-rotate-left text-slate-400"></i>
                                    <span className="font-medium">Reset</span>
                                </button>
                            </div>
                        </div>
                    </header>


        </>
    );
};
export default Header;
