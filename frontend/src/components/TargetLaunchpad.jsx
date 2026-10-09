import React, { useContext } from 'react';
import { DashboardContext } from '../context/DashboardContext';

const TargetLaunchpad = () => {

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
                        {/* --- 2. Target Ingestion & Launchpad Hero Section --- */}
                        <section className="bg-gradient-to-b from-dark-900 to-dark-850 border border-dark-750 rounded-2xl p-5 sm:p-7 shadow-2xl relative overflow-hidden">
                            {/* Decorative background glow */}
                            <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>

                            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-5">
                                <div>
                                    <h2 className="text-lg sm:text-xl font-black text-white flex items-center gap-2.5 tracking-tight">
                                        <span className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm">
                                            <i className="fa-solid fa-bullseye"></i>
                                        </span>
                                        Target Assessment Launchpad
                                    </h2>
                                    <p className="text-xs sm:text-sm text-slate-400 mt-1">
                                        Input any target domain or IP. The multi-agent swarm will autonomously discover assets, cross-reference CVEs, validate exploits in a safe sandbox, map lateral pivot paths, and synthesize code fixes with Gemini 3.5.
                                    </p>
                                </div>
                                <div className="hidden lg:flex items-center gap-2 text-xs text-slate-400 bg-dark-950/80 border border-dark-700 px-3.5 py-2 rounded-xl font-mono">
                                    <i className="fa-solid fa-microchip text-cyan-400"></i>
                                    <span>AI Engine: <strong className="text-slate-200">Gemini 3.5 Flash-Lite</strong></span>
                                </div>
                            </div>

                            {/* Launch Form */}
                            <form onSubmit={handleTargetSubmit} className="space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-12 gap-3 sm:gap-4">
                                    {/* Domain / IP Input */}
                                    <div className="md:col-span-6 lg:col-span-7">
                                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                                            Target Domain or IP Address
                                        </label>
                                        <div className="relative">
                                            <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                                                <i className="fa-solid fa-globe"></i>
                                            </span>
                                            <input 
                                                type="text" 
                                                required 
                                                value={targetDomain}
                                                onChange={(e) => setTargetDomain(e.target.value)}
                                                placeholder="e.g. scanme.nmap.org or 192.168.1.100" 
                                                className="w-full bg-dark-950 border border-dark-700 rounded-xl pl-10 pr-3 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition shadow-inner" 
                                            />
                                        </div>

                                        {/* Quick Test Chips */}
                                        <div className="mt-2 flex items-center gap-1.5 flex-wrap text-[11px] text-slate-400">
                                            <span className="text-slate-500">Presets:</span>
                                            <button 
                                                type="button" 
                                                onClick={() => setTargetDomain('scanme.nmap.org')}
                                                className="px-2 py-0.5 rounded bg-dark-800 hover:bg-dark-750 text-slate-300 border border-dark-700 transition">
                                                scanme.nmap.org
                                            </button>
                                            <button 
                                                type="button" 
                                                onClick={() => setTargetDomain('127.0.0.1')}
                                                className="px-2 py-0.5 rounded bg-dark-800 hover:bg-dark-750 text-slate-300 border border-dark-700 transition">
                                                127.0.0.1
                                            </button>
                                            <button 
                                                type="button" 
                                                onClick={() => setTargetDomain('localhost')}
                                                className="px-2 py-0.5 rounded bg-dark-800 hover:bg-dark-750 text-slate-300 border border-dark-700 transition">
                                                localhost
                                            </button>
                                        </div>
                                    </div>

                                    {/* Target Layer Selector */}
                                    <div className="md:col-span-3 lg:col-span-3">
                                        <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                                            Target Infrastructure Layer
                                        </label>
                                        <select 
                                            value={targetLayer}
                                            onChange={(e) => setTargetLayer(e.target.value)}
                                            className="w-full bg-dark-950 border border-dark-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition shadow-inner">
                                            <option value="Web">Web Application</option>
                                            <option value="Network">Network Infrastructure</option>
                                            <option value="Cloud">Cloud Environment</option>
                                            <option value="Host">Internal Host</option>
                                        </select>
                                    </div>

                                    {/* Action Button */}
                                    <div className="md:col-span-3 lg:col-span-2 flex items-end">
                                        <button 
                                            type="submit" 
                                            disabled={isSubmittingTarget || session.is_active}
                                            className={`w-full font-bold py-2.5 px-4 rounded-xl text-sm transition shadow-lg flex items-center justify-center gap-2 ${
                                                session.is_active 
                                                    ? 'bg-dark-800 text-slate-500 border border-dark-700 cursor-not-allowed'
                                                    : 'bg-gradient-to-r from-cyan-500 to-teal-400 hover:from-cyan-400 hover:to-teal-300 text-slate-950 shadow-cyan-500/20 active:scale-95'
                                            }`}>
                                            {isSubmittingTarget ? (
                                                <>
                                                    <i className="fa-solid fa-circle-notch fa-spin"></i>
                                                    <span>Launching...</span>
                                                </>
                                            ) : session.is_active ? (
                                                <>
                                                    <i className="fa-solid fa-spinner fa-spin text-cyan-400"></i>
                                                    <span>Scan In Flight</span>
                                                </>
                                            ) : (
                                                <>
                                                    <span>Start Scan</span>
                                                    <i className="fa-solid fa-bolt"></i>
                                                </>
                                            )}
                                        </button>
                                    </div>
                                </div>

                                {/* Checkbox Options */}
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 text-xs text-slate-300 border-t border-dark-750/70">
                                    <label className="flex items-center gap-2 cursor-pointer select-none">
                                        <input 
                                            type="checkbox" 
                                            required 
                                            checked={isAuthorized}
                                            onChange={(e) => setIsAuthorized(e.target.checked)}
                                            className="rounded border-dark-700 bg-dark-950 text-cyan-500 focus:ring-0" 
                                        />
                                        <span>I confirm explicit authorization to assess this target.</span>
                                    </label>

                                    <label className="flex items-center gap-2 cursor-pointer select-none text-slate-300 hover:text-white transition">
                                        <input 
                                            type="checkbox" 
                                            checked={includeCrownJewel}
                                            onChange={(e) => setIncludeCrownJewel(e.target.checked)}
                                            className="rounded border-dark-700 bg-dark-950 text-cyan-500 focus:ring-0" 
                                        />
                                        <span>Include Crown Jewel DB <span className="text-amber-400 font-semibold">(simulates lateral pivot & chokepoint)</span></span>
                                    </label>
                                </div>
                            </form>

                            {/* Operational Window & Real-time Progress Bar */}
                            {(session.is_active || session.completed_at) && (
                                <div className="mt-5 pt-4 border-t border-dark-750/70">
                                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs mb-2">
                                        <div className="flex items-center gap-2">
                                            <span className="font-semibold text-slate-200">
                                                Operational Scan Window
                                            </span>
                                            <span className="text-slate-400 font-mono">
                                                (Target Ceiling: 10m max | Elapsed: {formatStopwatch(elapsedMs)})
                                            </span>
                                        </div>
                                        <span className={`text-[11px] font-bold ${session.is_active ? 'text-cyan-400 animate-pulse' : 'text-emerald-400'}`}>
                                            {session.is_active 
                                                ? 'Running at full multi-agent parallel capacity' 
                                                : `Scan completed in ${formatDurationHuman(elapsedMs)}`}
                                        </span>
                                    </div>
                                    {/* Progress track */}
                                    <div className="w-full h-2 bg-dark-950 rounded-full overflow-hidden border border-dark-750 p-0.5">
                                        <div 
                                            className={`h-full rounded-full transition-all duration-300 ${
                                                session.completed_at 
                                                    ? 'bg-gradient-to-r from-emerald-500 to-teal-400' 
                                                    : 'bg-gradient-to-r from-cyan-500 to-blue-500'
                                            }`}
                                            style={{ width: session.completed_at ? '100%' : `${Math.max(5, operationalProgressPct)}%` }}>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </section>


        </>
    );
};
export default TargetLaunchpad;
