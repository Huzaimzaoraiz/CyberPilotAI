import React, { useContext } from 'react';
import { DashboardContext } from '../context/DashboardContext';

const MetricsSummary = () => {

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
                        {/* --- 3. High-Level KPI Summary Metrics (4 Cards) --- */}
                        <section className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
                            
                            {/* Card 1: Assets */}
                            <div className="bg-dark-900 border border-dark-750 rounded-2xl p-4 sm:p-5 flex items-center justify-between shadow-lg">
                                <div>
                                    <span className="text-xs font-semibold text-slate-400 block mb-1">Target Assets</span>
                                    <span className="text-2xl sm:text-3xl font-black text-white">{assets.length}</span>
                                    <span className="text-[11px] text-cyan-400 block mt-1 font-medium">
                                        {crownJewelsCount} Crown Jewel DB(s)
                                    </span>
                                </div>
                                <div className="h-12 w-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 text-xl">
                                    <i className="fa-solid fa-server"></i>
                                </div>
                            </div>

                            {/* Card 2: Total Findings */}
                            <div className="bg-dark-900 border border-dark-750 rounded-2xl p-4 sm:p-5 flex items-center justify-between shadow-lg">
                                <div>
                                    <span className="text-xs font-semibold text-slate-400 block mb-1">Total Findings</span>
                                    <span className="text-2xl sm:text-3xl font-black text-amber-400">{vulnerabilities.length}</span>
                                    <div className="text-[10px] text-slate-400 flex items-center gap-1.5 mt-1 font-mono">
                                        <span className="text-rose-400 font-bold">{severityStats.crit} Crit</span>
                                        <span>•</span>
                                        <span className="text-amber-400 font-bold">{severityStats.high} High</span>
                                        <span>•</span>
                                        <span className="text-cyan-400">{severityStats.med} Med</span>
                                    </div>
                                </div>
                                <div className="h-12 w-12 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 text-xl">
                                    <i className="fa-solid fa-bug"></i>
                                </div>
                            </div>

                            {/* Card 3: Validated Exploits */}
                            <div className="bg-dark-900 border border-dark-750 rounded-2xl p-4 sm:p-5 flex items-center justify-between shadow-lg">
                                <div>
                                    <span className="text-xs font-semibold text-slate-400 block mb-1">Validated Exploits</span>
                                    <span className="text-2xl sm:text-3xl font-black text-rose-400">{filterCounts.validated}</span>
                                    <span className="text-[11px] text-rose-400/90 block mt-1 font-medium">
                                        Sandbox PoC Verified
                                    </span>
                                </div>
                                <div className="h-12 w-12 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 text-xl">
                                    <i className="fa-solid fa-biohazard"></i>
                                </div>
                            </div>

                            {/* Card 4: Attack Chains */}
                            <div className="bg-dark-900 border border-dark-750 rounded-2xl p-4 sm:p-5 flex items-center justify-between shadow-lg">
                                <div>
                                    <span className="text-xs font-semibold text-slate-400 block mb-1">Lateral Attack Paths</span>
                                    <span className="text-2xl sm:text-3xl font-black text-purple-400">{attackPaths.length}</span>
                                    <span className="text-[11px] text-purple-300 block mt-1 font-medium">
                                        Chokepoints Identified
                                    </span>
                                </div>
                                <div className="h-12 w-12 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 text-xl">
                                    <i className="fa-solid fa-route"></i>
                                </div>
                            </div>
                        </section>


        </>
    );
};
export default MetricsSummary;
