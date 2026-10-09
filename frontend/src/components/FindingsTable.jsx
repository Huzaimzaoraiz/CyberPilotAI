import React, { useContext } from 'react';
import { DashboardContext } from '../context/DashboardContext';

const FindingsTable = () => {

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
                        {/* --- 6. Vulnerability Posture & Findings Studio --- */}
                        <section className="bg-dark-900 border border-dark-750 rounded-2xl p-5 sm:p-7 shadow-xl">
                            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                                <div>
                                    <h3 className="text-lg sm:text-xl font-bold text-white flex items-center gap-2">
                                        <i className="fa-solid fa-shield-virus text-rose-400"></i>
                                        Vulnerability Findings & Automated Fixes
                                    </h3>
                                    <p className="text-xs sm:text-sm text-slate-400 mt-1">
                                        Real-time findings, sandbox proof-of-concept verification, and AI-synthesized developer patches.
                                    </p>
                                </div>

                                {/* Search Input */}
                                <div className="w-full md:w-64">
                                    <div className="relative">
                                        <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 text-xs">
                                            <i className="fa-solid fa-magnifying-glass"></i>
                                        </span>
                                        <input 
                                            type="text" 
                                            placeholder="Search CVE, title, or asset..."
                                            value={searchQuery}
                                            onChange={(e) => setSearchQuery(e.target.value)}
                                            className="w-full bg-dark-950 border border-dark-700 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition" 
                                        />
                                    </div>
                                </div>
                            </div>

                            {/* Filter Tabs */}
                            <div className="flex items-center gap-1.5 flex-wrap bg-dark-950 p-1.5 rounded-xl border border-dark-750 text-xs mb-5">
                                {[
                                    { id: 'all', label: 'All Findings', count: filterCounts.all },
                                    { id: 'validated', label: 'Validated Exploitable', count: filterCounts.validated },
                                    { id: 'remediated', label: 'Remediated', count: filterCounts.remediated },
                                    { id: 'unvalidated', label: 'Unvalidated', count: filterCounts.unvalidated },
                                    { id: 'false_positive', label: 'False Positives', count: filterCounts.false_positive }
                                ].map(tab => (
                                    <button
                                        key={tab.id}
                                        onClick={() => setFilter(tab.id)}
                                        className={`px-3 py-1.5 rounded-lg font-bold transition flex items-center gap-1.5 ${
                                            filter === tab.id
                                                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                                                : 'text-slate-400 hover:text-white hover:bg-dark-800'
                                        }`}>
                                        <span>{tab.label}</span>
                                        <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${
                                            filter === tab.id ? 'bg-slate-950 text-cyan-400' : 'bg-dark-800 text-slate-400'
                                        }`}>
                                            {tab.count}
                                        </span>
                                    </button>
                                ))}
                            </div>

                            {/* Findings Cards Grid */}
                            {filteredVulns.length === 0 ? (
                                <div className="py-16 text-center text-slate-500 bg-dark-950/60 border border-dashed border-dark-700/80 rounded-2xl">
                                    <i className="fa-solid fa-radar fa-spin text-3xl mb-3 text-slate-600 block"></i>
                                    <p className="text-sm font-semibold text-slate-400">No vulnerabilities matching current criteria.</p>
                                    <p className="text-xs text-slate-500 mt-1">
                                        {vulnerabilities.length === 0 ? 'Submit a target domain or IP above to begin assessment.' : 'Try adjusting the filter or search query.'}
                                    </p>
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    {filteredVulns.map(vuln => {
                                        const asset = assets.find(a => a.id === vuln.asset_id);
                                        const assetName = asset ? asset.asset_identifier : vuln.asset_id;

                                        // CVSS score badge
                                        let cvssColor = 'bg-slate-800 text-slate-300 border-slate-700';
                                        if (vuln.criticality_score >= 9.0) cvssColor = 'bg-rose-500/20 text-rose-300 border-rose-500/40';
                                        else if (vuln.criticality_score >= 7.0) cvssColor = 'bg-amber-500/20 text-amber-300 border-amber-500/40';
                                        else if (vuln.criticality_score >= 4.0) cvssColor = 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';

                                        // Status badge
                                        let statusColor = 'bg-dark-800 text-slate-400 border-dark-700';
                                        if (vuln.status === 'validated') statusColor = 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40';
                                        if (vuln.status === 'remediated') statusColor = 'bg-blue-950/60 text-blue-300 border-blue-500/40';
                                        if (vuln.status === 'false_positive') statusColor = 'bg-dark-800 text-slate-500 border-dark-700';

                                        return (
                                            <div 
                                                key={vuln.id} 
                                                className="bg-dark-850 border border-dark-700/80 hover:border-dark-600 rounded-2xl p-5 flex flex-col justify-between transition shadow-md group">
                                                <div>
                                                    {/* Badges Row */}
                                                    <div className="flex items-start justify-between gap-2 mb-3">
                                                        <span className={`px-2.5 py-1 rounded-lg text-xs font-black border ${cvssColor}`}>
                                                            CVSS {vuln.criticality_score.toFixed(1)}
                                                        </span>
                                                        <div className="flex items-center gap-1.5 flex-wrap justify-end">
                                                            {vuln.metadata && vuln.metadata.mitre && vuln.metadata.mitre.technique_id && (
                                                                <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono font-bold" title={vuln.metadata.mitre.technique_name}>
                                                                    {vuln.metadata.mitre.technique_id}
                                                                </span>
                                                            )}
                                                            {vuln.metadata && vuln.metadata.phishing_score && (
                                                                <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30 font-bold">
                                                                    <i className="fa-solid fa-envelope-open-text mr-1"></i>
                                                                    Phish {vuln.metadata.phishing_score}/100
                                                                </span>
                                                            )}
                                                            {vuln.has_leaked_creds && (
                                                                <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold flex items-center gap-1">
                                                                    <i className="fa-solid fa-key"></i> LEAKED CREDS
                                                                </span>
                                                            )}
                                                            <span className={`px-2 py-0.5 rounded-md text-[10px] uppercase font-bold border ${statusColor}`}>
                                                                {vuln.status}
                                                            </span>
                                                        </div>
                                                    </div>

                                                    {/* Title */}
                                                    <h4 className="text-sm font-bold text-white mb-2 leading-snug group-hover:text-cyan-300 transition">
                                                        {vuln.title}
                                                    </h4>

                                                    {/* Asset and Source */}
                                                    <div className="text-xs text-slate-400 flex items-center gap-2 mb-3 flex-wrap">
                                                        <span className="truncate max-w-[200px]" title={assetName}>
                                                            <i className="fa-solid fa-server text-slate-500 mr-1"></i>
                                                            {assetName}
                                                        </span>
                                                        <span>•</span>
                                                        <span className="text-slate-400 uppercase text-[10px] font-mono whitespace-nowrap bg-dark-900 px-2 py-0.5 rounded border border-dark-800">
                                                            {vuln.discovery_source ? vuln.discovery_source.replace("TOOL_", "") : "SCANNER"}
                                                        </span>
                                                    </div>

                                                    {/* PoC Snippet Preview */}
                                                    {vuln.proof_of_concept && (
                                                        <div className="mt-2 bg-dark-950 border border-dark-750 rounded-xl p-3 font-mono text-xs text-slate-300">
                                                            <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1 font-sans">
                                                                <span>BENIGN PROOF-OF-CONCEPT</span>
                                                                <button 
                                                                    onClick={() => {
                                                                        navigator.clipboard.writeText(vuln.proof_of_concept);
                                                                        showToast("Proof-of-Concept copied!");
                                                                    }}
                                                                    className="text-cyan-400 hover:text-cyan-300 transition">
                                                                    Copy
                                                                </button>
                                                            </div>
                                                            <code className="text-cyan-300 block select-all break-all line-clamp-2">
                                                                {vuln.proof_of_concept}
                                                            </code>
                                                        </div>
                                                    )}
                                                </div>

                                                {/* Action Bar */}
                                                <div className="pt-4 mt-4 border-t border-dark-750 flex items-center justify-between gap-2">
                                                    <span className="text-[11px] text-slate-500 font-mono">
                                                        {vuln.id.substring(0, 8)}
                                                    </span>
                                                    <div className="flex items-center space-x-2">
                                                        <button 
                                                            onClick={() => openRemediation(vuln.id)}
                                                            className="px-3 py-1.5 text-xs bg-dark-800 hover:bg-dark-750 text-cyan-400 rounded-xl border border-cyan-500/30 transition flex items-center gap-1.5 font-semibold active:scale-95">
                                                            <i className="fa-solid fa-wrench text-[10px]"></i>
                                                            <span>AI Patch</span>
                                                        </button>
                                                        <button 
                                                            onClick={() => handleTriggerRetest(vuln.id)}
                                                            disabled={retestingVulnId === vuln.id}
                                                            className="px-3 py-1.5 text-xs bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 rounded-xl border border-emerald-500/30 transition flex items-center gap-1.5 font-semibold active:scale-95">
                                                            <i className={`fa-solid fa-vial text-[10px] ${retestingVulnId === vuln.id ? 'fa-spin' : ''}`}></i>
                                                            <span>Retest</span>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </section>

        </>
    );
};
export default FindingsTable;
