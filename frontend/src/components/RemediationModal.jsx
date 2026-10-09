import React, { useContext } from 'react';
import { DashboardContext } from '../context/DashboardContext';

const RemediationModal = () => {

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
                    {/* --- 7. Remediation Studio Modal --- */}
                    {modalVulnId && (
                        <div className="fixed inset-0 bg-black/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                            <div className="bg-dark-900 border border-dark-750 rounded-2xl max-w-2xl w-full p-6 sm:p-7 shadow-2xl relative max-h-[90vh] flex flex-col animate-fade-in">
                                
                                {/* Close Button */}
                                <button 
                                    onClick={closeRemediation}
                                    className="absolute top-5 right-5 text-slate-400 hover:text-white text-lg transition">
                                    <i className="fa-solid fa-xmark"></i>
                                </button>

                                {/* Modal Header */}
                                <div className="flex items-center space-x-3 mb-4">
                                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 text-lg">
                                        <i className="fa-solid fa-code-merge"></i>
                                    </div>
                                    <div>
                                        <h3 className="text-base font-bold text-white">AI Remediation Studio</h3>
                                        <p className="text-xs text-slate-400">
                                            {selectedVuln ? selectedVuln.title : 'Automated Mitigation Patch'}
                                        </p>
                                    </div>
                                </div>

                                {/* Modal Body */}
                                <div className="flex-1 overflow-y-auto space-y-4 pr-1 text-xs">
                                    {remediationLoading ? (
                                        <div className="py-12 text-center text-slate-400 space-y-2">
                                            <i className="fa-solid fa-circle-notch fa-spin text-2xl text-cyan-400"></i>
                                            <p className="text-xs">Querying Gemini 3.5 Flash-Lite for code patch...</p>
                                        </div>
                                    ) : remediationError ? (
                                        <div className="bg-dark-850 border border-dark-700 rounded-xl p-4 text-center space-y-2">
                                            <i className="fa-solid fa-clock text-amber-400 text-xl"></i>
                                            <p className="text-slate-300">{remediationError}</p>
                                            <button 
                                                onClick={() => openRemediation(modalVulnId)}
                                                className="px-3 py-1 rounded bg-dark-800 text-cyan-400 border border-dark-700 text-xs">
                                                Retry Fetch
                                            </button>
                                        </div>
                                    ) : remediationPlan ? (
                                        <>
                                            {/* Root Cause Analysis */}
                                            <div className="bg-dark-850 border border-dark-700 rounded-xl p-4">
                                                <div className="font-bold text-emerald-400 mb-1.5 flex items-center gap-2">
                                                    <i className="fa-solid fa-stethoscope"></i> Root Cause Analysis
                                                </div>
                                                <p className="text-slate-300 leading-relaxed text-xs">
                                                    {remediationPlan.root_cause_analysis}
                                                </p>
                                            </div>

                                            {/* Tech Stack & Patch Classification */}
                                            <div className="grid grid-cols-2 gap-3 text-xs">
                                                <div className="bg-dark-850 border border-dark-700 rounded-xl p-3">
                                                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">Target Tech Stack</span>
                                                    <span className="font-bold text-white text-xs mt-0.5 block font-mono">
                                                        {remediationPlan.target_tech_stack}
                                                    </span>
                                                </div>
                                                <div className="bg-dark-850 border border-dark-700 rounded-xl p-3">
                                                    <span className="text-slate-400 block text-[10px] uppercase font-semibold">Patch Type</span>
                                                    <span className="font-bold text-cyan-400 uppercase text-xs mt-0.5 block font-mono">
                                                        {remediationPlan.patch_type}
                                                    </span>
                                                </div>
                                            </div>

                                            {/* Patched Code Snippet */}
                                            <div>
                                                <div className="flex items-center justify-between mb-1.5">
                                                    <span className="font-bold text-slate-200 flex items-center gap-1.5">
                                                        <i className="fa-solid fa-wrench text-amber-400"></i> Synthesized Code Patch
                                                    </span>
                                                    <button 
                                                        onClick={copyPatchCode}
                                                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold transition">
                                                        <i className={`fa-regular ${copySuccess ? 'fa-check text-emerald-400' : 'fa-copy'}`}></i>
                                                        <span>{copySuccess ? 'Copied!' : 'Copy Code'}</span>
                                                    </button>
                                                </div>
                                                <pre className="bg-dark-950 border border-dark-700 rounded-xl p-4 text-xs text-emerald-400 font-mono overflow-x-auto whitespace-pre-wrap select-all shadow-inner">
                                                    {remediationPlan.patched_code_snippet}
                                                </pre>
                                            </div>

                                            {/* Original Code Context (if available) */}
                                            {remediationPlan.original_code_snippet && remediationPlan.original_code_snippet !== 'N/A' && (
                                                <div>
                                                    <span className="font-bold text-slate-400 block mb-1">Vulnerable Context:</span>
                                                    <pre className="bg-dark-950 border border-dark-700 rounded-xl p-3 text-xs text-rose-400 font-mono overflow-x-auto whitespace-pre-wrap">
                                                        {remediationPlan.original_code_snippet}
                                                    </pre>
                                                </div>
                                            )}
                                        </>
                                    ) : null}
                                </div>

                                {/* Modal Footer */}
                                <div className="flex items-center justify-between pt-4 border-t border-dark-750 mt-4">
                                    <span className="text-[11px] text-slate-500 font-mono">
                                        Synthesized by Gemini 3.5 Flash-Lite
                                    </span>
                                    <div className="flex items-center space-x-3">
                                        <button 
                                            onClick={closeRemediation}
                                            className="px-4 py-2 text-xs text-slate-400 hover:text-white transition">
                                            Close
                                        </button>
                                        <button 
                                            onClick={() => {
                                                handleTriggerRetest(modalVulnId);
                                                closeRemediation();
                                            }}
                                            className="px-4 py-2 text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 rounded-xl transition flex items-center gap-2 shadow-lg shadow-emerald-500/20 active:scale-95">
                                            <i className="fa-solid fa-vial-circle-check"></i>
                                            <span>Verify Fix (Retest)</span>
                                        </button>
                                    </div>
                                </div>

                            </div>
                        </div>
                    )}


        </>
    );
};
export default RemediationModal;
