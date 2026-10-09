import React, { useContext } from 'react';
import { DashboardContext } from '../context/DashboardContext';

const AttackPaths = () => {

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
                        {/* --- 5. Lateral Attack Paths & Strategic Chokepoint Analysis --- */}
                        <section className="bg-dark-900 border border-dark-750 rounded-2xl p-5 sm:p-6 shadow-xl">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
                                <div>
                                    <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
                                        <i className="fa-solid fa-arrows-split-up-and-left text-purple-400"></i>
                                        Lateral Attack Chains & Strategic Chokepoints
                                    </h3>
                                    <p className="text-xs text-slate-400 mt-0.5">
                                        Identifies multi-hop movement from perimeter entrypoints to internal crown jewel databases, revealing strategic chokepoints.
                                    </p>
                                </div>
                                <span className="text-xs text-purple-300 font-semibold px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/30 self-start sm:self-auto">
                                    Graph Shortest Paths
                                </span>
                            </div>

                            {/* Attack Chains List */}
                            {attackPaths.length === 0 ? (
                                <div className="py-10 text-center text-slate-500 text-xs bg-dark-950/60 border border-dashed border-dark-700/80 rounded-xl">
                                    <i className="fa-solid fa-route text-3xl text-slate-600 mb-2 block"></i>
                                    No attack chains discovered yet. Ingest a target domain above to map attack vectors.
                                </div>
                            ) : (
                                <div className="space-y-4">
                                    {attackPaths.map((path, idx) => {
                                        // Resolve nodes
                                        const stepNodes = path.nodes.map(nodeId => {
                                            if (nodeId === 'INTERNET') {
                                                return { name: 'Public Internet', type: 'internet', icon: 'fa-globe', badge: 'Public Ingress' };
                                            }
                                            const asset = assets.find(a => a.id === nodeId);
                                            if (asset) {
                                                const isJewel = asset.metadata && asset.metadata.is_crown_jewel;
                                                return {
                                                    name: asset.asset_identifier,
                                                    type: isJewel ? 'jewel' : 'asset',
                                                    icon: isJewel ? 'fa-crown' : 'fa-server',
                                                    badge: isJewel ? 'Crown Jewel DB' : asset.layer
                                                };
                                            }
                                            return { name: nodeId.substring(0, 8), type: 'asset', icon: 'fa-server', badge: 'Asset' };
                                        });

                                        // Chokepoint vuln lookup
                                        const chokepointVuln = vulnerabilities.find(v => v.id === path.chokepoint_vuln_id);
                                        const chokepointTitle = chokepointVuln ? chokepointVuln.title : 'Perimeter Exploit';

                                        return (
                                            <div key={path.id || idx} className="bg-dark-850 border border-dark-700/90 rounded-2xl p-5 sm:p-6 space-y-6 shadow-2xl">
                                                
                                                {/* 1. Header & MITRE Tactics Bar */}
                                                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-4 border-b border-dark-750">
                                                    <div className="flex items-center space-x-2.5 flex-wrap gap-y-2">
                                                        <span className="px-3 py-1 rounded-lg text-xs font-black bg-rose-500/20 text-rose-300 border border-rose-500/40 tracking-wider">
                                                            CRITICAL RISK {path.total_risk_score ? path.total_risk_score.toFixed(1) : '9.5'}
                                                        </span>
                                                        <span className="text-sm text-white font-black tracking-tight">
                                                            Consolidated Attack Corridor
                                                        </span>
                                                        <span className="px-2.5 py-0.5 rounded-lg text-[11px] font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                                                            <i className="fa-solid fa-chart-line mr-1 text-[10px]"></i>
                                                            Chain Likelihood: {Math.round((path.path_probability || 0.85) * 100)}%
                                                        </span>
                                                        {path.grouped_vectors && path.grouped_vectors.length > 0 && (
                                                            <span className="px-2.5 py-0.5 rounded-lg text-[11px] font-bold bg-purple-500/10 text-purple-300 border border-purple-500/30">
                                                                <i className="fa-solid fa-layer-group mr-1 text-[10px]"></i>
                                                                {path.grouped_vectors.length} Grouped Entry Vectors
                                                            </span>
                                                        )}
                                                    </div>
                                                    
                                                    {/* MITRE ATT&CK Strip */}
                                                    {path.mitre_tactics && path.mitre_tactics.length > 0 && (
                                                        <div className="flex items-center gap-1.5 flex-wrap">
                                                            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mr-1">MITRE ATT&CK:</span>
                                                            {path.mitre_tactics.map((m, mIdx) => (
                                                                <span key={mIdx} className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-dark-800 text-slate-300 border border-dark-700" title={m.technique}>
                                                                    {m.id} <span className="text-purple-400 font-normal">{m.tactic}</span>
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>

                                                {/* 2. SIMPLIFIED & UNDERSTANDABLE FLOW: How the Attack Reaches the Crown Jewel DB */}
                                                <div className="bg-dark-900/90 border border-dark-750 rounded-xl p-4 sm:p-5 space-y-3 shadow-inner">
                                                    <div className="flex items-center justify-between flex-wrap gap-2">
                                                        <div className="flex items-center gap-2">
                                                            <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-cyan-500/20 text-cyan-400 text-xs">
                                                                <i className="fa-solid fa-route"></i>
                                                            </span>
                                                            <h4 className="text-sm font-bold text-white tracking-wide">
                                                                How the Attack Reaches {path.objective_name || 'the Target Asset'} (Simplified Flow)
                                                            </h4>
                                                        </div>
                                                        <span className="text-[11px] text-slate-400 font-mono">
                                                            End-to-End Exploitation Trajectory
                                                        </span>
                                                    </div>

                                                    {/* 4-Stage Visual Cards Grid */}
                                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
                                                        {(path.simplified_flow && path.simplified_flow.length > 0 ? path.simplified_flow : [
                                                            {
                                                                stage: 1,
                                                                stage_name: "Perimeter Ingress",
                                                                icon: "fa-globe",
                                                                color: "rose",
                                                                mitre_id: "T1190 / T1566",
                                                                headline: "Adversary Breaches Public Endpoints",
                                                                explanation: "Attacker probes public web endpoints, discovering SQLi, exposed .env configs, unauthenticated API routes, or phishing entrypoints."
                                                            },
                                                            {
                                                                stage: 2,
                                                                stage_name: "Secrets Extraction",
                                                                icon: "fa-key",
                                                                color: "amber",
                                                                mitre_id: "T1552 / T1078",
                                                                headline: "Harvests DB Credentials & Secrets",
                                                                explanation: "Using initial endpoint execution, the attacker dumps backend database connection strings, API tokens, and elevated server credentials."
                                                            },
                                                            {
                                                                stage: 3,
                                                                stage_name: "Lateral Firewall Bypass",
                                                                icon: "fa-arrows-split-up-and-left",
                                                                color: "purple",
                                                                mitre_id: "T1210 / T1021",
                                                                headline: "Pivots Past Perimeter Firewall",
                                                                explanation: "Internal firewall rules trust DMZ web server traffic, allowing the attacker to laterally route socket requests directly into the private subnet."
                                                            },
                                                            {
                                                                stage: 4,
                                                                stage_name: "Crown Jewel Breach",
                                                                icon: "fa-database",
                                                                color: "cyan",
                                                                mitre_id: "T1530 / T1005",
                                                                headline: "Crown Jewel Database Exfiltrated",
                                                                explanation: "Attacker establishes authenticated connection to the Crown Jewel database, extracting customer records and vault assets without triggering perimeter alerts."
                                                            }
                                                        ]).map((stageItem, stIdx) => {
                                                            let stageBorder = "border-rose-500/40 bg-rose-950/20 text-rose-300";
                                                            let stageIconBg = "bg-rose-500/20 text-rose-400";
                                                            if (stageItem.color === "amber") {
                                                                stageBorder = "border-amber-500/40 bg-amber-950/20 text-amber-300";
                                                                stageIconBg = "bg-amber-500/20 text-amber-400";
                                                            } else if (stageItem.color === "purple") {
                                                                stageBorder = "border-purple-500/40 bg-purple-950/20 text-purple-300";
                                                                stageIconBg = "bg-purple-500/20 text-purple-400";
                                                            } else if (stageItem.color === "cyan") {
                                                                stageBorder = "border-cyan-500/40 bg-cyan-950/20 text-cyan-300";
                                                                stageIconBg = "bg-cyan-500/20 text-cyan-400";
                                                            }

                                                            return (
                                                                <div key={stIdx} className={`border rounded-xl p-3.5 flex flex-col justify-between space-y-2 relative ${stageBorder}`}>
                                                                    <div>
                                                                        <div className="flex items-center justify-between gap-1 mb-1.5">
                                                                            <span className="text-[10px] font-black uppercase tracking-wider font-mono opacity-80">
                                                                                STAGE {stageItem.stage}
                                                                            </span>
                                                                            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-dark-950/80 border border-dark-700 text-slate-300">
                                                                                {stageItem.mitre_id}
                                                                            </span>
                                                                        </div>
                                                                        <div className="flex items-center gap-2 mb-1.5">
                                                                            <div className={`h-7 w-7 rounded-lg flex items-center justify-center text-xs flex-shrink-0 ${stageIconBg}`}>
                                                                                <i className={`fa-solid ${stageItem.icon}`}></i>
                                                                            </div>
                                                                            <span className="text-xs font-bold text-white leading-tight">
                                                                                {stageItem.stage_name}
                                                                            </span>
                                                                        </div>
                                                                        <p className="text-[11px] font-semibold text-slate-200 mb-1 leading-snug">
                                                                            {stageItem.headline}
                                                                        </p>
                                                                        <p className="text-[11px] text-slate-400 leading-relaxed">
                                                                            {stageItem.explanation}
                                                                        </p>
                                                                    </div>
                                                                </div>
                                                            );
                                                        })}
                                                    </div>

                                                    {/* Plain-English Attack Narrative */}
                                                    {path.attack_narrative && (
                                                        <div className="mt-3 bg-dark-950/90 border border-dark-800 rounded-xl p-3 text-xs text-slate-300 flex items-start gap-3">
                                                            <i className="fa-solid fa-book-open text-cyan-400 text-sm mt-0.5 flex-shrink-0"></i>
                                                            <div>
                                                                <span className="font-bold text-slate-200 block mb-0.5">
                                                                    Executive Attack Narrative:
                                                                </span>
                                                                <p className="text-[11px] text-slate-400 leading-relaxed">
                                                                    {path.attack_narrative}
                                                                </p>
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>

                                                {/* 3. GROUPED ATTACK VECTORS: Mentioning Same-Type Attacks Together */}
                                                {path.grouped_vectors && path.grouped_vectors.length > 0 && (
                                                    <div className="bg-dark-900/60 border border-dark-750 rounded-xl p-4 space-y-3 text-xs">
                                                        <div className="flex items-center justify-between flex-wrap gap-2">
                                                            <div className="flex items-center gap-2">
                                                                <i className="fa-solid fa-list-check text-purple-400 text-sm"></i>
                                                                <h5 className="font-bold text-slate-200">
                                                                    Unified Ingress Vectors (Grouped Perimeter Attack Points)
                                                                </h5>
                                                            </div>
                                                            <span className="text-[11px] text-slate-400 font-mono">
                                                                {path.grouped_vectors.length} Alternate Entry Vectors Lead to Target Objective
                                                            </span>
                                                        </div>

                                                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5 pt-1">
                                                            {path.grouped_vectors.map((vec, vIdx) => (
                                                                <div key={vIdx} className="bg-dark-950/80 border border-dark-800 hover:border-dark-700 rounded-xl p-3 flex flex-col justify-between space-y-2 transition">
                                                                    <div>
                                                                        <div className="flex items-center justify-between gap-1 mb-1">
                                                                            <span className="text-[10px] font-bold text-purple-300 uppercase tracking-wider flex items-center gap-1.5">
                                                                                <i className={`fa-solid ${vec.icon} text-purple-400`}></i>
                                                                                {vec.category}
                                                                            </span>
                                                                            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-dark-900 text-slate-300 border border-dark-750">
                                                                                {vec.mitre_technique}
                                                                            </span>
                                                                        </div>
                                                                        <span className="font-bold text-slate-200 text-xs block mb-1">
                                                                            {vec.title}
                                                                        </span>
                                                                        <p className="text-[11px] text-slate-400 leading-relaxed">
                                                                            {vec.description}
                                                                        </p>

                                                                        {vec.exploitation_path && (
                                                                            <div className="mt-2 pt-2 border-t border-dark-800 space-y-1 text-[10px]">
                                                                                <div className="text-purple-300 font-mono flex items-center gap-1 truncate">
                                                                                    <span className="font-bold text-slate-400">Vector:</span> {vec.exploitation_path.method}
                                                                                </div>
                                                                                {vec.exploitation_path.payload && (
                                                                                    <div className="bg-dark-900/90 rounded px-1.5 py-0.5 font-mono text-[9px] text-cyan-300 truncate border border-dark-800">
                                                                                        <span className="text-slate-500">PoC: </span>{vec.exploitation_path.payload}
                                                                                    </div>
                                                                                )}
                                                                                <div className="text-emerald-400/90 text-[10px] leading-tight">
                                                                                    <span className="text-slate-500">Capability: </span>{vec.exploitation_path.capability_gained}
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                    <div className="flex items-center justify-between pt-2 border-t border-dark-800/80 text-[10px] font-mono">
                                                                        <span className="text-amber-400 font-bold">
                                                                            Score: {vec.cvss_score ? vec.cvss_score.toFixed(1) : '7.0'}
                                                                        </span>
                                                                        <span className="text-slate-500">
                                                                            {vec.cwe}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* 4. Responsive Stepper Breadcrumbs (Asset Topology) */}
                                                <div>
                                                    <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                                        <i className="fa-solid fa-network-wired text-cyan-400"></i>
                                                        <span>Traversed Asset Topology</span>
                                                    </div>
                                                    <div className="flex items-center flex-wrap gap-y-2 py-1 overflow-x-auto">
                                                        {stepNodes.map((node, stepIdx) => {
                                                            let cardStyle = 'bg-dark-800 border-dark-700 text-slate-200';
                                                            let iconColor = 'text-cyan-400';

                                                            if (node.type === 'internet') {
                                                                cardStyle = 'bg-cyan-950/40 border-cyan-500/40 text-cyan-200';
                                                                iconColor = 'text-cyan-400';
                                                            } else if (node.type === 'jewel') {
                                                                cardStyle = 'bg-amber-950/40 border-amber-500/40 text-amber-200';
                                                                iconColor = 'text-amber-400';
                                                            }

                                                            return (
                                                                <React.Fragment key={stepIdx}>
                                                                    <div className={`border rounded-xl px-3.5 py-2 text-xs flex items-center gap-2.5 shadow-sm ${cardStyle}`}>
                                                                        <i className={`fa-solid ${node.icon} ${iconColor} text-sm`}></i>
                                                                        <div>
                                                                            <div className="font-bold leading-tight">{node.name}</div>
                                                                            <div className="text-[10px] opacity-75 font-mono mt-0.5">{node.badge}</div>
                                                                        </div>
                                                                    </div>
                                                                    {stepIdx < stepNodes.length - 1 && (
                                                                        <div className="px-2 text-purple-400 flex items-center justify-center">
                                                                            <i className="fa-solid fa-arrow-right text-xs"></i>
                                                                        </div>
                                                                    )}
                                                                </React.Fragment>
                                                            );
                                                        })}
                                                    </div>
                                                </div>

                                                {/* 5. Causal Step-by-Step Vulnerability Tracing */}
                                                {path.step_details && path.step_details.length > 0 && (
                                                    <div className="bg-dark-950/70 border border-dark-750 rounded-xl p-4 space-y-2.5 text-xs">
                                                        <div className="text-[11px] font-bold text-slate-400 flex items-center gap-1.5 uppercase tracking-wider">
                                                            <i className="fa-solid fa-link text-cyan-400"></i>
                                                            <span>Detailed Causal Transition Tracing</span>
                                                        </div>
                                                        <div className="space-y-2 pt-1">
                                                            {path.step_details.map((step, sIdx) => (
                                                                <div key={sIdx} className="flex items-start gap-2.5 bg-dark-900/80 border border-dark-800 rounded-lg p-2.5">
                                                                    <span className="h-5 w-5 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center text-[10px] font-mono font-bold flex-shrink-0 mt-0.5">
                                                                        {step.step}
                                                                    </span>
                                                                    <div className="flex-1 min-w-0">
                                                                        <div className="flex items-center justify-between gap-2 flex-wrap mb-0.5">
                                                                            <span className="font-bold text-slate-200">
                                                                                {step.from_node} <span className="text-purple-400 font-normal">→</span> {step.to_node}
                                                                            </span>
                                                                            <span className="px-2 py-0.2 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                                                                                Transition P: {Math.round(step.transition_probability * 100)}%
                                                                            </span>
                                                                        </div>
                                                                        <div className="text-slate-400 text-[11px] leading-relaxed">
                                                                            {step.reason}
                                                                        </div>
                                                                        {step.chain_mechanism && (
                                                                            <div className="mt-1.5 flex items-center gap-1.5 text-[10px] text-cyan-300 font-mono bg-cyan-950/40 border border-cyan-500/20 rounded px-2 py-0.5 w-fit">
                                                                                <i className="fa-solid fa-arrows-turn-to-dots text-cyan-400"></i>
                                                                                <span>Chaining: {step.chain_mechanism}</span>
                                                                            </div>
                                                                        )}
                                                                        {step.exploitation_path && typeof step.exploitation_path === 'object' && (
                                                                            <div className="mt-1.5 text-[10px] text-slate-400 font-mono bg-dark-950 rounded p-2 border border-dark-800 space-y-1">
                                                                                <div className="flex items-center justify-between gap-2 flex-wrap">
                                                                                    <span className="text-purple-300 font-semibold"><i className="fa-solid fa-crosshairs text-purple-400 mr-1"></i>Exploitation: {step.exploitation_path.method}</span>
                                                                                    <span className="text-[9px] bg-dark-900 text-slate-400 px-1.5 py-0.5 rounded border border-dark-800">{step.exploitation_path.mitre_technique}</span>
                                                                                </div>
                                                                                {step.exploitation_path.payload && (
                                                                                    <div className="text-[9px] text-cyan-300 bg-dark-900/80 px-1.5 py-0.5 rounded truncate border border-dark-850">
                                                                                        <span className="text-slate-500">PoC: </span>{step.exploitation_path.payload}
                                                                                    </div>
                                                                                )}
                                                                                <div className="text-emerald-400/90 text-[10px]">
                                                                                    <span className="text-slate-500">Capability Gained: </span>{step.exploitation_path.capability_gained}
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* 6. Strategic Chokepoint Action Banner */}
                                                <div className="bg-dark-950 border border-amber-500/30 rounded-xl p-4 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-inner">
                                                    <div className="flex items-start gap-3">
                                                        <div className="h-9 w-9 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/40 flex items-center justify-center text-base flex-shrink-0 mt-0.5">
                                                            <i className="fa-solid fa-crosshairs"></i>
                                                        </div>
                                                        <div>
                                                            <div className="flex items-center gap-2 flex-wrap mb-0.5">
                                                                <span className="font-bold text-amber-300 text-sm">
                                                                    Primary Strategic Chokepoint:
                                                                </span>
                                                                <span className="text-white font-bold text-xs bg-dark-850 px-2 py-0.5 rounded border border-dark-700">
                                                                    {chokepointTitle}
                                                                </span>
                                                            </div>
                                                            <span className="text-[11px] text-slate-400 block leading-relaxed">
                                                                Remediating this critical chokepoint eliminates the attacker's ingress capability and severs the causal progression to the Crown Jewel DB.
                                                            </span>
                                                        </div>
                                                    </div>
                                                    <button 
                                                        onClick={() => openRemediation(path.chokepoint_vuln_id)}
                                                        className="px-4 py-2 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-dark-950 font-black rounded-xl transition text-xs whitespace-nowrap active:scale-95 shadow-lg flex items-center justify-center gap-1.5">
                                                        <i className="fa-solid fa-wrench"></i>
                                                        Apply Chokepoint Patch
                                                    </button>
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
export default AttackPaths;
