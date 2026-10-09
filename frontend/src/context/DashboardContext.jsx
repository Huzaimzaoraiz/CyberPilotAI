import React, { createContext, useState, useEffect, useRef, useMemo } from 'react';
import { formatStopwatch, formatDurationHuman, escapeHtml } from '../utils/helpers';

export const DashboardContext = createContext();

export const DashboardProvider = ({ children }) => {
            // Data States
            const [session, setSession] = useState({
                is_active: false,
                started_at: null,
                completed_at: null,
                target: null,
                active_tasks_count: 0,
                total_tasks_count: 0
            });
            const [assets, setAssets] = useState([]);
            const [vulnerabilities, setVulnerabilities] = useState([]);
            const [attackPaths, setAttackPaths] = useState([]);
            const [queueTasks, setQueueTasks] = useState([]);
            
            // Stopwatch & Elapsed Time
            const [elapsedMs, setElapsedMs] = useState(0);

            // Controls & Filter States
            const [filter, setFilter] = useState('all');
            const [searchQuery, setSearchQuery] = useState('');
            const [autoRefresh, setAutoRefresh] = useState(true);
            const [countdown, setCountdown] = useState(3);
            const [isRefreshing, setIsRefreshing] = useState(false);
            const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'findings' | 'chains' | 'queue'
            
            // Target Form State
            const [targetDomain, setTargetDomain] = useState('');
            const [targetLayer, setTargetLayer] = useState('Web');
            const [isAuthorized, setIsAuthorized] = useState(true);
            const [includeCrownJewel, setIncludeCrownJewel] = useState(true);
            const [isSubmittingTarget, setIsSubmittingTarget] = useState(false);
            
            // Remediation Modal State
            const [modalVulnId, setModalVulnId] = useState(null);
            const [remediationPlan, setRemediationPlan] = useState(null);
            const [remediationLoading, setRemediationLoading] = useState(false);
            const [remediationError, setRemediationError] = useState(null);
            const [copySuccess, setCopySuccess] = useState(false);

            // Retest & Reset States
            const [retestingVulnId, setRetestingVulnId] = useState(null);
            const [isResetting, setIsResetting] = useState(false);
            const [toastMessage, setToastMessage] = useState(null);

            const toastTimeoutRef = useRef(null);
            const showToast = (msg) => {
                if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
                setToastMessage(msg);
                toastTimeoutRef.current = setTimeout(() => setToastMessage(null), 3500);
            };

            // --- Real-time Stopwatch Interval (Runs every 100ms) ---
            useEffect(() => {
                const timer = setInterval(() => {
                    if (session.is_active && session.started_at) {
                        const start = new Date(session.started_at).getTime();
                        const now = Date.now();
                        setElapsedMs(Math.max(0, now - start));
                    } else if (session.completed_at && session.started_at) {
                        const start = new Date(session.started_at).getTime();
                        const end = new Date(session.completed_at).getTime();
                        setElapsedMs(Math.max(0, end - start));
                    } else {
                        setElapsedMs(0);
                    }
                }, 100);
                return () => clearInterval(timer);
            }, [session.is_active, session.started_at, session.completed_at]);

            // --- Data Fetching Logic ---
            const fetchData = async (silent = false) => {
                if (!silent) setIsRefreshing(true);
                try {
                    const [sessRes, assetsRes, vulnsRes, pathsRes, tasksRes] = await Promise.all([
                        fetch('/api/v1/session'),
                        fetch('/api/v1/assets'),
                        fetch('/api/v1/vulnerabilities'),
                        fetch('/api/v1/attack-paths'),
                        fetch('/api/v1/queue')
                    ]);

                    if (sessRes.ok) {
                        const sessData = await sessRes.json();
                        setSession(sessData);
                    }
                    if (assetsRes.ok) setAssets(await assetsRes.json());
                    if (vulnsRes.ok) setVulnerabilities(await vulnsRes.json());
                    if (pathsRes.ok) setAttackPaths(await pathsRes.json());
                    if (tasksRes.ok) setQueueTasks(await tasksRes.json());
                } catch (err) {
                    console.error("Failed to fetch dashboard data:", err);
                } finally {
                    if (!silent) {
                        setTimeout(() => setIsRefreshing(false), 300);
                    }
                }
            };

            // Initial Fetch on Mount
            useEffect(() => {
                fetchData(false);
            }, []);

            // Auto-Refresh Polling Loop (Countdown 3s)
            useEffect(() => {
                const interval = setInterval(() => {
                    if (!autoRefresh) return;
                    setCountdown(prev => {
                        if (prev <= 1) {
                            fetchData(true);
                            return 3;
                        }
                        return prev - 1;
                    });
                }, 1000);
                return () => clearInterval(interval);
            }, [autoRefresh]);

            // --- Target Submission ---
            const handleTargetSubmit = async (e) => {
                e.preventDefault();
                const trimmedDomain = targetDomain.trim();
                if (!trimmedDomain) return;

                setIsSubmittingTarget(true);
                try {
                    const res = await fetch('/api/v1/targets', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            domain_or_ip: trimmedDomain,
                            layer: targetLayer,
                            is_authorized: isAuthorized,
                            include_simulated_crown_jewel: includeCrownJewel
                        })
                    });

                    if (!res.ok) {
                        const err = await res.json();
                        throw new Error(err.detail || 'Target launch failed.');
                    }

                    showToast(`Autonomous assessment launched for ${trimmedDomain}!`);
                    setTargetDomain('');
                    fetchData(false);
                } catch (err) {
                    alert("Submission failed: " + err.message);
                } finally {
                    setIsSubmittingTarget(false);
                }
            };

            // --- Reset Session to Standby ---
            const handleResetSession = async () => {
                if (!window.confirm("Are you sure you want to reset the engine to Standby? This will clear all discovered assets, tasks, and findings.")) {
                    return;
                }
                setIsResetting(true);
                try {
                    const res = await fetch('/api/v1/reset', { method: 'POST' });
                    if (res.ok) {
                        showToast("Engine returned to Standby mode. All metrics cleared.");
                        fetchData(false);
                    }
                } catch (err) {
                    alert("Failed to reset: " + err.message);
                } finally {
                    setIsResetting(false);
                }
            };

            // --- Remediation Modal Logic ---
            const openRemediation = async (vulnId) => {
                setModalVulnId(vulnId);
                setRemediationPlan(null);
                setRemediationError(null);
                setRemediationLoading(true);
                setCopySuccess(false);

                try {
                    const res = await fetch(`/api/v1/remediations/${vulnId}`);
                    if (!res.ok) {
                        setRemediationError("Remediation patch is currently being synthesized by Gemini 3.5 Flash-Lite. Please check back in a few seconds.");
                        return;
                    }
                    const data = await res.json();
                    setRemediationPlan(data);
                } catch (err) {
                    setRemediationError("Error loading remediation: " + err.message);
                } finally {
                    setRemediationLoading(false);
                }
            };

            const closeRemediation = () => {
                setModalVulnId(null);
                setRemediationPlan(null);
            };

            const copyPatchCode = () => {
                if (!remediationPlan?.patched_code_snippet) return;
                navigator.clipboard.writeText(remediationPlan.patched_code_snippet).then(() => {
                    setCopySuccess(true);
                    setTimeout(() => setCopySuccess(false), 2500);
                });
            };

            // --- Trigger Retesting ---
            const handleTriggerRetest = async (vulnId) => {
                setRetestingVulnId(vulnId);
                try {
                    const res = await fetch(`/api/v1/retest/${vulnId}`, { method: 'POST' });
                    const data = await res.json();
                    showToast(data.message || "Retest dispatched to orchestrator!");
                    fetchData(true);
                } catch (err) {
                    alert("Retest failed: " + err.message);
                } finally {
                    setRetestingVulnId(null);
                }
            };

            // Filtered Findings
            const filteredVulns = useMemo(() => {
                return vulnerabilities.filter(v => {
                    const matchesFilter = filter === 'all' || v.status === filter;
                    const matchesSearch = !searchQuery || 
                        v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                        v.discovery_source.toLowerCase().includes(searchQuery.toLowerCase()) ||
                        v.id.toLowerCase().includes(searchQuery.toLowerCase());
                    return matchesFilter && matchesSearch;
                });
            }, [vulnerabilities, filter, searchQuery]);

            // Filter Counts
            const filterCounts = useMemo(() => {
                return {
                    all: vulnerabilities.length,
                    validated: vulnerabilities.filter(v => v.status === 'validated').length,
                    remediated: vulnerabilities.filter(v => v.status === 'remediated').length,
                    unvalidated: vulnerabilities.filter(v => v.status === 'unvalidated').length,
                    false_positive: vulnerabilities.filter(v => v.status === 'false_positive').length
                };
            }, [vulnerabilities]);

            // Severity Breakdown
            const severityStats = useMemo(() => {
                let crit = 0, high = 0, med = 0, low = 0;
                vulnerabilities.forEach(v => {
                    if (v.criticality_score >= 9.0) crit++;
                    else if (v.criticality_score >= 7.0) high++;
                    else if (v.criticality_score >= 4.0) med++;
                    else low++;
                });
                return { crit, high, med, low };
            }, [vulnerabilities]);

            // Crown Jewels count
            const crownJewelsCount = useMemo(() => {
                return assets.filter(a => a.metadata && a.metadata.is_crown_jewel).length;
            }, [assets]);

            // Operational 10-Minute Progress Bar
            const tenMinMs = 10 * 60 * 1000; // 600,000 ms
            const operationalProgressPct = Math.min(100, Math.max(0, (elapsedMs / tenMinMs) * 100));

            // Selected Vuln for Modal
            const selectedVuln = useMemo(() => {
                return vulnerabilities.find(v => v.id === modalVulnId) || null;
            }, [vulnerabilities, modalVulnId]);

            // Active Agents from Queue
            const activeAgentsSet = useMemo(() => {
                const set = new Set();
                queueTasks.forEach(t => {
                    if (t.status === 'in_progress') {
                        set.add(t.target_agent.replace('_agent', ''));
                    }
                });
                return set;
            }, [queueTasks]);


    const contextValue = {
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
    };

    return (
        <DashboardContext.Provider value={contextValue}>
            {children}
        </DashboardContext.Provider>
    );
};
