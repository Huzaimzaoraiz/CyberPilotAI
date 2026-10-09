import React, { useContext } from 'react';
import { DashboardContext } from './context/DashboardContext';
import Header from './components/Header';
import TargetLaunchpad from './components/TargetLaunchpad';
import MetricsSummary from './components/MetricsSummary';
import AgentSwarmQueue from './components/AgentSwarmQueue';
import AttackPaths from './components/AttackPaths';
import FindingsTable from './components/FindingsTable';
import RemediationModal from './components/RemediationModal';

const AppContent = () => {
    const { toastMessage } = useContext(DashboardContext);

    return (
        <div className="min-h-screen flex flex-col bg-dark-950">
            {toastMessage && (
                <div className="fixed bottom-5 right-5 z-50 bg-dark-850 border border-cyan-500/50 text-cyan-300 px-4 py-3 rounded-xl shadow-2xl flex items-center gap-3 animate-bounce">
                    <i className="fa-solid fa-circle-check text-emerald-400 text-lg"></i>
                    <span className="text-xs font-semibold text-white">{toastMessage}</span>
                </div>
            )}
            
            <Header />
            <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 md:p-8 space-y-6">
                <TargetLaunchpad />
                <MetricsSummary />
                <AgentSwarmQueue />
                <AttackPaths />
                <FindingsTable />
                <RemediationModal />
            </main>
        </div>
    );
};

export default AppContent;
