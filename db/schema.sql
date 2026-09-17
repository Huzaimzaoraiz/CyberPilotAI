-- =============================================================================
-- TECHQUEST: AUTONOMOUS CYBER-DEFENSE PLATFORM
-- POSTGRESQL RELATIONAL PERSISTENCE SCHEMA
-- Single Source of Truth for Autonomous Multi-Agent Swarm
-- =============================================================================

-- 1. ASSETS TABLE
CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(64) PRIMARY KEY,
    target TEXT NOT NULL,
    asset_type TEXT DEFAULT 'Web',
    host TEXT,
    port INT,
    protocol TEXT,
    is_authorized BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'done'))
);

-- 2. FINDINGS TABLE (Raw evidence from reconnaissance & initial audits)
-- Constraint: source MUST be strictly 'tool' or 'ai_inference'
CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    cve_id TEXT,
    source TEXT NOT NULL CHECK (source IN ('tool', 'ai_inference')),
    raw_evidence TEXT,
    criticality_score FLOAT DEFAULT 5.0,
    confidence_score FLOAT DEFAULT 0.5,
    has_leaked_creds BOOLEAN DEFAULT FALSE,
    layer TEXT DEFAULT 'Web',
    metadata JSONB DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'done'))
);

-- 3. VALIDATED FINDINGS TABLE (Proof-of-Concept & Sandboxed verification)
CREATE TABLE IF NOT EXISTS validated_findings (
    id VARCHAR(64) PRIMARY KEY,
    finding_id VARCHAR(64) REFERENCES findings(id) ON DELETE CASCADE,
    exploitable BOOLEAN DEFAULT FALSE,
    confidence_score FLOAT DEFAULT 0.0,
    cvss_score FLOAT DEFAULT 0.0,
    poc_exists BOOLEAN DEFAULT FALSE,
    validation_evidence TEXT,
    mitre_technique TEXT,
    validated_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'done' CHECK (status IN ('pending', 'processing', 'done'))
);

-- 4. ATTACK PATHS TABLE (Bayesian exploitation chains & Chokepoint identification)
CREATE TABLE IF NOT EXISTS attack_paths (
    id VARCHAR(64) PRIMARY KEY,
    path_nodes JSONB DEFAULT '[]'::jsonb,
    path_edges JSONB DEFAULT '[]'::jsonb,
    cumulative_risk FLOAT DEFAULT 0.0,
    break_chain_target TEXT,
    mitre_chain JSONB DEFAULT '[]'::jsonb,
    attack_narrative TEXT,
    simplified_flow JSONB DEFAULT '[]'::jsonb,
    grouped_vectors JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'done' CHECK (status IN ('pending', 'processing', 'done'))
);

-- 5. REMEDIATIONS TABLE (AI root-cause analyses & functional code patches)
CREATE TABLE IF NOT EXISTS remediations (
    id VARCHAR(64) PRIMARY KEY,
    finding_id VARCHAR(64) REFERENCES findings(id) ON DELETE CASCADE,
    attack_path_id VARCHAR(64),
    root_cause TEXT,
    fix_suggestion TEXT,
    code_snippet TEXT,
    target_tech_stack TEXT DEFAULT 'general',
    original_code_snippet TEXT,
    patch_type TEXT DEFAULT 'code',
    priority INT DEFAULT 50,
    applied BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'done'))
);

-- 6. RETESTS TABLE (Automated patch verification & lifecycle closure)
CREATE TABLE IF NOT EXISTS retests (
    id VARCHAR(64) PRIMARY KEY,
    finding_id VARCHAR(64) REFERENCES findings(id) ON DELETE CASCADE,
    remediation_id VARCHAR(64),
    still_vulnerable BOOLEAN DEFAULT TRUE,
    evidence TEXT,
    retested_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'done' CHECK (status IN ('pending', 'processing', 'done'))
);

-- 7. ORCHESTRATOR TASKS TABLE (Priority-driven asynchronous scheduling)
CREATE TABLE IF NOT EXISTS tasks (
    id VARCHAR(64) PRIMARY KEY,
    target_agent TEXT NOT NULL,
    priority INT NOT NULL,
    payload JSONB DEFAULT '{}'::jsonb,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- INDEXES for performance
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_validated_findings_finding_id ON validated_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_remediations_finding_id ON remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_tasks_priority_status ON tasks(priority DESC, status);
