const API_BASE = "";

class CloudVaultAPI {
    constructor() {
        this.token = localStorage.getItem("cloudvault_token") || null;
        this.eventSource = null;
    }

    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem("cloudvault_token", token);
        } else {
            localStorage.removeItem("cloudvault_token");
        }
    }

    async request(endpoint, options = {}) {
        const headers = options.headers || {};
        if (this.token && !headers["Authorization"]) {
            headers["Authorization"] = `Bearer ${this.token}`;
        }

        const config = {
            ...options,
            headers
        };

        try {
            const res = await fetch(API_BASE + endpoint, config);
            if (res.status === 401) {
                this.setToken(null);
                window.dispatchEvent(new CustomEvent("cloudvault_unauthorized"));
                throw new Error("Session expired. Please log in again.");
            }

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || data.message || "Request failed");
            }
            return data;
        } catch (err) {
            throw err;
        }
    }

    // Auth
    async register(email, password, full_name) {
        const data = await this.request("/api/v1/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password, full_name })
        });
        if (data.access_token) this.setToken(data.access_token);
        return data;
    }

    async login(email, password, mfa_code = null) {
        const payload = { email, password };
        if (mfa_code) payload.mfa_code = mfa_code;
        const data = await this.request("/api/v1/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (data.access_token) this.setToken(data.access_token);
        return data;
    }

    async getMe() {
        return await this.request("/api/v1/auth/me");
    }

    // Backups
    async getStats() {
        return await this.request("/api/v1/backups/stats");
    }

    async getPlans() {
        return await this.request("/api/v1/backups/plans");
    }

    async createPlan(planData) {
        return await this.request("/api/v1/backups/plans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(planData)
        });
    }

    async triggerBackup(planId) {
        return await this.request(`/api/v1/backups/plans/${planId}/trigger`, {
            method: "POST"
        });
    }

    async uploadFile(planId, file, relativePath = "") {
        const formData = new FormData();
        formData.append("plan_id", planId);
        formData.append("file", file);
        if (relativePath) {
            formData.append("relative_path", relativePath);
        }

        return await this.request("/api/v1/backups/upload-file", {
            method: "POST",
            body: formData
        });
    }

    async getJobs(limit = 20) {
        return await this.request(`/api/v1/backups/jobs?limit=${limit}`);
    }

    // Recovery & Immutability
    async getSnapshots(planId = null) {
        const query = planId ? `?plan_id=${planId}` : "";
        return await this.request(`/api/v1/recovery/snapshots${query}`);
    }

    async getSnapshotTree(snapshotId) {
        return await this.request(`/api/v1/recovery/snapshots/${snapshotId}/tree`);
    }

    async lockSnapshot(snapshotId, days = 30) {
        return await this.request(`/api/v1/recovery/snapshots/${snapshotId}/lock`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ lock_duration_days: days })
        });
    }

    async restoreFile(snapshotFileId, destinationDirectory, conflictStrategy = "overwrite") {
        return await this.request("/api/v1/recovery/restore-file", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                snapshot_file_id: snapshotFileId,
                destination_directory: destinationDirectory,
                conflict_strategy: conflictStrategy
            })
        });
    }

    async restoreSnapshot(snapshotId, destinationDirectory, conflictStrategy = "overwrite") {
        return await this.request("/api/v1/recovery/restore-snapshot", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                snapshot_id: snapshotId,
                destination_directory: destinationDirectory,
                conflict_strategy: conflictStrategy
            })
        });
    }

    async getDeletedFiles(planId) {
        return await this.request(`/api/v1/recovery/deleted-files?plan_id=${planId}`);
    }

    // Disaster Recovery Center
    async getDRMetrics() {
        return await this.request("/api/v1/dr/metrics");
    }

    async getDRCommandCenter() {
        return await this.request("/api/v1/dr/command-center");
    }

    async simulateDRDrill(snapshotId = null) {
        return await this.request("/api/v1/dr/simulate-drill", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ snapshot_id: snapshotId })
        });
    }

    async runAdvancedDRDrill(payload = {}) {
        return await this.request("/api/v1/dr/advanced-drill", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
    }

    async getDRDrillReport(drillId) {
        return await this.request(`/api/v1/dr/drills/${drillId}/report`);
    }

    async getPointInTimePreview(snapshotId, destinationDir = "") {
        let url = `/api/v1/dr/point-in-time/preview?snapshot_id=${encodeURIComponent(snapshotId)}`;
        if (destinationDir) {
            url += `&destination_dir=${encodeURIComponent(destinationDir)}`;
        }
        return await this.request(url);
    }

    async getRansomwareRecoveryPlan() {
        return await this.request("/api/v1/dr/ransomware-recovery/plan");
    }

    async executeRansomwareRecovery(payload = {}) {
        return await this.request("/api/v1/dr/ransomware-recovery/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
    }

    async runRecoverySandboxPreview(payload = {}) {
        return await this.request("/api/v1/dr/sandbox/preview", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
    }

    async getRecoveryOperations(limit = 20) {
        return await this.request(`/api/v1/dr/operations?limit=${limit}`);
    }

    async getDRHistory(limit = 20) {
        return await this.request(`/api/v1/dr/history?limit=${limit}`);
    }

    // Security & Ransomware
    async getSecurityHealth() {
        return await this.request("/api/v1/security/health");
    }

    async getSecurityAlerts(status = "ACTIVE") {
        return await this.request(`/api/v1/security/alerts?status=${status}`);
    }

    async dismissSecurityAlert(alertId, resolutionNotes = "Verified false positive") {
        return await this.request(`/api/v1/security/alerts/${alertId}/dismiss`, {
            method: "POST",
            body: JSON.stringify({ resolution_notes: resolutionNotes })
        });
    }

    async resolveSecurityAlert(alertId, resolutionNotes = "Threat resolved", unquarantine = true) {
        return await this.request(`/api/v1/security/alerts/${alertId}/resolve`, {
            method: "POST",
            body: JSON.stringify({ resolution_notes: resolutionNotes, unquarantine_snapshots: unquarantine })
        });
    }

    async simulateAttack(scenarioType = "mass_encryption") {
        return await this.request("/api/v1/security/simulate-test", {
            method: "POST",
            body: JSON.stringify({ scenario_type: scenarioType })
        });
    }

    async analyzeSecurityPath(planId = null, targetDirectory = null) {
        return await this.request("/api/v1/security/analyze-path", {
            method: "POST",
            body: JSON.stringify({ plan_id: planId, target_directory: targetDirectory })
        });
    }

    async getAuditLogs(limit = 30) {
        return await this.request(`/api/v1/security/audit-logs?limit=${limit}`);
    }

    // Predictive Analytics
    async getAnalyticsOverview() {
        return await this.request("/api/v1/analytics/overview");
    }

    async getStorageForecast() {
        return await this.request("/api/v1/analytics/storage-forecast");
    }

    async getHealthScore() {
        return await this.request("/api/v1/analytics/health-score");
    }

    async getTopLargeFiles(limit = 10) {
        return await this.request(`/api/v1/analytics/large-files?limit=${limit}`);
    }

    async getFailureTrends(lookbackDays = 30) {
        return await this.request(`/api/v1/analytics/failure-trends?lookback_days=${lookbackDays}`);
    }

    async getStorageOptimizations() {
        return await this.request("/api/v1/analytics/optimizations");
    }

    async getWeeklyReport() {
        return await this.request("/api/v1/analytics/weekly-report");
    }

    async getCadenceRecommendations() {
        return await this.request("/api/v1/analytics/cadence-recommendations");
    }

    // Multi-Cloud Storage Core
    async getMultiClouds() {
        return await this.request("/api/v1/storage/clouds");
    }

    async getStorageInventory() {
        return await this.request("/api/v1/storage/inventory");
    }

    async getStorageProviders() {
        return await this.request("/api/v1/storage/providers");
    }

    async checkAllProvidersHealth() {
        return await this.request("/api/v1/storage/health-all", { method: "POST" });
    }

    async getStorageTelemetry() {
        return await this.request("/api/v1/storage/telemetry");
    }

    async testStorageFailover(simulatePrimaryFailure = true, testPayload = "Failover verification payload") {
        return await this.request("/api/v1/storage/failover/test", {
            method: "POST",
            body: JSON.stringify({ simulate_primary_failure: simulatePrimaryFailure, test_payload: testPayload })
        });
    }

    async migrateSnapshotCloud(snapshotId, targetProvider, deleteSource = false) {
        return await this.request("/api/v1/storage/migrate", {
            method: "POST",
            body: JSON.stringify({ snapshot_id: snapshotId, target_provider: targetProvider, delete_source: deleteSource })
        });
    }

    async getStorageCosts() {
        return await this.request("/api/v1/storage/costs");
    }

    // Scheduler
    async getSchedulerStatus() {
        return await this.request("/api/v1/scheduler/status");
    }

    async startScheduler() {
        return await this.request("/api/v1/scheduler/start", { method: "POST" });
    }

    async stopScheduler() {
        return await this.request("/api/v1/scheduler/stop", { method: "POST" });
    }

    // AI Assistant
    async queryAI(prompt) {
        return await this.request("/api/v1/ai/query", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prompt })
        });
    }

    async confirmAIAction(confirmationToken) {
        return await this.request("/api/v1/ai/confirm-action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ confirmation_token: confirmationToken })
        });
    }

    async getAICapabilities() {
        return await this.request("/api/v1/ai/capabilities");
    }

    // Phase 4 Security Core Methods
    async getCryptoStatus() {
        return await this.request("/api/v1/security/crypto/status");
    }

    async rotateCryptoKey() {
        return await this.request("/api/v1/security/crypto/rotate-key", {
            method: "POST"
        });
    }

    async getMFAStatus() {
        return await this.request("/api/v1/auth/mfa/status");
    }

    async setupMFA() {
        return await this.request("/api/v1/auth/mfa/setup", {
            method: "POST"
        });
    }

    async enableMFA(secret, code) {
        return await this.request("/api/v1/auth/mfa/enable", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ secret, code })
        });
    }

    async disableMFA(password, code) {
        return await this.request("/api/v1/auth/mfa/disable", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password, code })
        });
    }

    async regenerateRecoveryCodes(password, code) {
        return await this.request("/api/v1/auth/mfa/regenerate-recovery-codes", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password, code })
        });
    }

    async verifyAuditTrail() {
        return await this.request("/api/v1/security/audit-logs/verify");
    }

    async lockSnapshotWORM(snapshotId, retentionDays = 30) {
        return await this.request(`/api/v1/recovery/snapshots/${snapshotId}/lock`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ retention_days: retentionDays })
        });
    }

    // Real-Time Server-Sent Events (SSE)
    connectSSE(onMessage, onError) {
        if (this.eventSource) {
            this.eventSource.close();
        }

        if (!this.token) return;

        try {
            const url = `${API_BASE}/api/v1/events/stream?token=${encodeURIComponent(this.token)}`;
            this.eventSource = new EventSource(url);

            this.eventSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (onMessage) onMessage(data);
                } catch (e) {
                    console.error("SSE parse error", e);
                }
            };

            this.eventSource.onerror = (err) => {
                if (onError) onError(err);
            };
        } catch (e) {
            console.warn("Could not establish SSE connection, using REST fallback:", e);
        }
    }

    disconnectSSE() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
    }
}

const api = new CloudVaultAPI();
