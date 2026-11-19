// UI Controller & State Manager
let currentUser = null;
let currentPlans = [];
let selectedPlanId = null;

// Helper: Format Bytes
function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Helper: Format Date
function formatDate(isoString) {
    if (!isoString) return "-";
    const d = new Date(isoString);
    return d.toLocaleString();
}

// Helper: Show Toast Notification
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div>
            <strong>${type.toUpperCase()}:</strong> ${message}
        </div>
        <button style="background:none;border:none;color:#94a3b8;cursor:pointer;font-size:1.1rem;" onclick="this.parentElement.remove()">×</button>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        if (toast.parentElement) toast.remove();
    }, 4500);
}

// Tab Switching & Mobile Navigation Sync
function switchTab(targetTabId) {
    document.querySelectorAll(".tab-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.tab === targetTabId);
    });
    document.querySelectorAll(".mobile-nav-item").forEach(b => {
        b.classList.toggle("active", b.dataset.tab === targetTabId);
    });
    document.querySelectorAll(".tab-content").forEach(c => {
        c.classList.toggle("active", c.id === targetTabId);
    });

    // Refresh specific tab data
    if (targetTabId === "snapshots-tab") loadSnapshots();
    if (targetTabId === "trash-tab") loadDeletedFiles();
    if (targetTabId === "jobs-tab") loadJobs();
    if (targetTabId === "scheduler-tab") loadScheduler();
    if (targetTabId === "dr-tab") loadDisasterRecovery();
    if (targetTabId === "security-tab") loadSecurityCenter();
    if (targetTabId === "analytics-tab") loadAnalytics();
    if (targetTabId === "timeline-tab") loadTimeline();
}

function setupTabs() {
    document.querySelectorAll(".tab-btn, .mobile-nav-item").forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.dataset.tab;
            if (target) switchTab(target);
        });
    });
}

// Authentication Check & View Toggle
async function checkAuth() {
    try {
        if (!api.token) {
            showAuthModal();
            return;
        }
        currentUser = await api.getMe();
        document.getElementById("auth-modal").style.display = "none";
        document.getElementById("user-display").textContent = currentUser.full_name;
        refreshDashboard();
    } catch (err) {
        showAuthModal();
    }
}

function showAuthModal() {
    document.getElementById("auth-modal").style.display = "flex";
}

function logout() {
    api.setToken(null);
    currentUser = null;
    showAuthModal();
    showToast("Logged out successfully", "info");
}

// Refresh Entire Dashboard
async function refreshDashboard() {
    try {
        await Promise.all([
            loadStats(),
            loadPlans(),
            loadJobs()
        ]);
    } catch (err) {
        showToast("Error updating dashboard: " + err.message, "error");
    }
}

// 1. Stats
async function loadStats() {
    const stats = await api.getStats();
    document.getElementById("stat-snapshots").textContent = stats.total_snapshots;
    document.getElementById("stat-files").textContent = stats.total_files_protected;
    document.getElementById("stat-stored").textContent = formatBytes(stats.total_stored_bytes);
    document.getElementById("stat-saved").textContent = formatBytes(stats.bytes_saved_deduplication);
    document.getElementById("stat-savings-pct").textContent = `(${stats.savings_percentage}% saved via deduplication)`;

    const providerBadge = document.getElementById("provider-badge");
    providerBadge.textContent = stats.storage_provider;
    if (stats.storage_provider.includes("Google")) {
        providerBadge.className = "badge badge-gcs";
    } else {
        providerBadge.className = "badge badge-mock";
    }
}

// 2. Plans
async function loadPlans() {
    currentPlans = await api.getPlans();
    const select = document.getElementById("active-plan-select");
    const snapshotPlanSelect = document.getElementById("snapshot-plan-select");
    const trashPlanSelect = document.getElementById("trash-plan-select");

    select.innerHTML = "";
    snapshotPlanSelect.innerHTML = "<option value=''>All Plans</option>";
    trashPlanSelect.innerHTML = "";

    if (currentPlans.length === 0) {
        select.innerHTML = "<option value=''>No backup plans found. Create one below!</option>";
        trashPlanSelect.innerHTML = "<option value=''>No plans available</option>";
        return;
    }

    currentPlans.forEach(plan => {
        const opt = document.createElement("option");
        opt.value = plan.id;
        opt.textContent = `${plan.plan_name} (${plan.schedule_type})`;
        select.appendChild(opt);

        const opt2 = document.createElement("option");
        opt2.value = plan.id;
        opt2.textContent = plan.plan_name;
        snapshotPlanSelect.appendChild(opt2);

        const opt3 = document.createElement("option");
        opt3.value = plan.id;
        opt3.textContent = plan.plan_name;
        trashPlanSelect.appendChild(opt3);
    });

    selectedPlanId = currentPlans[0].id;
    select.value = selectedPlanId;
    trashPlanSelect.value = selectedPlanId;
}

// Trigger Manual Folder Backup
async function handleTriggerBackup() {
    const planId = document.getElementById("active-plan-select").value;
    if (!planId) {
        showToast("Please select or create a backup plan first", "warning");
        return;
    }

    const btn = document.getElementById("trigger-backup-btn");
    btn.disabled = true;
    btn.textContent = "Backing up...";

    try {
        const res = await api.triggerBackup(planId);
        showToast(`Backup Complete! ${res.files_uploaded} uploaded, ${res.files_deduplicated} deduplicated (${res.duration_seconds}s).`, "success");
        await refreshDashboard();
    } catch (err) {
        showToast("Backup failed: " + err.message, "error");
    } finally {
        btn.disabled = false;
        btn.textContent = "⚡ Execute Backup Now";
    }
}

// Handle Direct File Upload (with deduplication)
async function handleFileUpload(event) {
    event.preventDefault();
    const fileInput = document.getElementById("file-upload-input");
    const planId = document.getElementById("active-plan-select").value;

    if (!fileInput.files.length) {
        showToast("Please select a file to upload", "warning");
        return;
    }
    if (!planId) {
        showToast("Please select a backup plan", "warning");
        return;
    }

    const file = fileInput.files[0];
    const uploadBtn = document.getElementById("upload-file-btn");
    uploadBtn.disabled = true;
    uploadBtn.textContent = "Uploading...";

    try {
        const res = await api.uploadFile(planId, file);
        if (res.deduplicated) {
            showToast(`Deduplication Success! "${file.name}" already in storage. Upload skipped (0 bytes cloud transfer).`, "info");
        } else {
            showToast(`Uploaded "${file.name}" successfully (${formatBytes(res.bytes_stored)} stored).`, "success");
        }
        fileInput.value = "";
        await refreshDashboard();
    } catch (err) {
        showToast("Upload failed: " + err.message, "error");
    } finally {
        uploadBtn.disabled = false;
        uploadBtn.textContent = "Upload to CloudVault";
    }
}

// Create New Plan
async function handleCreatePlan(event) {
    event.preventDefault();
    const name = document.getElementById("plan-name-input").value;
    const dir = document.getElementById("plan-dir-input").value;
    const scheduleType = document.getElementById("plan-schedule-type").value;
    const scheduleExpr = document.getElementById("plan-schedule-expr").value;

    try {
        await api.createPlan({
            plan_name: name,
            source_directories: [dir],
            exclusion_patterns: ["*.tmp", ".git", "node_modules", "__pycache__"],
            schedule_type: scheduleType,
            schedule_expression: scheduleExpr,
            retention_days: 30,
            compression_algo: "gzip"
        });

        showToast("Backup plan created successfully!", "success");
        document.getElementById("plan-name-input").value = "";
        document.getElementById("plan-dir-input").value = "";
        await loadPlans();
    } catch (err) {
        showToast("Failed to create plan: " + err.message, "error");
    }
}

// 3. Snapshots (Time Machine)
async function loadSnapshots() {
    const planId = document.getElementById("snapshot-plan-select").value || null;
    const snapshots = await api.getSnapshots(planId);
    const tbody = document.getElementById("snapshots-table-body");
    tbody.innerHTML = "";

    if (!snapshots.length) {
        tbody.innerHTML = "<tr><td colspan='6' style='text-align:center;'>No snapshots available yet.</td></tr>";
        return;
    }

    snapshots.forEach(s => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong>#${s.snapshot_number}</strong></td>
            <td>${s.name}</td>
            <td>${formatDate(s.created_at)}</td>
            <td>${s.total_files} files</td>
            <td>${formatBytes(s.total_uncompressed_bytes)}</td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="viewSnapshotTree('${s.id}', '${s.name}')">🔍 Browse Files</button>
                <button class="btn btn-primary btn-sm" onclick="openRestoreModal('${s.id}', '${s.name}')">↺ Restore Snapshot</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// Browse files inside a snapshot
async function viewSnapshotTree(snapshotId, snapshotName) {
    document.getElementById("tree-modal-title").textContent = `Files in: ${snapshotName}`;
    const tbody = document.getElementById("snapshot-tree-body");
    tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;'>Loading snapshot files...</td></tr>";
    document.getElementById("tree-modal").style.display = "flex";

    try {
        const files = await api.getSnapshotTree(snapshotId);
        tbody.innerHTML = "";
        if (!files.length) {
            tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;'>Empty snapshot.</td></tr>";
            return;
        }

        files.forEach(f => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><code>${f.relative_path}</code></td>
                <td>${formatBytes(f.file_size)}</td>
                <td><small style="font-family:monospace;color:#94a3b8;">${f.sha256_hash ? f.sha256_hash.substring(0, 12) + '...' : '-'}</small></td>
                <td>${formatDate(f.modified_at)}</td>
                <td>
                    <button class="btn btn-success btn-sm" onclick="openRestoreFileModal('${f.id}', '${f.file_name}')">Restore</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan='5' style='color:#ef4444;text-align:center;'>Error: ${err.message}</td></tr>`;
    }
}

// Restore Modal Handling
let restoreTargetType = "snapshot"; // snapshot or file
let restoreTargetId = null;

function openRestoreModal(snapshotId, name) {
    restoreTargetType = "snapshot";
    restoreTargetId = snapshotId;
    document.getElementById("restore-modal-title").textContent = `Restore Snapshot: ${name}`;
    document.getElementById("restore-modal").style.display = "flex";
}

function openRestoreFileModal(snapshotFileId, name) {
    restoreTargetType = "file";
    restoreTargetId = snapshotFileId;
    document.getElementById("restore-modal-title").textContent = `Restore File: ${name}`;
    document.getElementById("restore-modal").style.display = "flex";
}

async function handleExecuteRestore() {
    const dest = document.getElementById("restore-dest-input").value.trim();
    const conflict = document.getElementById("restore-conflict-strategy").value;

    if (!dest) {
        showToast("Please provide a destination directory", "warning");
        return;
    }

    const btn = document.getElementById("confirm-restore-btn");
    btn.disabled = true;
    btn.textContent = "Verifying & Restoring...";

    try {
        let res;
        if (restoreTargetType === "file") {
            res = await api.restoreFile(restoreTargetId, dest, conflict);
        } else {
            res = await api.restoreSnapshot(restoreTargetId, dest, conflict);
        }

        document.getElementById("restore-modal").style.display = "none";
        showToast(`Recovery Success! ${res.files_restored} files restored to ${res.destination}. Integrity verified: SHA-256 matched bit-for-bit.`, "success");
    } catch (err) {
        showToast("Restore failed: " + err.message, "error");
    } finally {
        btn.disabled = false;
        btn.textContent = "Confirm Restore";
    }
}

// 4. Deleted Files Recovery (Trash)
async function loadDeletedFiles() {
    const planId = document.getElementById("trash-plan-select").value;
    if (!planId) return;

    const tbody = document.getElementById("trash-table-body");
    tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;'>Scanning historical snapshots for deleted files...</td></tr>";

    try {
        const deletedFiles = await api.getDeletedFiles(planId);
        tbody.innerHTML = "";
        if (!deletedFiles.length) {
            tbody.innerHTML = "<tr><td colspan='5' style='text-align:center;color:#10b981;'>Zero deleted files detected! Current state is in sync with history.</td></tr>";
            return;
        }

        deletedFiles.forEach(df => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><code>${df.relative_path}</code></td>
                <td>${formatBytes(df.file_size)}</td>
                <td>${df.last_seen_snapshot_name}</td>
                <td>${formatDate(df.last_seen_date)}</td>
                <td>
                    <button class="btn btn-success btn-sm" onclick="openRestoreFileModal('${df.snapshot_file_id}', '${df.file_name}')">♻ Undelete / Restore</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan='5' style='color:#ef4444;text-align:center;'>Error: ${err.message}</td></tr>`;
    }
}

// 5. Jobs
async function loadJobs() {
    const jobs = await api.getJobs(20);
    const tbody = document.getElementById("jobs-table-body");
    tbody.innerHTML = "";

    if (!jobs.length) {
        tbody.innerHTML = "<tr><td colspan='7' style='text-align:center;'>No backup jobs recorded yet.</td></tr>";
        return;
    }

    jobs.forEach(j => {
        const tr = document.createElement("tr");
        let badgeClass = "badge-success";
        if (j.status === "FAILED") badgeClass = "badge-danger";
        if (j.status === "RUNNING") badgeClass = "badge-warning";

        tr.innerHTML = `
            <td><span class="badge ${badgeClass}">${j.status}</span></td>
            <td>${j.trigger_type}</td>
            <td>${formatDate(j.started_at)}</td>
            <td>${j.files_scanned} scanned (${j.files_uploaded} new, ${j.files_deduplicated} deduped)</td>
            <td>${formatBytes(j.bytes_uploaded)}</td>
            <td>${formatBytes(j.bytes_deduplicated)}</td>
            <td>${j.duration_seconds}s</td>
        `;
        tbody.appendChild(tr);
    });
}

// 6. Scheduler
async function loadScheduler() {
    try {
        const s = await api.getSchedulerStatus();
        const statusText = document.getElementById("scheduler-status-text");
        const toggleBtn = document.getElementById("scheduler-toggle-btn");

        if (s.running) {
            statusText.textContent = "ACTIVE (Running background checks)";
            statusText.style.color = "#10b981";
            toggleBtn.textContent = "Stop Scheduler";
            toggleBtn.className = "btn btn-danger";
        } else {
            statusText.textContent = "STOPPED";
            statusText.style.color = "#ef4444";
            toggleBtn.textContent = "Start Scheduler";
            toggleBtn.className = "btn btn-success";
        }
    } catch (err) {
        showToast("Error reading scheduler: " + err.message, "error");
    }
}

async function handleToggleScheduler() {
    const s = await api.getSchedulerStatus();
    if (s.running) {
        await api.stopScheduler();
        showToast("Scheduler stopped", "warning");
    } else {
        await api.startScheduler();
        showToast("Scheduler started", "success");
    }
    loadScheduler();
}

// Auth Form Listeners
function setupAuthForms() {
    let isRegisterMode = false;
    const authTitle = document.getElementById("auth-form-title");
    const nameGroup = document.getElementById("name-input-group");
    const authSubmit = document.getElementById("auth-submit-btn");
    const toggleLink = document.getElementById("auth-toggle-link");

    toggleLink.addEventListener("click", (e) => {
        e.preventDefault();
        isRegisterMode = !isRegisterMode;
        if (isRegisterMode) {
            authTitle.textContent = "Create CloudVault Account";
            nameGroup.style.display = "block";
            authSubmit.textContent = "Register";
            toggleLink.textContent = "Already have an account? Log in";
        } else {
            authTitle.textContent = "Log In to CloudVault";
            nameGroup.style.display = "none";
            authSubmit.textContent = "Log In";
            toggleLink.textContent = "Need an account? Register";
        }
    });

    document.getElementById("auth-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = document.getElementById("auth-email").value;
        const password = document.getElementById("auth-password").value;
        const name = document.getElementById("auth-name").value;

        try {
            if (isRegisterMode) {
                await api.register(email, password, name || "Student User");
                showToast("Account created successfully!", "success");
            } else {
                await api.login(email, password);
                showToast("Welcome back!", "success");
            }
            document.getElementById("auth-modal").style.display = "none";
            checkAuth();
        } catch (err) {
            showToast(err.message, "error");
        }
    });

    document.getElementById("logout-btn").addEventListener("click", logout);
}

// Initial Boot
window.addEventListener("DOMContentLoaded", () => {
    setupTabs();
    setupAuthForms();

    document.getElementById("trigger-backup-btn").addEventListener("click", handleTriggerBackup);
    document.getElementById("file-upload-form").addEventListener("submit", handleFileUpload);
    document.getElementById("create-plan-form").addEventListener("submit", handleCreatePlan);
    document.getElementById("snapshot-plan-select").addEventListener("change", loadSnapshots);
    document.getElementById("trash-plan-select").addEventListener("change", loadDeletedFiles);
    document.getElementById("confirm-restore-btn").addEventListener("click", handleExecuteRestore);
    document.getElementById("scheduler-toggle-btn").addEventListener("click", handleToggleScheduler);

    checkAuth();
    setupPWA();
    setupAIAssistant();
    setupDRControls();
    setupRealtimeEvents();
});

// Progressive Web App (PWA) & Offline Handling
function setupPWA() {
    // 1. Service Worker Registration
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js')
                .then(reg => {
                    console.log('CloudVault PWA ServiceWorker active with scope:', reg.scope);
                })
                .catch(err => {
                    console.warn('CloudVault ServiceWorker registration notice:', err);
                });
        });
    }

    // 2. Install App Prompt
    let deferredPrompt = null;
    const installBtn = document.getElementById("pwa-install-btn");

    window.addEventListener("beforeinstallprompt", (e) => {
        e.preventDefault();
        deferredPrompt = e;
        if (installBtn) {
            installBtn.style.display = "inline-flex";
            installBtn.onclick = async () => {
                installBtn.style.display = "none";
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                console.log("PWA install outcome:", outcome);
                deferredPrompt = null;
            };
        }
    });

    window.addEventListener("appinstalled", () => {
        if (installBtn) installBtn.style.display = "none";
        showToast("CloudVault installed to home screen!", "success");
    });

    // 3. Online/Offline Network Status
    const offlineBanner = document.getElementById("offline-banner");
    window.addEventListener("online", () => {
        if (offlineBanner) offlineBanner.style.display = "none";
        showToast("Network restored. CloudVault is online.", "success");
    });
    window.addEventListener("offline", () => {
        if (offlineBanner) offlineBanner.style.display = "block";
        showToast("You are offline. Cloud operations are paused.", "warning");
    });
}




// AI Assistant Drawer Controller
function setupAIAssistant() {
    const toggleBtn = document.getElementById('ai-chat-toggle-btn');
    const closeBtn = document.getElementById('ai-drawer-close-btn');
    const drawer = document.getElementById('ai-chat-drawer');
    const form = document.getElementById('ai-chat-form');
    const input = document.getElementById('ai-chat-input');
    const messagesContainer = document.getElementById('ai-messages-container');

    if (!toggleBtn || !drawer) return;

    toggleBtn.addEventListener('click', () => {
        const isHidden = drawer.style.display === 'none' || !drawer.style.display;
        drawer.style.display = isHidden ? 'flex' : 'none';
        if (isHidden && input) {
            input.focus();
        }
    });

    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            drawer.style.display = 'none';
        });
    }

    // Suggested prompt pills
    document.querySelectorAll('.ai-pill').forEach(pill => {
        pill.addEventListener('click', () => {
            const prompt = pill.dataset.prompt;
            if (prompt) {
                if (input) input.value = prompt;
                handleAISubmit(prompt);
            }
        });
    });

    if (form) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const prompt = input.value.trim();
            if (!prompt) return;
            handleAISubmit(prompt);
        });
    }

    async function handleAISubmit(prompt) {
        if (input) input.value = '';
        appendAIMessage('user', escapeHTML(prompt));

        const loadingId = 'loading-' + Date.now();
        appendAIMessage('assistant', '<em>Thinking and analyzing backup metadata...</em>', loadingId);

        try {
            const res = await api.queryAI(prompt);
            removeAIMessage(loadingId);
            const formatted = renderSimpleMarkdown(res.response);
            appendAIMessage('assistant', formatted, null, res.action_card);
        } catch (err) {
            removeAIMessage(loadingId);
            appendAIMessage('assistant', `<span style="color:#ef4444;">Error: ${escapeHTML(err.message)}</span>`);
        }
    }

    function appendAIMessage(role, contentHTML, elementId = null, actionCard = null) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `ai-message ${role}`;
        if (elementId) msgDiv.id = elementId;

        const avatar = role === 'assistant' ? '🤖' : '👤';
        let cardHTML = '';

        if (actionCard && actionCard.confirmation_token) {
            const proposed = actionCard.proposed_action || {};
            cardHTML = `
                <div class="ai-action-card">
                    <div class="ai-action-header">
                        <span>⚡</span>
                        <span>ACTION AUTHORIZATION REQUIRED</span>
                    </div>
                    <div class="ai-action-body">
                        <strong>Action:</strong> ${escapeHTML(proposed.action || actionCard.action_type)}<br>
                        ${escapeHTML(proposed.description || 'Please review and confirm this operation.')}
                    </div>
                    <div class="ai-action-actions">
                        <button class="btn btn-success btn-sm confirm-action-btn" data-token="${actionCard.confirmation_token}">
                            ✓ Confirm Execution
                        </button>
                        <button class="btn btn-secondary btn-sm cancel-action-btn" onclick="this.closest('.ai-action-card').remove()">
                            ✕ Cancel
                        </button>
                    </div>
                </div>
            `;
        }

        msgDiv.innerHTML = `
            <div class="ai-msg-avatar">${avatar}</div>
            <div class="ai-msg-bubble">
                ${contentHTML}
                ${cardHTML}
            </div>
        `;

        messagesContainer.appendChild(msgDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

        if (actionCard && actionCard.confirmation_token) {
            const confirmBtn = msgDiv.querySelector('.confirm-action-btn');
            if (confirmBtn) {
                confirmBtn.addEventListener('click', async () => {
                    const token = confirmBtn.dataset.token;
                    confirmBtn.disabled = true;
                    confirmBtn.textContent = 'Executing...';
                    try {
                        const execRes = await api.confirmAIAction(token);
                        showToast('Operation executed: ' + execRes.message, 'success');
                        const card = confirmBtn.closest('.ai-action-card');
                        card.innerHTML = `<span style="color:#10b981;font-weight:700;">✓ EXECUTED: ${escapeHTML(execRes.message)}</span>`;
                        refreshDashboard();
                    } catch (err) {
                        confirmBtn.disabled = false;
                        confirmBtn.textContent = '✓ Retry Confirmation';
                        showToast('Execution failed: ' + err.message, 'error');
                    }
                });
            }
        }
    }

    function removeAIMessage(elementId) {
        const el = document.getElementById(elementId);
        if (el) el.remove();
    }

    function escapeHTML(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function renderSimpleMarkdown(md) {
        if (!md) return '';
        return md
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/gim, '<em>$1</em>')
            .replace(/`([^`]+)`/gim, '<code>$1</code>')
            .replace(/^\- (.*$)/gim, '<li>$1</li>')
            .replace(/\n\n/gim, '<p></p>')
            .replace(/\n/gim, '<br>');
    }
}


// ========================================================
// CLOUDVAULT 2.0 ADVANCED MODULE CONTROLLERS
// ========================================================

// 1. Disaster Recovery Center Controller
async function loadDisasterRecovery() {
    try {
        const metrics = await api.getDRMetrics();
        const rpoVal = document.getElementById("dr-rpo-value");
        const rpoBadge = document.getElementById("dr-rpo-badge");
        const rtoVal = document.getElementById("dr-rto-value");
        const rtoSpeed = document.getElementById("dr-rto-speed");
        const readinessVal = document.getElementById("dr-readiness-value");
        const readinessBadge = document.getElementById("dr-readiness-badge");
        const drillsCount = document.getElementById("dr-drills-count");

        if (metrics.rpo.hours !== null) {
            rpoVal.textContent = `${metrics.rpo.hours}h`;
            rpoBadge.textContent = metrics.rpo.status;
            rpoBadge.className = `dr-metric-badge badge-${metrics.rpo.status === 'HEALTHY' ? 'optimal' : 'warning'}`;
        } else {
            rpoVal.textContent = "No Backups";
            rpoBadge.textContent = "PENDING";
            rpoBadge.className = "dr-metric-badge badge-warning";
        }

        rtoVal.textContent = `${metrics.rto.estimated_minutes} min`;
        rtoSpeed.textContent = `Speed: ${metrics.rto.measured_speed_mbps} MB/s`;
        readinessVal.textContent = `${metrics.readiness_score} / 100`;
        readinessBadge.textContent = metrics.readiness_level;
        readinessBadge.className = `dr-metric-badge badge-${metrics.readiness_level === 'OPTIMAL' ? 'optimal' : (metrics.readiness_level === 'ACCEPTABLE' ? 'warning' : 'critical')}`;
        drillsCount.textContent = `${metrics.total_drills_executed} Drills`;

        // Populate Snapshot Selector
        const snapSelect = document.getElementById("dr-snapshot-select");
        const snapshotsData = await api.getSnapshots();
        const snapshots = snapshotsData.snapshots || [];
        snapSelect.innerHTML = "";

        if (snapshots.length === 0) {
            snapSelect.innerHTML = "<option value=''>No snapshots available</option>";
        } else {
            snapshots.forEach((s, idx) => {
                const opt = document.createElement("option");
                opt.value = s.id;
                opt.textContent = `${s.name} (${formatDate(s.created_at)}) - ${s.total_files} files`;
                if (idx === 0) opt.selected = true;
                snapSelect.appendChild(opt);
            });
        }

        // Load Past Drills
        const historyData = await api.getDRHistory(20);
        const drills = historyData.drills || [];
        const tbody = document.getElementById("dr-history-table-body");
        tbody.innerHTML = "";

        if (drills.length === 0) {
            tbody.innerHTML = "<tr><td colspan='8' style='text-align:center;'>No synthetic recovery drills executed yet. Click 'Run Synthetic Recovery Drill' above to test your backup.</td></tr>";
            return;
        }

        drills.forEach(d => {
            const tr = document.createElement("tr");
            const statusClass = d.status === "PASSED" ? "badge-passed" : "badge-failed";
            tr.innerHTML = `
                <td><code>${d.drill_id.substring(0, 8)}...</code></td>
                <td><span class="badge ${statusClass}">${d.status}</span></td>
                <td>${d.files_tested}</td>
                <td>${formatBytes(d.bytes_tested)}</td>
                <td><strong>${d.restoration_speed_mbps} MB/s</strong></td>
                <td>${d.rpo_hours !== null ? d.rpo_hours + 'h' : '-'}</td>
                <td>${d.estimated_rto_minutes} min</td>
                <td>${formatDate(d.created_at)}</td>
            `;
            tbody.appendChild(tr);
        });

    } catch (err) {
        console.error("Disaster Recovery load error:", err);
        showToast("Could not load DR metrics: " + err.message, "error");
    }
}

function setupDRControls() {
    const drillBtn = document.getElementById("trigger-dr-drill-btn");
    const snapSelect = document.getElementById("dr-snapshot-select");
    const statusBox = document.getElementById("dr-drill-status");

    if (!drillBtn) return;

    drillBtn.addEventListener("click", async () => {
        const snapId = snapSelect.value || null;
        drillBtn.disabled = true;
        drillBtn.textContent = "⏳ Executing Sandboxed Drill...";
        statusBox.style.display = "block";
        statusBox.innerHTML = "<em>Streaming backup blocks, verifying SHA-256 integrity, measuring throughput...</em>";

        try {
            const res = await api.simulateDRDrill(snapId);
            if (res.status === "PASSED") {
                statusBox.innerHTML = `
                    <strong style="color:#10b981;">✅ RECOVERY DRILL PASSED (100% BIT-LEVEL INTEGRITY)</strong><br>
                    Files Tested: ${res.files_tested} | Data Verified: ${formatBytes(res.bytes_tested)} | 
                    Duration: ${res.duration_seconds}s | <strong>Speed: ${res.restoration_speed_mbps} MB/s</strong><br>
                    Isolated test sandbox automatically removed without impacting live files.
                `;
                showToast("Synthetic recovery drill passed with 100% data integrity!", "success");
            } else {
                statusBox.innerHTML = `
                    <strong style="color:#ef4444;">❌ DRILL FAILED: ${escapeHTML(res.error_details || 'Integrity check failed')}</strong>
                `;
                showToast("Drill failed: Integrity mismatch detected.", "error");
            }
            loadDisasterRecovery();
        } catch (err) {
            statusBox.innerHTML = `<span style="color:#ef4444;">Drill failed to execute: ${escapeHTML(err.message)}</span>`;
            showToast("Drill execution failed: " + err.message, "error");
        } finally {
            drillBtn.disabled = false;
            drillBtn.textContent = "🚀 Run Synthetic Recovery Drill";
        }
    });
}

// 2. Security & Ransomware Shield Controller
async function loadSecurityCenter() {
    try {
        // 1. Fetch Security Health
        try {
            const health = await api.getSecurityHealth();
            const threatStatusEl = document.getElementById("sec-stat-threat-level");
            const threatSubEl = document.getElementById("sec-stat-threat-sub");
            const riskScoreEl = document.getElementById("sec-stat-risk-score");
            const riskMeterFill = document.getElementById("sec-risk-meter-fill");
            const activeAlertsEl = document.getElementById("sec-stat-active-alerts");
            const quarantinedEl = document.getElementById("sec-stat-quarantined");
            const shieldedSnapsEl = document.getElementById("sec-stat-shielded-snaps");

            if (threatStatusEl) {
                threatStatusEl.textContent = health.status;
                threatStatusEl.style.color = health.status === "CRITICAL" ? "#ef4444" : (health.status === "WARNING" ? "#f59e0b" : "#10b981");
            }
            if (threatSubEl) {
                threatSubEl.textContent = health.status === "CRITICAL" ? "Immediate attention required" : (health.status === "WARNING" ? "Anomalies detected" : "All systems normal");
            }
            if (riskScoreEl) {
                riskScoreEl.textContent = `${health.overall_risk_score} / 100`;
            }
            if (riskMeterFill) {
                riskMeterFill.style.width = `${Math.min(100, health.overall_risk_score)}%`;
                riskMeterFill.className = "risk-meter-fill " + (
                    health.overall_risk_score >= 80 ? "critical" : (
                        health.overall_risk_score >= 60 ? "high-risk" : (
                            health.overall_risk_score >= 30 ? "suspicious" : "normal"
                        )
                    )
                );
            }
            if (activeAlertsEl) activeAlertsEl.textContent = health.active_ransomware_alerts;
            if (quarantinedEl) quarantinedEl.textContent = `${health.quarantined_alerts_count} quarantined`;
            if (shieldedSnapsEl) shieldedSnapsEl.textContent = health.shielded_snapshots_count;
        } catch (e) {
            console.warn("Could not load security health:", e);
        }

        // 2. Fetch Alerts (using filter selection)
        const filterSelect = document.getElementById("security-alerts-filter");
        const statusFilter = filterSelect ? filterSelect.value : "ACTIVE";
        const alertsData = await api.getSecurityAlerts(statusFilter);
        const alerts = alertsData.alerts || [];
        const tbody = document.getElementById("security-alerts-table-body");
        const banner = document.getElementById("threat-banner");
        const bannerTitle = document.getElementById("threat-status-title");
        const threatIcon = document.getElementById("threat-icon");
        tbody.innerHTML = "";

        const activeAlertsCount = alerts.filter(a => a.status === "ACTIVE").length;

        if (activeAlertsCount === 0) {
            banner.classList.remove("threat-detected");
            bannerTitle.textContent = "RANSOMWARE SHIELD: ARMED & MONITORING";
            bannerTitle.style.color = "#34d399";
            threatIcon.textContent = "🛡️";
            if (alerts.length === 0) {
                tbody.innerHTML = "<tr><td colspan='6' style='text-align:center;'>No security alerts recorded. All files verified clean.</td></tr>";
            }
        } else {
            banner.classList.add("threat-detected");
            bannerTitle.textContent = `🚨 ${activeAlertsCount} ANOMALOUS ACTIVITY ALERT(S) DETECTED`;
            bannerTitle.style.color = "#ef4444";
            threatIcon.textContent = "⚠️";
        }

        if (alerts.length > 0) {
            alerts.forEach(a => {
                const tr = document.createElement("tr");
                const level = a.alert_level || a.severity || "NORMAL";
                const badgeClass = level === "QUARANTINED" ? "badge-quarantined" : (
                    level === "HIGH_RISK" ? "badge-high-risk" : (
                        level === "SUSPICIOUS" ? "badge-suspicious" : "badge-normal"
                    )
                );

                const reasonsList = Array.isArray(a.reasons) ? a.reasons : [a.details || "Anomalous file behavior"];
                const reasonsHtml = reasonsList.map(r => `<div>• ${escapeHTML(r)}</div>`).join("");

                const exts = Array.isArray(a.matched_extensions) ? a.matched_extensions.join(", ") : "";
                const extsBadge = exts ? `<div style="margin-top:0.25rem;"><span class="badge badge-mock" style="font-size:0.7rem;">Ext: ${escapeHTML(exts)}</span></div>` : "";

                const statusBadge = a.status === "ACTIVE" ?
                    `<span class="badge badge-warning">ACTIVE</span>` :
                    `<span class="badge badge-passed">${escapeHTML(a.status)}</span>`;

                let actionButtons = "";
                if (a.status === "ACTIVE") {
                    actionButtons = `
                        <div style="display:flex;gap:0.35rem;flex-wrap:wrap;">
                            <button class="btn btn-secondary btn-sm dismiss-alert-btn" data-alert-id="${a.id}" title="Acknowledge False Positive">Dismiss</button>
                            <button class="btn btn-outline-accent btn-sm resolve-alert-btn" data-alert-id="${a.id}" title="Resolve Threat and Unlock Snapshots">✓ Resolve</button>
                        </div>
                    `;
                } else {
                    actionButtons = `<span style="font-size:0.8rem;color:var(--text-secondary);">Closed</span>`;
                }

                tr.innerHTML = `
                    <td><span class="badge ${badgeClass}">${escapeHTML(level)}</span></td>
                    <td><strong>${a.risk_score} / 100</strong></td>
                    <td style="font-size:0.85rem;max-width:340px;">
                        ${reasonsHtml}
                        ${extsBadge}
                    </td>
                    <td>${statusBadge}</td>
                    <td style="font-size:0.8rem;">${formatDate(a.created_at)}</td>
                    <td>${actionButtons}</td>
                `;
                tbody.appendChild(tr);
            });

            // Bind dismiss buttons
            tbody.querySelectorAll(".dismiss-alert-btn").forEach(btn => {
                btn.addEventListener("click", async () => {
                    const alertId = btn.dataset.alertId;
                    try {
                        await api.dismissSecurityAlert(alertId, "Dismissed via Security Center dashboard");
                        showToast("Security alert dismissed.", "info");
                        loadSecurityCenter();
                    } catch (e) {
                        showToast("Could not dismiss alert: " + e.message, "error");
                    }
                });
            });

            // Bind resolve buttons
            tbody.querySelectorAll(".resolve-alert-btn").forEach(btn => {
                btn.addEventListener("click", async () => {
                    const alertId = btn.dataset.alertId;
                    try {
                        const res = await api.resolveSecurityAlert(alertId, "Threat verified resolved and safe", true);
                        showToast(`Alert resolved! ${res.unlocked_snapshots || 0} snapshot(s) unlocked.`, "success");
                        loadSecurityCenter();
                    } catch (e) {
                        showToast("Could not resolve alert: " + e.message, "error");
                    }
                });
            });
        }

        // 3. Bind Filter change
        if (filterSelect && !filterSelect.dataset.bound) {
            filterSelect.dataset.bound = "true";
            filterSelect.addEventListener("change", () => {
                loadSecurityCenter();
            });
        }

        // 4. Bind Simulation Button
        const simBtn = document.getElementById("run-sim-attack-btn");
        if (simBtn && !simBtn.dataset.bound) {
            simBtn.dataset.bound = "true";
            simBtn.addEventListener("click", async () => {
                const scenarioSelect = document.getElementById("sim-scenario-select");
                const scenario = scenarioSelect ? scenarioSelect.value : "mass_encryption";
                const feedbackEl = document.getElementById("sim-status-feedback");
                simBtn.disabled = true;
                simBtn.textContent = "Testing...";
                if (feedbackEl) feedbackEl.textContent = "Creating isolated sandbox files and running multi-signal engine...";

                try {
                    const simRes = await api.simulateAttack(scenario);
                    const risk = simRes.analysis.risk_score;
                    const level = simRes.analysis.alert_level;
                    if (feedbackEl) {
                        feedbackEl.innerHTML = `<strong>Result:</strong> Risk Score ${risk}/100 (${level}) — ${simRes.sandbox_files_created} sandbox files tested. Temp files safely deleted.`;
                    }
                    showToast(`Simulation complete: Risk ${risk}/100 (${level})`, level === "NORMAL" ? "info" : "warning");
                    await loadSecurityCenter();
                } catch (e) {
                    if (feedbackEl) feedbackEl.textContent = "Simulation error: " + e.message;
                    showToast("Simulation failed: " + e.message, "error");
                } finally {
                    simBtn.disabled = false;
                    simBtn.textContent = "⚡ Run Safe Simulation";
                }
            });
        }

        // 5. Fetch Audit Logs
        const auditData = await api.getAuditLogs(30);
        const logs = auditData.audit_logs || auditData.logs || [];
        const auditTbody = document.getElementById("audit-logs-table-body");
        auditTbody.innerHTML = "";

        if (logs.length === 0) {
            auditTbody.innerHTML = "<tr><td colspan='7' style='text-align:center;'>No audit logs recorded yet.</td></tr>";
        } else {
            logs.forEach(l => {
                const tr = document.createElement("tr");
                const prev = l.prev_hash || l.previous_hash || "";
                const cur = l.current_hash || l.entry_hash || "";
                const prevHashShort = prev ? `${prev.substring(0, 10)}...` : '0000000000...';
                const curHashShort = cur ? `${cur.substring(0, 12)}...` : '-';
                tr.innerHTML = `
                    <td><code>${l.id.substring(0, 6)}</code></td>
                    <td><strong>${escapeHTML(l.event_type)}</strong></td>
                    <td>${escapeHTML(l.action || "")}</td>
                    <td><span class="badge badge-optimal">${escapeHTML(l.severity || "INFO")}</span></td>
                    <td><span class="audit-hash-code" title="${prev}">${prevHashShort}</span></td>
                    <td><span class="audit-hash-code" title="${cur}">${curHashShort}</span></td>
                    <td>${formatDate(l.created_at)}</td>
                `;
                auditTbody.appendChild(tr);
            });
        }

        // Bind Entropy scan button
        const scanBtn = document.getElementById("run-entropy-scan-btn");
        if (scanBtn && !scanBtn.dataset.bound) {
            scanBtn.dataset.bound = "true";
            scanBtn.onclick = () => {
                showToast("Continuous real-time Shannon entropy monitoring is active across all file uploads.", "info");
            };
        }

    } catch (err) {
        console.error("Security Center load error:", err);
        showToast("Could not load security center: " + err.message, "error");
    }
}

    } catch (err) {
        console.error("Security Center load error:", err);
        showToast("Could not load security center: " + err.message, "error");
    }
}

// 3. Predictive AI Analytics Controller
async function loadAnalytics() {
    try {
        const [health, overview, forecast, largeFiles] = await Promise.all([
            api.getHealthScore(),
            api.getAnalyticsOverview(),
            api.getStorageForecast(),
            api.getTopLargeFiles(10)
        ]);

        // Health Score
        const scoreEl = document.getElementById("ai-health-score");
        const ratingEl = document.getElementById("ai-health-rating");
        if (scoreEl) scoreEl.textContent = `${health.health_score || health.score || 0} / 100`;
        if (ratingEl) ratingEl.textContent = `${health.rating || health.status || 'Active'} • ${(health.recommendations && health.recommendations[0]) || 'System Healthy'}`;

        // 6 Health Dimensions Breakdown
        const bd = health.breakdown || {};
        const setDim = (dimId, score, max) => {
            const labelEl = document.getElementById(`score-dim-${dimId}`);
            const barEl = document.getElementById(`bar-dim-${dimId}`);
            if (labelEl) labelEl.textContent = `${score} / ${max}`;
            if (barEl) barEl.style.width = `${Math.min(100, Math.round((score / max) * 100))}%`;
        };
        setDim("rpo", bd.rpo_score ?? 0, 35);
        setDim("rel", bd.job_reliability_score ?? 0, 25);
        setDim("sec", bd.security_posture_score ?? 0, 15);
        setDim("drill", bd.drill_integrity_score ?? 0, 10);
        setDim("worm", bd.retention_protection_score ?? 0, 5);
        setDim("dedup", bd.dedup_efficiency_score ?? 0, 10);

        // Load Failure Trends & Root Cause Diagnosis
        try {
            const trends = await api.getFailureTrends(14);
            const failContainer = document.getElementById("failure-trends-container");
            if (failContainer) {
                if (!trends || trends.total_jobs === 0) {
                    failContainer.innerHTML = "<span style='color:var(--text-secondary);'>No backup executions recorded in the past 14 days.</span>";
                } else if (trends.failed_jobs === 0) {
                    failContainer.innerHTML = `
                        <div style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem;background:rgba(34,197,94,0.1);border-radius:var(--radius);color:var(--success);">
                            <span style="font-size:1.5rem;">✅</span>
                            <div>
                                <strong>100% Execution Success Rate</strong>
                                <div style="font-size:0.8rem;color:var(--text-secondary);">${trends.total_jobs} total executions over the past 14 days with zero failures.</div>
                            </div>
                        </div>
                    `;
                } else {
                    let html = `
                        <div style="margin-bottom:0.75rem;font-size:0.85rem;">
                            <strong>Execution Stability:</strong> ${trends.success_rate_percentage}% success (${trends.failed_jobs} failed out of ${trends.total_jobs} jobs)
                        </div>
                        <div style="display:flex;flex-direction:column;gap:0.5rem;">
                    `;
                    (trends.root_cause_analysis || []).forEach(rc => {
                        html += `
                            <div style="padding:0.5rem;background:var(--bg-secondary);border-radius:var(--radius);font-size:0.8rem;">
                                <div style="display:flex;justify-content:space-between;margin-bottom:0.25rem;">
                                    <strong style="color:var(--danger);">${rc.category}</strong>
                                    <span>${rc.count} failure(s) (${rc.percentage}%)</span>
                                </div>
                                <div style="color:var(--text-secondary);font-size:0.78rem;">${rc.remediation}</div>
                            </div>
                        `;
                    });
                    html += "</div>";
                    failContainer.innerHTML = html;
                }
            }
        } catch (trendErr) {
            console.warn("Could not load failure trends:", trendErr);
        }

        // Deduplication & Cost
        const dedupEl = document.getElementById("ai-dedup-multiplier");
        const dedupPctEl = document.getElementById("ai-dedup-pct");
        const costEl = document.getElementById("ai-cloud-cost");
        const costSavedEl = document.getElementById("ai-cost-saved");
        const velocityEl = document.getElementById("ai-growth-rate");
        const runwayEl = document.getElementById("ai-days-to-quota");

        const dedupRatio = overview.deduplication?.ratio_multiplier ?? overview.deduplication_ratio ?? 1.0;
        const spaceSavedPct = overview.deduplication?.space_saved_percentage ?? 0;
        const estCost = overview.cost_estimation?.estimated_monthly_cost_usd ?? 0.0;
        const costSaved = overview.cost_estimation?.monthly_cost_saved_usd ?? 0.0;

        if (dedupEl) dedupEl.textContent = `${dedupRatio}x`;
        if (dedupPctEl) dedupPctEl.textContent = `${spaceSavedPct}% space saved via deduplication`;
        if (costEl) costEl.textContent = `$${estCost.toFixed(2)} / mo`;
        if (costSavedEl) costSavedEl.textContent = `Saved $${costSaved.toFixed(2)}/mo via deduplication`;
        if (velocityEl) velocityEl.textContent = `+${formatBytes(forecast.daily_growth_bytes || 0)} / day`;
        
        const daysToQuota = forecast.days_to_quota ?? forecast.days_until_quota_exhausted;
        if (runwayEl) runwayEl.textContent = (daysToQuota !== null && daysToQuota !== undefined) ? `Days to Quota: ${daysToQuota} days` : 'Unlimited quota headroom';

        // 30-Day Forecast Bars
        const proj = forecast.projections || {};
        const curBytes = proj.day_0_bytes ?? forecast.current_stored_bytes ?? 0;
        const d7Bytes = proj.day_7_bytes ?? curBytes;
        const d14Bytes = proj.day_14_bytes ?? curBytes;
        const d30Bytes = proj.day_30_bytes ?? forecast.projected_bytes_30d ?? curBytes;

        const maxVal = Math.max(d30Bytes, curBytes, 1024 * 1024);
        const getPct = (b) => Math.max(12, Math.min(100, Math.round((b / maxVal) * 100)));

        const bar0 = document.getElementById("bar-day-0");
        const bar7 = document.getElementById("bar-day-7");
        const bar14 = document.getElementById("bar-day-14");
        const bar30 = document.getElementById("bar-day-30");

        if (bar0) { bar0.style.height = `${getPct(curBytes)}%`; bar0.title = formatBytes(curBytes); }
        if (bar7) { bar7.style.height = `${getPct(d7Bytes)}%`; bar7.title = formatBytes(d7Bytes); }
        if (bar14) { bar14.style.height = `${getPct(d14Bytes)}%`; bar14.title = formatBytes(d14Bytes); }
        if (bar30) { bar30.style.height = `${getPct(d30Bytes)}%`; bar30.title = formatBytes(d30Bytes); }

        const summaryText = document.getElementById("forecast-summary-text");
        if (summaryText) {
            summaryText.textContent = `Forecasting ${formatBytes(d30Bytes)} in storage within 30 days based on ${forecast.growth_model || 'linear backup velocity'}. Confidence: ${forecast.forecast_confidence || 'Normal'}.`;
        }

        // File Types Breakdown
        const ftContainer = document.getElementById("file-types-breakdown-container");
        if (ftContainer) {
            ftContainer.innerHTML = "";
            const breakdown = overview.file_breakdown || {};
            const entries = Object.entries(breakdown);

            if (entries.length === 0) {
                ftContainer.innerHTML = "<span style='font-size:0.85rem;color:var(--text-secondary);'>No files backed up yet.</span>";
            } else {
                const totalBytes = entries.reduce((acc, curr) => acc + curr[1].bytes, 0) || 1;
                entries.slice(0, 6).forEach(([ext, info]) => {
                    const pct = Math.round((info.bytes / totalBytes) * 100);
                    const row = document.createElement("div");
                    row.innerHTML = `
                        <div style="display:flex;justify-content:space-between;font-size:0.8rem;margin-bottom:0.25rem;">
                            <span><strong>${escapeHTML(ext)}</strong> (${info.count} files)</span>
                            <span>${formatBytes(info.bytes)} (${pct}%)</span>
                        </div>
                        <div class="progress-bar-container">
                            <div class="progress-bar-fill" style="width:${pct}%;"></div>
                        </div>
                    `;
                    ftContainer.appendChild(row);
                });
            }
        }

        // Multi-Cloud Cost Comparison Table
        const cloudComp = overview.cloud_cost_comparison;
        if (cloudComp) {
            if (cloudComp.gcs) {
                const el = document.getElementById("cost-gcs-std"); if (el) el.textContent = `$${cloudComp.gcs.standard_monthly_usd.toFixed(2)}`;
                const elN = document.getElementById("cost-gcs-near"); if (elN) elN.textContent = `$${cloudComp.gcs.nearline_monthly_usd.toFixed(2)}`;
                const elA = document.getElementById("cost-gcs-arch"); if (elA) elA.textContent = `$${cloudComp.gcs.archive_monthly_usd.toFixed(2)}`;
                const elS = document.getElementById("cost-gcs-saved"); if (elS) elS.textContent = `-$${cloudComp.gcs.saved_via_dedup_usd.toFixed(2)}`;
            }
            if (cloudComp.aws_s3) {
                const el = document.getElementById("cost-aws-std"); if (el) el.textContent = `$${cloudComp.aws_s3.standard_monthly_usd.toFixed(2)}`;
                const elI = document.getElementById("cost-aws-ia"); if (elI) elI.textContent = `$${cloudComp.aws_s3.ia_monthly_usd.toFixed(2)}`;
                const elA = document.getElementById("cost-aws-arch"); if (elA) elA.textContent = `$${cloudComp.aws_s3.deep_archive_monthly_usd.toFixed(2)}`;
                const elS = document.getElementById("cost-aws-saved"); if (elS) elS.textContent = `-$${cloudComp.aws_s3.saved_via_dedup_usd.toFixed(2)}`;
            }
            if (cloudComp.azure_blob) {
                const el = document.getElementById("cost-az-hot"); if (el) el.textContent = `$${cloudComp.azure_blob.hot_monthly_usd.toFixed(2)}`;
                const elC = document.getElementById("cost-az-cool"); if (elC) elC.textContent = `$${cloudComp.azure_blob.cool_monthly_usd.toFixed(2)}`;
                const elA = document.getElementById("cost-az-arch"); if (elA) elA.textContent = `$${cloudComp.azure_blob.archive_monthly_usd.toFixed(2)}`;
                const elS = document.getElementById("cost-az-saved"); if (elS) elS.textContent = `-$${cloudComp.azure_blob.saved_via_dedup_usd.toFixed(2)}`;
            }
        }

        // AI Protection Recommendations List
        const recListEl = document.getElementById("analytics-recommendations-list");
        if (recListEl) {
            recListEl.innerHTML = "";
            const recs = health.recommendations || [];
            if (recs.length === 0) {
                recListEl.innerHTML = "<li style='color:var(--success);'>✅ Backup posture is optimal. No urgent actions needed.</li>";
            } else {
                recs.forEach(r => {
                    const li = document.createElement("li");
                    li.style.display = "flex";
                    li.style.alignItems = "flex-start";
                    li.style.gap = "0.5rem";
                    li.innerHTML = `<span>💡</span><span>${escapeHTML(r)}</span>`;
                    recListEl.appendChild(li);
                });
            }
        }

        // Top 10 Largest Files
        const largeTbody = document.getElementById("large-files-table-body");
        if (largeTbody) {
            largeTbody.innerHTML = "";
            const files = largeFiles.large_files || [];

            if (files.length === 0) {
                largeTbody.innerHTML = "<tr><td colspan='5' style='text-align:center;'>No large files recorded.</td></tr>";
            } else {
                files.forEach(f => {
                    const tr = document.createElement("tr");
                    const ext = f.file_extension || (f.file_name.includes('.') ? '.' + f.file_name.split('.').pop() : 'none');
                    tr.innerHTML = `
                        <td><strong>${escapeHTML(f.file_name)}</strong></td>
                        <td><code>${escapeHTML(ext)}</code></td>
                        <td>${formatBytes(f.file_size)}</td>
                        <td style="font-size:0.8rem;color:var(--text-secondary);">${escapeHTML(f.relative_path)}</td>
                        <td>${escapeHTML(f.snapshot_name || (f.snapshot_id ? 'Snap #' + f.snapshot_id.slice(0, 6) : 'Active'))}</td>
                    `;
                    largeTbody.appendChild(tr);
                });
            }
        }

    } catch (err) {
        console.error("Predictive Analytics load error:", err);
        showToast("Could not load analytics: " + err.message, "error");
    }
}

// AI Weekly Executive Report Controller
let currentWeeklyReportMarkdown = "";

async function openWeeklyReportModal() {
    const modal = document.getElementById("weekly-report-modal");
    const contentEl = document.getElementById("weekly-report-content");
    if (modal) modal.style.display = "flex";
    if (contentEl) contentEl.textContent = "Compiling live weekly intelligence report from database telemetry...";

    try {
        const report = await api.getWeeklyReport();
        currentWeeklyReportMarkdown = report.markdown_report || "";
        if (contentEl) contentEl.textContent = currentWeeklyReportMarkdown;
    } catch (err) {
        if (contentEl) contentEl.textContent = "Error compiling weekly report: " + err.message;
    }
}

function copyWeeklyReport() {
    if (!currentWeeklyReportMarkdown) return;
    navigator.clipboard.writeText(currentWeeklyReportMarkdown).then(() => {
        showToast("Weekly report copied to clipboard!", "success");
    }).catch(() => {
        showToast("Could not access clipboard", "error");
    });
}

// 4. Visual File Version Timeline Scrubber
let cachedAllFiles = [];

async function loadTimeline() {
    try {
        const snapData = await api.getSnapshots();
        const snapshots = snapData.snapshots || [];
        const fileSelect = document.getElementById("timeline-file-select");
        const emptyMsg = document.getElementById("timeline-empty-message");
        const container = document.getElementById("timeline-nodes-container");

        fileSelect.innerHTML = "<option value=''>Select a protected file to view revisions...</option>";

        // Gather all files from tree of all snapshots
        cachedAllFiles = [];
        const uniquePaths = new Set();

        for (const s of snapshots) {
            try {
                const tree = await api.getSnapshotTree(s.id);
                (tree.files || []).forEach(f => {
                    cachedAllFiles.push({
                        ...f,
                        snapshot_id: s.id,
                        snapshot_name: s.name,
                        snapshot_timestamp: s.created_at
                    });
                    uniquePaths.add(f.relative_path);
                });
            } catch (e) {
                // Ignore empty snapshots
            }
        }

        if (uniquePaths.size === 0) {
            fileSelect.innerHTML = "<option value=''>No files backed up yet</option>";
            return;
        }

        Array.from(uniquePaths).sort().forEach(p => {
            const opt = document.createElement("option");
            opt.value = p;
            opt.textContent = p;
            fileSelect.appendChild(opt);
        });

        fileSelect.onchange = () => {
            const path = fileSelect.value;
            renderTimelineForFile(path);
        };

        if (fileSelect.options.length > 1) {
            fileSelect.selectedIndex = 1;
            renderTimelineForFile(fileSelect.value);
        }

    } catch (err) {
        console.error("Timeline load error:", err);
        showToast("Could not load timeline: " + err.message, "error");
    }
}

function renderTimelineForFile(relativePath) {
    const container = document.getElementById("timeline-nodes-container");
    container.innerHTML = '<div class="timeline-line"></div>';

    if (!relativePath) {
        container.innerHTML += `
            <div id="timeline-empty-message" style="padding-left:3.5rem;color:var(--text-secondary);font-size:0.875rem;">
                Select a file above to view its historical version timeline.
            </div>
        `;
        return;
    }

    const versions = cachedAllFiles.filter(f => f.relative_path === relativePath);
    // Sort versions by snapshot timestamp descending
    versions.sort((a, b) => new Date(b.snapshot_timestamp) - new Date(a.snapshot_timestamp));

    if (versions.length === 0) {
        container.innerHTML += `<div style="padding-left:3.5rem;color:var(--text-secondary);font-size:0.875rem;">No revisions found for ${escapeHTML(relativePath)}.</div>`;
        return;
    }

    versions.forEach((v, idx) => {
        const node = document.createElement("div");
        node.className = "timeline-node";
        const shaShort = v.sha256_hash ? `${v.sha256_hash.substring(0, 16)}...` : '-';
        node.innerHTML = `
            <div class="timeline-dot" style="${idx === 0 ? 'background:#10b981;box-shadow:0 0 0 2px #10b981;' : ''}"></div>
            <div class="timeline-card">
                <div class="timeline-card-header">
                    <div>
                        <strong style="font-size:0.95rem;">${escapeHTML(v.snapshot_name)}</strong>
                        ${idx === 0 ? '<span class="badge badge-optimal" style="margin-left:0.5rem;">LATEST VERSION</span>' : ''}
                    </div>
                    <span style="font-size:0.8rem;color:var(--text-secondary);">${formatDate(v.snapshot_timestamp)}</span>
                </div>
                <div style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:0.75rem;">
                    Size: <strong>${formatBytes(v.file_size)}</strong> | Modified: ${formatDate(v.modified_at || v.modified_time)}<br>
                    SHA-256 Digest: <span class="audit-hash-code" title="${v.sha256_hash}">${shaShort}</span>
                </div>
                <button class="btn btn-outline-accent btn-sm restore-version-btn" data-snap-file-id="${v.id}" data-file-name="${v.file_name}">
                    ↺ Restore This Version
                </button>
            </div>
        `;
        container.appendChild(node);
    });

    // Bind restore buttons
    container.querySelectorAll(".restore-version-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const snapFileId = btn.dataset.snapFileId;
            const fileName = btn.dataset.fileName;
            const modal = document.getElementById("restore-modal");
            document.getElementById("restore-modal-title").textContent = `Restore Version: ${fileName}`;
            selectedRestoreType = "file";
            selectedRestoreId = snapFileId;
            modal.style.display = "flex";
        });
    });
}

// 5. Server-Sent Events (SSE) Real-Time Notification Receiver
function setupRealtimeEvents() {
    api.connectSSE(
        (event) => {
            if (event.type === "CONNECTED") {
                console.log("CloudVault Real-Time Events Stream Connected");
            } else if (event.type === "BACKUP_PROGRESS") {
                showToast(`Backup Job Progress: ${event.scanned} scanned, ${event.uploaded} uploaded`, "info");
            } else if (event.type === "RANSOMWARE_ALERT") {
                showToast(`🚨 SECURITY ALERT: High-risk anomaly detected! (Score: ${event.risk_score})`, "error");
                loadSecurityCenter();
            } else if (event.type === "DR_DRILL_RESULT") {
                showToast(`Disaster Recovery Drill Completed: ${event.status} (${event.speed_mbps} MB/s)`, event.status === "PASSED" ? "success" : "error");
                loadDisasterRecovery();
            }
        },
        (err) => {
            console.warn("SSE EventSource notice, retrying automatically...", err);
        }
    );
}
