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

    await loadMultiCloudStorage();
}

async function loadMultiCloudStorage() {
    try {
        const [inv, costs, telem] = await Promise.all([
            api.getStorageInventory().catch(() => null),
            api.getStorageCosts().catch(() => null),
            api.getStorageTelemetry().catch(() => null)
        ]);

        if (inv) {
            const badge = document.getElementById("mc-active-badge");
            if (badge) {
                badge.textContent = `PRIMARY: ${inv.active_provider.toUpperCase()}`;
            }
            const primDisplay = document.getElementById("mc-primary-display");
            if (primDisplay && inv.routing) {
                primDisplay.textContent = inv.routing.primary || "Mock";
            }
            const secDisplay = document.getElementById("mc-secondary-display");
            if (secDisplay && inv.routing) {
                secDisplay.textContent = inv.routing.secondary || "None";
            }
            const failoverStat = document.getElementById("mc-failover-status");
            if (failoverStat && inv.routing) {
                failoverStat.textContent = `Failover: ${inv.routing.failover_enabled ? "ENABLED" : "DISABLED"}`;
            }

            if (inv.supported_clouds) {
                if (inv.supported_clouds.gcs && inv.supported_clouds.gcs.health) {
                    const l = document.getElementById("gcs-latency");
                    if (l) l.textContent = `${inv.supported_clouds.gcs.health.latency_ms} ms`;
                    const b = document.getElementById("gcs-status-badge");
                    if (b) b.textContent = inv.supported_clouds.gcs.status;
                }
                if (inv.supported_clouds.aws_s3 && inv.supported_clouds.aws_s3.health) {
                    const l = document.getElementById("s3-latency");
                    if (l) l.textContent = `${inv.supported_clouds.aws_s3.health.latency_ms} ms`;
                    const b = document.getElementById("s3-status-badge");
                    if (b) b.textContent = inv.supported_clouds.aws_s3.status;
                }
                if (inv.supported_clouds.azure_blob && inv.supported_clouds.azure_blob.health) {
                    const l = document.getElementById("azure-latency");
                    if (l) l.textContent = `${inv.supported_clouds.azure_blob.health.latency_ms} ms`;
                    const b = document.getElementById("azure-status-badge");
                    if (b) b.textContent = inv.supported_clouds.azure_blob.status;
                }
                if (inv.supported_clouds.local_mock && inv.supported_clouds.local_mock.health) {
                    const l = document.getElementById("mock-latency");
                    if (l) l.textContent = `${inv.supported_clouds.local_mock.health.latency_ms} ms`;
                }
            }
        }

        if (telem && telem.telemetry) {
            const countEl = document.getElementById("mc-transfers-count");
            if (countEl) {
                countEl.textContent = `${telem.telemetry.uploads_count || 0} / ${telem.telemetry.downloads_count || 0}`;
            }
            const foCountEl = document.getElementById("mc-failover-events");
            if (foCountEl) {
                foCountEl.textContent = telem.telemetry.failover_events_count || 0;
            }

            const logBody = document.getElementById("mc-failover-log-body");
            if (logBody && telem.telemetry.failover_log && telem.telemetry.failover_log.length > 0) {
                logBody.innerHTML = telem.telemetry.failover_log.map(ev => `
                    <tr>
                        <td><code>${ev.timestamp ? ev.timestamp.substring(11, 19) : ""}</code></td>
                        <td><code>${escapeHtml(ev.destination_path)}</code></td>
                        <td>${escapeHtml(ev.primary_provider)}</td>
                        <td><strong style="color:#f59e0b;">${escapeHtml(ev.secondary_provider)}</strong></td>
                        <td style="font-size:0.8rem;color:#f87171;">${escapeHtml(ev.error_reason)}</td>
                        <td><span class="badge" style="background:#059669;color:#fff;">${escapeHtml(ev.status)}</span></td>
                    </tr>
                `).join("");
            }
        }

        if (costs && costs.usage_by_provider) {
            const u = costs.usage_by_provider;
            if (u.mock) {
                document.getElementById("cost-mock-count").textContent = u.mock.object_count;
                document.getElementById("cost-mock-size").textContent = `${u.mock.stored_mb} MB`;
            }
            if (u.gcs) {
                document.getElementById("cost-gcs-count").textContent = u.gcs.object_count;
                document.getElementById("cost-gcs-size").textContent = `${u.gcs.stored_mb} MB`;
            }
            if (u.s3) {
                document.getElementById("cost-s3-count").textContent = u.s3.object_count;
                document.getElementById("cost-s3-size").textContent = `${u.s3.stored_mb} MB`;
            }
            if (u.azure) {
                document.getElementById("cost-azure-count").textContent = u.azure.object_count;
                document.getElementById("cost-azure-size").textContent = `${u.azure.stored_mb} MB`;
            }
            if (costs.estimated_monthly_costs_usd) {
                document.getElementById("cost-gcs-est").textContent = `$${costs.estimated_monthly_costs_usd.gcs_standard}/mo`;
                document.getElementById("cost-s3-est").textContent = `$${costs.estimated_monthly_costs_usd.aws_s3_standard}/mo`;
                document.getElementById("cost-azure-est").textContent = `$${costs.estimated_monthly_costs_usd.azure_blob_hot}/mo`;
            }
        }
    } catch (err) {
        console.error("Error loading multi-cloud storage telemetry:", err);
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
    setupMultiCloudControls();
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

// ========================================================
// 1. Disaster Recovery Command Center Controller
// ========================================================
let currentDRTelemetry = null;
let currentDRHistoryTab = "drills"; // "drills" or "ops"

async function loadDisasterRecovery() {
    try {
        const telemetry = await api.getDRCommandCenter();
        currentDRTelemetry = telemetry;

        // 1. Mission Control Header & Readiness
        const readinessBadge = document.getElementById("dr-readiness-banner-badge");
        if (readinessBadge) {
            readinessBadge.textContent = `${telemetry.readiness_level} (${telemetry.readiness_score}/100)`;
            readinessBadge.className = `dr-metric-badge badge-${telemetry.readiness_level === 'OPTIMAL' ? 'optimal' : (telemetry.readiness_level === 'ACCEPTABLE' ? 'warning' : 'critical')}`;
        }

        // Readiness factors
        const sb = telemetry.score_breakdown || {};
        const fRpo = document.getElementById("factor-rpo");
        const fDrills = document.getElementById("factor-drills");
        const fShield = document.getElementById("factor-shield");
        const fWorm = document.getElementById("factor-worm");
        const fInteg = document.getElementById("factor-integrity");
        if (fRpo) fRpo.textContent = `RPO: ${sb.rpo_recency !== undefined ? sb.rpo_recency + '/30' : '--'}`;
        if (fDrills) fDrills.textContent = `Drills: ${sb.verification_drills !== undefined ? sb.verification_drills + '/25' : '--'}`;
        if (fShield) fShield.textContent = `Shield: ${sb.cyber_shield !== undefined ? sb.cyber_shield + '/25' : '--'}`;
        if (fWorm) fWorm.textContent = `WORM: ${sb.worm_retention !== undefined ? sb.worm_retention + '/10' : '--'}`;
        if (fInteg) fInteg.textContent = `Integrity: ${sb.storage_integrity !== undefined ? sb.storage_integrity + '/10' : '--'}`;

        // 2. KPI 1: Calculated RPO
        const rpoVal = document.getElementById("dr-rpo-value");
        const rpoBadge = document.getElementById("dr-rpo-badge");
        if (rpoVal && telemetry.rpo) {
            if (telemetry.rpo.hours !== null) {
                rpoVal.textContent = `${telemetry.rpo.hours}h`;
                rpoBadge.textContent = telemetry.rpo.status;
                rpoBadge.className = `dr-metric-badge badge-${telemetry.rpo.status === 'HEALTHY' ? 'optimal' : (telemetry.rpo.status === 'WARNING' ? 'warning' : 'critical')}`;
            } else {
                rpoVal.textContent = "No Backups";
                rpoBadge.textContent = "PENDING";
                rpoBadge.className = "dr-metric-badge badge-warning";
            }
        }

        // 3. KPI 2: Measured RTO
        const rtoVal = document.getElementById("dr-rto-value");
        const rtoSpeed = document.getElementById("dr-rto-speed");
        if (rtoVal && telemetry.rto) {
            rtoVal.textContent = `${telemetry.rto.predicted_full_rto_minutes} min`;
            rtoSpeed.textContent = `Speed: ${telemetry.rto.measured_speed_mbps} MB/s`;
        }

        // 4. KPI 3: Available Recovery Points
        const ptsTotal = document.getElementById("dr-points-total");
        const ptsVer = document.getElementById("dr-points-verified");
        const ptsWorm = document.getElementById("dr-points-worm");
        if (ptsTotal && telemetry.recovery_points) {
            ptsTotal.textContent = telemetry.recovery_points.total;
            ptsVer.textContent = `${telemetry.recovery_points.verified} Verified`;
            ptsWorm.textContent = `${telemetry.recovery_points.worm_locked} WORM`;
        }

        // 5. KPI 4: Active Recovery Incidents
        const incCount = document.getElementById("dr-incidents-count");
        const incBadge = document.getElementById("dr-incidents-badge");
        const failedOps = document.getElementById("dr-failed-ops");
        if (incCount && telemetry.active_incidents) {
            const count = telemetry.active_incidents.count || 0;
            incCount.textContent = count;
            if (count === 0) {
                incBadge.textContent = "ALL CLEAR";
                incBadge.className = "dr-metric-badge badge-optimal";
            } else {
                incBadge.textContent = "THREAT DETECTED";
                incBadge.className = "dr-metric-badge badge-critical";
            }
            if (failedOps) failedOps.textContent = `${telemetry.failed_operations_count} Failed Ops`;
        }

        // 6. KPI 5: Last Verified Point
        const lastVerTitle = document.getElementById("dr-last-verified-title");
        const lastVerDate = document.getElementById("dr-last-verified-date");
        const lastVerStatus = document.getElementById("dr-last-verified-status");
        if (lastVerTitle && telemetry.recovery_points && telemetry.recovery_points.latest_snapshot) {
            const ls = telemetry.recovery_points.latest_snapshot;
            lastVerTitle.textContent = `#${ls.snapshot_number} ${ls.name}`;
            lastVerDate.textContent = formatDate(ls.created_at);
            lastVerStatus.textContent = ls.verification_status;
            lastVerStatus.className = `dr-metric-badge badge-${ls.verification_status === 'VERIFIED' ? 'optimal' : 'warning'}`;
        } else if (lastVerTitle) {
            lastVerTitle.textContent = "None";
            lastVerDate.textContent = "-";
        }

        // 7. KPI 6: Data Protection Scope
        const protBytes = document.getElementById("dr-protected-bytes");
        const unprotFiles = document.getElementById("dr-unprotected-files");
        const protBadge = document.getElementById("dr-protection-badge");
        if (protBytes && telemetry.data_protection) {
            protBytes.textContent = formatBytes(telemetry.data_protection.total_stored_bytes);
            unprotFiles.textContent = `${telemetry.data_protection.unprotected_files_count} unsynced`;
            protBadge.textContent = telemetry.data_protection.status;
            protBadge.className = `dr-metric-badge badge-${telemetry.data_protection.status === 'PROTECTED' ? 'optimal' : 'warning'}`;
        }

        // 8. Guided Ransomware Incident Recovery Container
        renderRansomwareContainer();

        // 9. Populate Snapshots in Advanced Drill Dropdown
        const snapSelect = document.getElementById("dr-snapshot-select");
        if (snapSelect) {
            const snapshotsData = await api.getSnapshots();
            const snapshots = Array.isArray(snapshotsData) ? snapshotsData : (snapshotsData.snapshots || []);
            snapSelect.innerHTML = "";
            if (snapshots.length === 0) {
                snapSelect.innerHTML = "<option value=''>No snapshots available</option>";
            } else {
                snapshots.forEach((s, idx) => {
                    const opt = document.createElement("option");
                    opt.value = s.id;
                    const vIcon = s.verification_status === "VERIFIED" ? "✅" : (s.verification_status === "FAILED" ? "❌" : "⏳");
                    const lockIcon = s.is_locked ? "🔒" : "";
                    opt.textContent = `${vIcon} #${s.snapshot_number} ${s.name} (${formatDate(s.created_at)}) ${lockIcon}`;
                    if (idx === 0) opt.selected = true;
                    snapSelect.appendChild(opt);
                });
            }
        }

        // 10. Load Recovery History
        await loadDRHistoryTable();

    } catch (err) {
        console.error("Disaster Recovery Command Center load error:", err);
        showToast("Could not load DR Command Center: " + err.message, "error");
    }
}

async function renderRansomwareContainer() {
    const container = document.getElementById("dr-ransomware-alert-container");
    if (!container) return;

    try {
        const plan = await api.getRansomwareRecoveryPlan();
        if (plan.has_active_threat) {
            const rec = plan.recommended_snapshot;
            let recHtml = "";
            if (rec) {
                recHtml = `
                    <div style="background:rgba(16,185,129,0.15);border:1px solid #10b981;border-radius:8px;padding:0.75rem;margin-top:0.75rem;">
                        <strong style="color:#34d399;">🛡️ Recommended Safe Recovery Point: Snapshot #${rec.snapshot_number} (${escapeHTML(rec.name)})</strong>
                        <p style="font-size:0.8rem;color:var(--text-secondary);margin:0.25rem 0;">Created at ${formatDate(rec.created_at)} | ${rec.total_files} files | WORM Protection: ${rec.is_locked ? '🔒 LOCKED' : 'Active'}</p>
                        <ul style="font-size:0.78rem;margin:0.5rem 0 0.5rem 1.25rem;color:#e2e8f0;">
                            ${(plan.safety_justification || []).map(j => `<li>${escapeHTML(j)}</li>`).join('')}
                        </ul>
                        <button class="btn btn-warning btn-sm" onclick="openRansomwareRecoveryModal('${rec.id}')" style="margin-top:0.5rem;">
                            🚀 Launch Guided Clean Recovery Wizard
                        </button>
                    </div>
                `;
            } else {
                recHtml = `<p style="color:#f87171;font-size:0.85rem;margin-top:0.5rem;">⚠️ No clean pre-incident snapshot recorded before the alarm. Please review quarantined snapshots in the Security Center.</p>`;
            }

            container.innerHTML = `
                <div class="card" style="border:1px solid #ef4444;background:rgba(239,68,68,0.08);">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <h3 style="color:#f87171;margin:0;font-size:1.1rem;">🚨 Active Ransomware Incident Detected</h3>
                        <span class="badge badge-critical">${plan.alert ? plan.alert.alert_level : 'ALERT'}</span>
                    </div>
                    <p style="color:var(--text-secondary);font-size:0.85rem;margin:0.5rem 0 0 0;">
                        CloudVault has isolated recent backup versions. Use the guided recovery engine below to restore verified clean files from before the incident without overwriting existing forensic data.
                    </p>
                    ${recHtml}
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="card" style="border:1px solid rgba(16,185,129,0.3);background:rgba(16,185,129,0.05);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.75rem;">
                    <div>
                        <strong style="color:#34d399;font-size:0.95rem;">✅ Threat Posture Clean (0 Active Ransomware Alerts)</strong>
                        <p style="color:var(--text-secondary);font-size:0.8rem;margin:0.25rem 0 0 0;">Continuous Shannon entropy monitoring and heuristic anomaly protection are active.</p>
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="openRansomwareRecoveryModal()">
                        🛡️ Recovery Readiness Check
                    </button>
                </div>
            `;
        }
    } catch (e) {
        container.innerHTML = "";
    }
}

async function loadDRHistoryTable() {
    const tbody = document.getElementById("dr-history-table-body");
    const headerRow = document.getElementById("dr-history-table-header");
    if (!tbody) return;

    if (currentDRHistoryTab === "drills") {
        if (headerRow) {
            headerRow.innerHTML = `
                <th>Drill ID</th>
                <th>Scope / Type</th>
                <th>Status</th>
                <th>Files Verified</th>
                <th>Restoration Speed</th>
                <th>Measured RTO</th>
                <th>Timestamp</th>
                <th>Action</th>
            `;
        }
        const historyData = await api.getDRHistory(20);
        const drills = historyData.drills || [];
        tbody.innerHTML = "";

        if (drills.length === 0) {
            tbody.innerHTML = "<tr><td colspan='8' style='text-align:center;'>No synthetic recovery drills executed yet. Click 'Run Recovery Drill' to test your backup.</td></tr>";
            return;
        }

        drills.forEach(d => {
            const tr = document.createElement("tr");
            const statusClass = d.status === "PASSED" ? "badge-passed" : "badge-failed";
            const scopeLabel = d.drill_type ? `${d.drill_type}${d.drill_scope ? ': ' + d.drill_scope : ''}` : "FULL_SNAPSHOT";
            tr.innerHTML = `
                <td><code>${d.drill_id.substring(0, 8)}...</code></td>
                <td style="font-size:0.8rem;"><span class="badge" style="background:#334155;">${escapeHTML(scopeLabel)}</span></td>
                <td><span class="badge ${statusClass}">${d.status}</span></td>
                <td>${d.files_tested} (${formatBytes(d.bytes_tested)})</td>
                <td><strong>${d.restoration_speed_mbps} MB/s</strong></td>
                <td>${d.duration_seconds}s</td>
                <td>${formatDate(d.created_at)}</td>
                <td><button class="btn btn-secondary btn-sm" onclick="openDrillReportModal('${d.drill_id}')" style="padding:0.2rem 0.5rem;font-size:0.75rem;">🔬 Report</button></td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        if (headerRow) {
            headerRow.innerHTML = `
                <th>Operation ID</th>
                <th>Type</th>
                <th>Status</th>
                <th>Files Restored</th>
                <th>Throughput</th>
                <th>Duration (RTO)</th>
                <th>RPO Age</th>
                <th>Timestamp</th>
            `;
        }
        const opsData = await api.getRecoveryOperations(20);
        const ops = opsData.operations || [];
        tbody.innerHTML = "";

        if (ops.length === 0) {
            tbody.innerHTML = "<tr><td colspan='8' style='text-align:center;'>No actual recovery operations recorded yet. Use 'Point-in-Time Restore' or 'Ransomware Recovery' to execute a restore.</td></tr>";
            return;
        }

        ops.forEach(o => {
            const tr = document.createElement("tr");
            const statusClass = o.status === "SUCCESS" ? "badge-passed" : "badge-failed";
            tr.innerHTML = `
                <td><code>${o.operation_id.substring(0, 8)}...</code></td>
                <td><span class="badge" style="background:#334155;">${o.operation_type}</span></td>
                <td><span class="badge ${statusClass}">${o.status}</span></td>
                <td>${o.files_restored} (${formatBytes(o.bytes_restored)})</td>
                <td><strong>${o.throughput_mbps} MB/s</strong></td>
                <td>${o.duration_seconds}s</td>
                <td>${o.rpo_hours}h</td>
                <td>${formatDate(o.created_at)}</td>
            `;
            tbody.appendChild(tr);
        });
    }
}

function setupDRControls() {
    const drillBtn = document.getElementById("trigger-dr-drill-btn");
    const scopeTypeSelect = document.getElementById("dr-drill-scope-type");
    const scopeInputWrapper = document.getElementById("dr-drill-scope-input-wrapper");
    const scopeInput = document.getElementById("dr-drill-scope-input");
    const snapSelect = document.getElementById("dr-snapshot-select");
    const statusBox = document.getElementById("dr-drill-status");

    // Scope change toggle
    if (scopeTypeSelect) {
        scopeTypeSelect.addEventListener("change", () => {
            const val = scopeTypeSelect.value;
            if (val === "FOLDER" || val === "FILE") {
                scopeInputWrapper.style.display = "block";
                scopeInput.placeholder = val === "FOLDER" ? "e.g. documents/ or src/" : "e.g. resume.pdf or thesis.docx";
            } else {
                scopeInputWrapper.style.display = "none";
            }
        });
    }

    // Drill execution handler
    if (drillBtn) {
        drillBtn.addEventListener("click", async () => {
            const snapId = snapSelect ? snapSelect.value : null;
            const scopeType = scopeTypeSelect ? scopeTypeSelect.value : "FULL_SNAPSHOT";
            const scopeVal = scopeInput ? scopeInput.value.trim() : null;

            drillBtn.disabled = true;
            drillBtn.textContent = "⏳ Executing Drill...";
            statusBox.style.display = "block";
            statusBox.innerHTML = "<em>Streaming cloud objects, verifying AES-256-GCM envelope tags, recalculating bit-level SHA-256 digests...</em>";
            statusBox.style.background = "rgba(56,189,248,0.1)";
            statusBox.style.border = "1px solid #38bdf8";

            try {
                const res = await api.runAdvancedDRDrill({
                    snapshot_id: snapId,
                    drill_type: scopeType,
                    drill_scope: scopeVal,
                    inject_corruption: (scopeType === "CORRUPTED_OBJECT_TEST")
                });

                if (res.status === "PASSED") {
                    statusBox.style.background = "rgba(16,185,129,0.12)";
                    statusBox.style.border = "1px solid #10b981";
                    statusBox.innerHTML = `
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <strong style="color:#10b981;">✅ ADVANCED DRILL PASSED (100% BIT-LEVEL INTEGRITY)</strong>
                            <button class="btn btn-secondary btn-sm" onclick="openDrillReportModal('${res.drill_id}')" style="padding:0.2rem 0.6rem;font-size:0.75rem;">🔬 View Full Report</button>
                        </div>
                        <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.4rem;">
                            Scope: <code>${res.drill_type}</code> | Files Tested: <strong>${res.files_tested}</strong> | Data Verified: ${formatBytes(res.bytes_tested)} | 
                            Duration: ${res.duration_seconds}s | <strong>Speed: ${res.restoration_speed_mbps} MB/s</strong><br>
                            Decryption authentication verified. Primary storage was untouched.
                        </div>
                    `;
                    showToast("Synthetic recovery drill passed with 100% data integrity!", "success");
                } else {
                    statusBox.style.background = "rgba(239,68,68,0.12)";
                    statusBox.style.border = "1px solid #ef4444";
                    statusBox.innerHTML = `
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <strong style="color:#f87171;">❌ DRILL INTEGRITY CHECK FAILED</strong>
                            <button class="btn btn-secondary btn-sm" onclick="openDrillReportModal('${res.drill_id}')" style="padding:0.2rem 0.6rem;font-size:0.75rem;">🔬 View Error Details</button>
                        </div>
                        <p style="font-size:0.82rem;color:#fca5a5;margin:0.35rem 0 0 0;">
                            ${escapeHTML(res.error_details || 'Hash mismatch detected on reconstructed payload')}
                        </p>
                    `;
                    showToast("Drill failed: Integrity mismatch detected.", "error");
                }
                loadDisasterRecovery();
            } catch (err) {
                statusBox.style.background = "rgba(239,68,68,0.12)";
                statusBox.style.border = "1px solid #ef4444";
                statusBox.innerHTML = `<span style="color:#f87171;">Drill execution error: ${escapeHTML(err.message)}</span>`;
                showToast("Drill failed: " + err.message, "error");
            } finally {
                drillBtn.disabled = false;
                drillBtn.textContent = "🚀 Run Recovery Drill";
            }
        });
    }

    // Modal buttons
    const btnAdvDrill = document.getElementById("dr-btn-open-advanced-drill");
    if (btnAdvDrill) {
        btnAdvDrill.addEventListener("click", () => {
            const panel = document.getElementById("dr-drill-scope-type");
            if (panel) panel.scrollIntoView({ behavior: "smooth" });
        });
    }

    const btnPit = document.getElementById("dr-btn-open-pit-wizard");
    if (btnPit) btnPit.addEventListener("click", () => openPointInTimeModal());

    const btnRansom = document.getElementById("dr-btn-open-ransomware-wizard");
    if (btnRansom) btnRansom.addEventListener("click", () => openRansomwareRecoveryModal());

    const btnSandbox = document.getElementById("dr-btn-open-sandbox");
    if (btnSandbox) btnSandbox.addEventListener("click", () => openRecoverySandboxModal());

    const btnExport = document.getElementById("dr-btn-export-report");
    if (btnExport) btnExport.addEventListener("click", () => exportDRReport());

    // History tab toggle
    const btnHistDrills = document.getElementById("dr-tab-history-drills");
    const btnHistOps = document.getElementById("dr-tab-history-ops");
    if (btnHistDrills && btnHistOps) {
        btnHistDrills.addEventListener("click", () => {
            currentDRHistoryTab = "drills";
            btnHistDrills.className = "btn btn-sm btn-primary";
            btnHistOps.className = "btn btn-sm btn-secondary";
            loadDRHistoryTable();
        });
        btnHistOps.addEventListener("click", () => {
            currentDRHistoryTab = "ops";
            btnHistDrills.className = "btn btn-sm btn-secondary";
            btnHistOps.className = "btn btn-sm btn-primary";
            loadDRHistoryTable();
        });
    }
}

function setupMultiCloudControls() {
    // 1. Ping All Providers
    const pingBtn = document.getElementById("btn-mc-ping-all");
    if (pingBtn) {
        pingBtn.addEventListener("click", async () => {
            pingBtn.disabled = true;
            pingBtn.textContent = "⏳ Pinging...";
            try {
                const res = await api.checkAllProvidersHealth();
                if (res && res.results) {
                    if (res.results.mock) document.getElementById("mock-latency").textContent = `${res.results.mock.latency_ms} ms`;
                    if (res.results.gcs) document.getElementById("gcs-latency").textContent = `${res.results.gcs.latency_ms} ms`;
                    if (res.results.s3) document.getElementById("s3-latency").textContent = `${res.results.s3.latency_ms} ms`;
                    if (res.results.azure) document.getElementById("azure-latency").textContent = `${res.results.azure.latency_ms} ms`;
                }
                showToast("All multi-cloud storage providers probed successfully!", "success");
            } catch (e) {
                showToast("Ping error: " + e.message, "error");
            } finally {
                pingBtn.disabled = false;
                pingBtn.textContent = "⚡ Ping All Providers";
            }
        });
    }

    // 2. Test Automated Failover
    const failoverBtn = document.getElementById("btn-mc-test-failover");
    if (failoverBtn) {
        failoverBtn.addEventListener("click", async () => {
            failoverBtn.disabled = true;
            failoverBtn.textContent = "⏳ Simulating...";
            try {
                const res = await api.testStorageFailover(true, "CloudVault automated failover live test");
                if (res && res.verified) {
                    showToast(`Failover verified! Transferred cleanly to ${res.active_destination}.`, "success");
                }
                await loadMultiCloudStorage();
            } catch (e) {
                showToast("Failover test failed: " + e.message, "error");
            } finally {
                failoverBtn.disabled = false;
                failoverBtn.textContent = "🧪 Test Failover";
            }
        });
    }

    // 3. Open Migration Modal
    const migrateBtn = document.getElementById("btn-mc-open-migrate");
    if (migrateBtn) {
        migrateBtn.addEventListener("click", async () => {
            const modal = document.getElementById("modal-cloud-migration");
            const select = document.getElementById("migrate-snapshot-select");
            const feedback = document.getElementById("migration-result-feedback");
            if (feedback) feedback.style.display = "none";

            if (modal && select) {
                select.innerHTML = "<option value=''>Loading snapshots...</option>";
                modal.style.display = "flex";
                try {
                    const plans = await api.getPlans();
                    let allSnaps = [];
                    for (const p of plans) {
                        const sList = await api.getSnapshots(p.id);
                        allSnaps = allSnaps.concat(sList);
                    }
                    if (allSnaps.length === 0) {
                        select.innerHTML = "<option value=''>No snapshots available to migrate</option>";
                    } else {
                        select.innerHTML = allSnaps.map(s => `
                            <option value="${s.id}">${escapeHtml(s.name)} (ID: ${s.id.substring(0,8)}, ${round(s.total_stored_bytes/(1024*1024),2)} MB)</option>
                        `).join("");
                    }
                } catch (e) {
                    select.innerHTML = `<option value=''>Error: ${escapeHtml(e.message)}</option>`;
                }
            }
        });
    }

    // 4. Execute Migration
    const execMigrateBtn = document.getElementById("btn-execute-migration");
    if (execMigrateBtn) {
        execMigrateBtn.addEventListener("click", async () => {
            const snapId = document.getElementById("migrate-snapshot-select").value;
            const targetProv = document.getElementById("migrate-target-provider").value;
            const delSource = document.getElementById("migrate-delete-source").checked;
            const feedback = document.getElementById("migration-result-feedback");

            if (!snapId) {
                showToast("Please select a snapshot to migrate.", "warning");
                return;
            }

            execMigrateBtn.disabled = true;
            execMigrateBtn.textContent = "⏳ Migrating...";
            if (feedback) feedback.style.display = "none";

            try {
                const res = await api.migrateSnapshotCloud(snapId, targetProv, delSource);
                if (feedback) {
                    feedback.style.display = "block";
                    feedback.innerHTML = `
                        <div style="padding:0.75rem;background:rgba(16,185,129,0.15);border:1px solid #10b981;border-radius:6px;color:#34d399;font-size:0.85rem;">
                            ✅ <strong>Migration Verified:</strong> Migrated ${res.result.files_migrated} objects (${round(res.result.total_bytes_migrated/1024, 2)} KB) to ${res.result.to_provider}. Cryptographic SHA-256 hashes verified on target.
                        </div>
                    `;
                }
                showToast("Snapshot migration completed with bit-level verification!", "success");
                await loadMultiCloudStorage();
            } catch (e) {
                if (feedback) {
                    feedback.style.display = "block";
                    feedback.innerHTML = `
                        <div style="padding:0.75rem;background:rgba(239,68,68,0.15);border:1px solid #ef4444;border-radius:6px;color:#f87171;font-size:0.85rem;">
                            🚨 <strong>Migration Failed:</strong> ${escapeHtml(e.message)}
                        </div>
                    `;
                }
                showToast("Migration failed: " + e.message, "error");
            } finally {
                execMigrateBtn.disabled = false;
                execMigrateBtn.textContent = "Start Migration";
            }
        });
    }
}

// -------------------------------------------------------------
// Modals: Drill Report, Point-in-Time, Ransomware Wizard, Sandbox
// -------------------------------------------------------------
async function openDrillReportModal(drillId) {
    const modal = document.getElementById("dr-report-modal");
    const body = document.getElementById("dr-report-modal-body");
    if (!modal || !body) return;

    modal.style.display = "flex";
    body.innerHTML = "<p>Loading drill report...</p>";

    try {
        const rep = await api.getDRDrillReport(drillId);
        const files = rep.verification_report || [];
        const isPassed = rep.status === "PASSED";

        let filesHtml = "";
        if (files.length === 0) {
            filesHtml = `<p style="font-size:0.85rem;color:var(--text-secondary);">No per-file report entries recorded for this drill.</p>`;
        } else {
            filesHtml = `
                <div class="table-wrapper" style="max-height:350px;overflow-y:auto;margin-top:1rem;">
                    <table>
                        <thead>
                            <tr>
                                <th>File Name</th>
                                <th>Expected SHA-256</th>
                                <th>Computed SHA-256</th>
                                <th>Encrypted</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${files.map(f => `
                                <tr>
                                    <td><code>${escapeHTML(f.file_name || f.relative_path)}</code></td>
                                    <td><code style="font-size:0.72rem;">${(f.expected_sha256 || '').substring(0, 16)}...</code></td>
                                    <td><code style="font-size:0.72rem;">${(f.computed_sha256 || '').substring(0, 16)}...</code></td>
                                    <td>${f.is_encrypted ? '🔐 AES-256-GCM' : 'Plaintext'}</td>
                                    <td><span class="badge ${f.status === 'PASSED' ? 'badge-passed' : 'badge-failed'}">${f.status}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        body.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
                <div>
                    <strong style="font-size:1.05rem;">Drill: <code>${rep.drill_id.substring(0, 12)}...</code></strong>
                    <div style="font-size:0.8rem;color:var(--text-secondary);">Target Snapshot: <strong>${escapeHTML(rep.snapshot_name)}</strong> | Type: <code>${rep.drill_type}</code></div>
                </div>
                <span class="badge ${isPassed ? 'badge-passed' : 'badge-failed'}" style="font-size:0.9rem;padding:0.35rem 0.8rem;">
                    ${rep.status}
                </span>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(130px, 1fr));gap:0.75rem;background:rgba(255,255,255,0.03);padding:0.75rem;border-radius:8px;font-size:0.8rem;">
                <div>Files Tested: <strong>${rep.files_tested}</strong></div>
                <div>Bytes Verified: <strong>${formatBytes(rep.bytes_tested)}</strong></div>
                <div>Throughput: <strong>${rep.restoration_speed_mbps} MB/s</strong></div>
                <div>Duration: <strong>${rep.duration_seconds}s</strong></div>
            </div>
            ${rep.error_details ? `<div style="background:rgba(239,68,68,0.1);border:1px solid #ef4444;border-radius:6px;padding:0.6rem;margin-top:0.75rem;color:#fca5a5;font-size:0.8rem;"><strong>Failure Reason:</strong> ${escapeHTML(rep.error_details)}</div>` : ''}
            ${filesHtml}
            <div style="display:flex;justify-content:flex-end;margin-top:1.25rem;">
                <button class="btn btn-secondary btn-sm" onclick="document.getElementById('dr-report-modal').style.display='none'">Close Report</button>
            </div>
        `;
    } catch (err) {
        body.innerHTML = `<p style="color:#ef4444;">Error loading report: ${escapeHTML(err.message)}</p>`;
    }
}

async function openPointInTimeModal() {
    const modal = document.getElementById("dr-pit-modal");
    const body = document.getElementById("dr-pit-modal-body");
    if (!modal || !body) return;

    modal.style.display = "flex";
    body.innerHTML = "<p>Loading recovery snapshots...</p>";

    try {
        const snapshotsData = await api.getSnapshots();
        const snapshots = Array.isArray(snapshotsData) ? snapshotsData : (snapshotsData.snapshots || []);

        if (snapshots.length === 0) {
            body.innerHTML = "<p>No snapshots available for recovery.</p>";
            return;
        }

        body.innerHTML = `
            <div style="display:flex;flex-direction:column;gap:1rem;">
                <div>
                    <label style="font-size:0.8rem;color:var(--text-secondary);display:block;margin-bottom:0.35rem;">Select Recovery Snapshot</label>
                    <select id="pit-snapshot-select" style="width:100%;">
                        ${snapshots.map((s, idx) => `
                            <option value="${s.id}" ${idx === 0 ? 'selected' : ''}>
                                #${s.snapshot_number} ${escapeHTML(s.name)} (${formatDate(s.created_at)}) - ${s.total_files} files ${s.is_locked ? '🔒' : ''}
                            </option>
                        `).join('')}
                    </select>
                </div>
                <div>
                    <label style="font-size:0.8rem;color:var(--text-secondary);display:block;margin-bottom:0.35rem;">Destination Directory (Defaults to safe isolated folder)</label>
                    <input type="text" id="pit-destination-input" placeholder="e.g. data/recovered/pit_restore_1" style="width:100%;">
                </div>
                <div>
                    <label style="font-size:0.8rem;color:var(--text-secondary);display:block;margin-bottom:0.35rem;">Conflict Resolution Strategy</label>
                    <select id="pit-conflict-select" style="width:100%;">
                        <option value="keep_both">Keep Both (Append _restored suffix on collision)</option>
                        <option value="overwrite">Overwrite Existing Files</option>
                        <option value="skip">Skip Existing Files</option>
                    </select>
                </div>
                <div style="display:flex;gap:0.75rem;">
                    <button id="pit-preview-btn" class="btn btn-secondary btn-sm">🔍 Preview Affected Files</button>
                    <button id="pit-execute-btn" class="btn btn-primary btn-sm">🚀 Execute Point-in-Time Restore</button>
                </div>
                <div id="pit-results-container" style="max-height:260px;overflow-y:auto;display:none;background:rgba(0,0,0,0.25);border:1px solid var(--border-color);border-radius:6px;padding:0.75rem;font-size:0.8rem;"></div>
            </div>
        `;

        document.getElementById("pit-preview-btn").addEventListener("click", async () => {
            const snapId = document.getElementById("pit-snapshot-select").value;
            const dest = document.getElementById("pit-destination-input").value;
            const resBox = document.getElementById("pit-results-container");
            resBox.style.display = "block";
            resBox.innerHTML = "<em>Inspecting snapshot contents and comparing with destination...</em>";

            try {
                const prev = await api.getPointInTimePreview(snapId, dest);
                const files = prev.files || [];
                const diff = prev.diff_summary || {};
                resBox.innerHTML = `
                    <div style="display:flex;justify-content:space-between;margin-bottom:0.5rem;">
                        <strong>Total: ${prev.total_files} files (${formatBytes(prev.total_bytes)})</strong>
                        <span>New: <span style="color:#34d399;">${diff.new || 0}</span> | Modified: <span style="color:#fbbf24;">${diff.modified || 0}</span> | Unchanged: <span style="color:#94a3b8;">${diff.unchanged || 0}</span></span>
                    </div>
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr><th>File</th><th>Size</th><th>Encryption</th><th>Diff Status</th></tr>
                            </thead>
                            <tbody>
                                ${files.slice(0, 20).map(f => `
                                    <tr>
                                        <td><code>${escapeHTML(f.relative_path)}</code></td>
                                        <td>${formatBytes(f.file_size)}</td>
                                        <td>${f.is_encrypted ? `🔐 AES-256-GCM (v${f.key_version})` : 'Plaintext'}</td>
                                        <td><span class="badge badge-${f.diff_status === 'NEW' ? 'optimal' : (f.diff_status === 'MODIFIED' ? 'warning' : 'passed')}">${f.diff_status}</span></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            } catch (e) {
                resBox.innerHTML = `<span style="color:#ef4444;">Preview error: ${escapeHTML(e.message)}</span>`;
            }
        });

        document.getElementById("pit-execute-btn").addEventListener("click", async () => {
            const snapId = document.getElementById("pit-snapshot-select").value;
            const dest = document.getElementById("pit-destination-input").value;
            const conflict = document.getElementById("pit-conflict-select").value;
            const resBox = document.getElementById("pit-results-container");
            resBox.style.display = "block";
            resBox.innerHTML = "<em>Executing point-in-time restoration with bit-level verification...</em>";

            try {
                const res = await api.restoreEntireSnapshot(snapId, dest, conflict);
                resBox.innerHTML = `
                    <div style="color:#10b981;font-weight:700;">✅ ${escapeHTML(res.message)}</div>
                    <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.35rem;">
                        Restored: ${res.files_restored} files (${formatBytes(res.bytes_restored)})<br>
                        Destination: <code>${escapeHTML(res.destination)}</code>
                    </div>
                `;
                showToast("Point-in-time restore completed successfully!", "success");
                loadDisasterRecovery();
            } catch (e) {
                resBox.innerHTML = `<span style="color:#ef4444;">Restore failed: ${escapeHTML(e.message)}</span>`;
                showToast("Restore failed: " + e.message, "error");
            }
        });

    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Error: ${escapeHTML(e.message)}</p>`;
    }
}

async function openRansomwareRecoveryModal(preselectedSnapId = null) {
    const modal = document.getElementById("dr-ransomware-modal");
    const body = document.getElementById("dr-ransomware-modal-body");
    if (!modal || !body) return;

    modal.style.display = "flex";
    body.innerHTML = "<p>Generating ransomware incident recovery plan...</p>";

    try {
        const plan = await api.getRansomwareRecoveryPlan();
        const rec = plan.recommended_snapshot;

        if (!rec) {
            body.innerHTML = `
                <p>No clean recovery snapshots could be verified prior to the ransomware incident.</p>
                <button class="btn btn-secondary btn-sm" onclick="document.getElementById('dr-ransomware-modal').style.display='none'">Close</button>
            `;
            return;
        }

        body.innerHTML = `
            <div style="display:flex;flex-direction:column;gap:1rem;">
                <div style="background:rgba(239,68,68,0.1);border:1px solid #ef4444;border-radius:6px;padding:0.75rem;">
                    <strong style="color:#f87171;">Threat Posture: Active Incident Protection</strong>
                    <p style="font-size:0.82rem;color:var(--text-secondary);margin:0.25rem 0 0 0;">
                        CloudVault has isolated corrupted or suspicious blocks. You are preparing to recover from the latest verified clean point: <strong>Snapshot #${rec.snapshot_number} (${escapeHTML(rec.name)})</strong>.
                    </p>
                </div>
                <div>
                    <h4 style="margin:0 0 0.5rem 0;font-size:0.95rem;">Clean Recovery Point Verification:</h4>
                    <ul style="font-size:0.8rem;margin:0 0 0 1.25rem;color:#e2e8f0;">
                        ${(plan.safety_justification || []).map(j => `<li>${escapeHTML(j)}</li>`).join('')}
                    </ul>
                </div>
                <div>
                    <label style="font-size:0.8rem;color:var(--text-secondary);display:block;margin-bottom:0.35rem;">Isolated Recovery Folder (Prevents overwriting forensic data)</label>
                    <input type="text" id="rw-destination-input" value="${plan.suggested_destination || 'data/recovered/ransomware_clean_recovery'}" style="width:100%;">
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.5rem;">
                    <input type="checkbox" id="rw-confirm-checkbox">
                    <label for="rw-confirm-checkbox" style="font-size:0.85rem;color:#f8fafc;cursor:pointer;">
                        I confirm restoration of this verified pre-incident baseline.
                    </label>
                </div>
                <div style="display:flex;justify-content:flex-end;gap:0.75rem;margin-top:0.5rem;">
                    <button class="btn btn-secondary btn-sm" onclick="document.getElementById('dr-ransomware-modal').style.display='none'">Cancel</button>
                    <button id="rw-execute-btn" class="btn btn-danger btn-sm" disabled>Confirm & Execute Clean Recovery</button>
                </div>
                <div id="rw-status-box" style="display:none;padding:0.75rem;border-radius:6px;font-size:0.82rem;"></div>
            </div>
        `;

        const chk = document.getElementById("rw-confirm-checkbox");
        const btnExec = document.getElementById("rw-execute-btn");
        chk.addEventListener("change", () => {
            btnExec.disabled = !chk.checked;
        });

        btnExec.addEventListener("click", async () => {
            btnExec.disabled = true;
            btnExec.textContent = "⏳ Restoring...";
            const sBox = document.getElementById("rw-status-box");
            sBox.style.display = "block";
            sBox.style.background = "rgba(56,189,248,0.1)";
            sBox.innerHTML = "<em>Restoring verified clean files with bit-level SHA-256 checks...</em>";

            try {
                const dest = document.getElementById("rw-destination-input").value;
                const res = await api.executeRansomwareRecovery({
                    snapshot_id: rec.id,
                    destination_dir: dest,
                    conflict_strategy: "keep_both",
                    confirmed: true
                });

                sBox.style.background = "rgba(16,185,129,0.15)";
                sBox.style.border = "1px solid #10b981";
                sBox.innerHTML = `
                    <strong style="color:#10b981;">✅ RANSOMWARE RECOVERY COMPLETE</strong><br>
                    Restored <strong>${res.files_restored} verified files</strong> (${formatBytes(res.bytes_restored)})<br>
                    Destination: <code>${escapeHTML(res.destination)}</code><br>
                    Duration: ${res.duration_seconds}s | Speed: ${res.restoration_speed_mbps} MB/s
                `;
                showToast("Clean recovery point restored successfully!", "success");
                loadDisasterRecovery();
            } catch (err) {
                sBox.style.background = "rgba(239,68,68,0.15)";
                sBox.style.border = "1px solid #ef4444";
                sBox.innerHTML = `<span style="color:#f87171;">Recovery failed: ${escapeHTML(err.message)}</span>`;
                showToast("Recovery failed: " + err.message, "error");
            }
        });

    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Error: ${escapeHTML(e.message)}</p>`;
    }
}

async function openRecoverySandboxModal() {
    const modal = document.getElementById("dr-sandbox-modal");
    const body = document.getElementById("dr-sandbox-modal-body");
    if (!modal || !body) return;

    modal.style.display = "flex";
    body.innerHTML = "<p>Loading recovery snapshots...</p>";

    try {
        const snapshotsData = await api.getSnapshots();
        const snapshots = Array.isArray(snapshotsData) ? snapshotsData : (snapshotsData.snapshots || []);

        if (snapshots.length === 0) {
            body.innerHTML = "<p>No snapshots available.</p>";
            return;
        }

        body.innerHTML = `
            <div style="display:flex;flex-direction:column;gap:1rem;">
                <p style="font-size:0.85rem;color:var(--text-secondary);margin:0;">
                    Streams backup objects into an isolated temporary RAM/disk sandbox, verifies SHA-256 signatures, validates envelope decryption, and lets you safely inspect file contents before restoring to live storage.
                </p>
                <div>
                    <label style="font-size:0.8rem;color:var(--text-secondary);display:block;margin-bottom:0.35rem;">Select Snapshot</label>
                    <select id="sb-snapshot-select" style="width:100%;">
                        ${snapshots.map((s, idx) => `
                            <option value="${s.id}" ${idx === 0 ? 'selected' : ''}>
                                #${s.snapshot_number} ${escapeHTML(s.name)} (${formatDate(s.created_at)})
                            </option>
                        `).join('')}
                    </select>
                </div>
                <div>
                    <button id="sb-run-btn" class="btn btn-primary btn-sm">🚀 Run Sandboxed Preview</button>
                </div>
                <div id="sb-results-container" style="display:none;background:rgba(0,0,0,0.3);border:1px solid var(--border-color);border-radius:6px;padding:0.75rem;max-height:350px;overflow-y:auto;font-size:0.82rem;"></div>
            </div>
        `;

        document.getElementById("sb-run-btn").addEventListener("click", async () => {
            const snapId = document.getElementById("sb-snapshot-select").value;
            const rBox = document.getElementById("sb-results-container");
            rBox.style.display = "block";
            rBox.innerHTML = "<em>Spinning up isolated sandbox, downloading blocks, verifying digests...</em>";

            try {
                const res = await api.runRecoverySandboxPreview({ snapshot_id: snapId });
                const previews = res.previews || [];
                rBox.innerHTML = `
                    <div style="display:flex;justify-content:space-between;margin-bottom:0.5rem;border-bottom:1px solid var(--border-color);padding-bottom:0.35rem;">
                        <strong>Tested: ${res.files_tested} files</strong>
                        <span style="color:#10b981;">Status: ${res.status}</span>
                    </div>
                    ${previews.map(p => `
                        <div style="margin-bottom:0.75rem;padding-bottom:0.75rem;border-bottom:1px solid rgba(255,255,255,0.06);">
                            <div style="display:flex;justify-content:space-between;align-items:center;">
                                <code>${escapeHTML(p.relative_path)}</code>
                                <span class="badge ${p.status === 'VERIFIED' ? 'badge-passed' : 'badge-failed'}">${p.status}</span>
                            </div>
                            <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:0.2rem;">
                                Expected: <code>${(p.expected_sha256 || '').substring(0, 16)}...</code> | Computed: <code>${(p.computed_sha256 || '').substring(0, 16)}...</code> | Match: ${p.sha256_verified ? '✅' : '❌'}
                            </div>
                            ${p.preview_snippet ? `
                                <pre style="background:#0f172a;padding:0.5rem;border-radius:4px;margin-top:0.4rem;font-size:0.72rem;max-height:100px;overflow-y:auto;">${escapeHTML(p.preview_snippet)}</pre>
                            ` : ''}
                        </div>
                    `).join('')}
                `;
            } catch (err) {
                rBox.innerHTML = `<span style="color:#ef4444;">Sandbox execution error: ${escapeHTML(err.message)}</span>`;
            }
        });

    } catch (e) {
        body.innerHTML = `<p style="color:#ef4444;">Error: ${escapeHTML(e.message)}</p>`;
    }
}

function exportDRReport() {
    if (!currentDRTelemetry) {
        showToast("No telemetry loaded yet to export.", "warning");
        return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentDRTelemetry, null, 2));
    const dlAnchor = document.createElement("a");
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `cloudvault_dr_report_${new Date().toISOString().substring(0, 10)}.json`);
    document.body.appendChild(dlAnchor);
    dlAnchor.click();
    dlAnchor.remove();
    showToast("Disaster Recovery report exported successfully!", "success");
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

        // =================================================================
        // PHASE 4: ENCRYPTION, MFA & WORM SNAPSHOT RETENTION CONTROLLERS
        // =================================================================

        // 6. Load Zero-Trust Encryption Status
        try {
            const cryptoStatus = await api.getCryptoStatus();
            const kekEl = document.getElementById("crypto-kek-version");
            const encCountEl = document.getElementById("crypto-enc-count");
            const badgeEl = document.getElementById("crypto-engine-badge");

            if (kekEl) kekEl.textContent = `Version v${cryptoStatus.key_version || 1}`;
            if (encCountEl) encCountEl.textContent = `${cryptoStatus.encrypted_objects_count} objects (${cryptoStatus.encryption_ratio_percent}%)`;
            if (badgeEl) {
                badgeEl.textContent = cryptoStatus.all_plans_encrypted ? "AES-256-GCM Active" : "Partial Encryption";
                badgeEl.className = cryptoStatus.all_plans_encrypted ? "badge badge-passed" : "badge badge-warning";
            }
        } catch (e) {
            console.warn("Could not load crypto status:", e);
        }

        // Bind Key Rotation Button
        const rotateBtn = document.getElementById("btn-rotate-key");
        if (rotateBtn && !rotateBtn.dataset.bound) {
            rotateBtn.dataset.bound = "true";
            rotateBtn.onclick = () => {
                const modal = document.getElementById("key-rotation-modal");
                if (modal) modal.style.display = "flex";
            };
        }

        const confirmRotateBtn = document.getElementById("confirm-rotate-key-btn");
        if (confirmRotateBtn && !confirmRotateBtn.dataset.bound) {
            confirmRotateBtn.dataset.bound = "true";
            confirmRotateBtn.onclick = async () => {
                try {
                    confirmRotateBtn.disabled = true;
                    confirmRotateBtn.textContent = "Rotating...";
                    const res = await api.rotateCryptoKey();
                    showToast(`Key rotated successfully to version v${res.new_key_version}!`, "success");
                    document.getElementById("key-rotation-modal").style.display = "none";
                    loadSecurityCenter();
                } catch (e) {
                    showToast("Key rotation failed: " + e.message, "error");
                } finally {
                    confirmRotateBtn.disabled = false;
                    confirmRotateBtn.textContent = "Confirm Key Rotation";
                }
            };
        }

        // 7. Load Multi-Factor Authentication Status
        try {
            const mfaStatus = await api.getMFAStatus();
            const badgeEl = document.getElementById("mfa-status-badge");
            const recCountEl = document.getElementById("mfa-recovery-count");
            const protLevelEl = document.getElementById("mfa-protection-level");
            const manageBtn = document.getElementById("btn-manage-mfa");

            if (badgeEl) {
                badgeEl.textContent = mfaStatus.mfa_enabled ? "TOTP ACTIVE" : "DISABLED";
                badgeEl.className = mfaStatus.mfa_enabled ? "badge badge-passed" : "badge badge-warning";
            }
            if (recCountEl) {
                recCountEl.textContent = mfaStatus.mfa_enabled ? `${mfaStatus.recovery_codes_remaining} remaining` : "None configured";
            }
            if (protLevelEl) {
                protLevelEl.textContent = mfaStatus.mfa_enabled ? "2FA (Password + TOTP)" : "Password Only";
                protLevelEl.style.color = mfaStatus.mfa_enabled ? "#10b981" : "#f59e0b";
            }
            if (manageBtn) {
                manageBtn.textContent = mfaStatus.mfa_enabled ? "📱 Manage 2FA Settings" : "📱 Set Up MFA Now";
                manageBtn.onclick = () => openMFAModal(mfaStatus);
            }
        } catch (e) {
            console.warn("Could not load MFA status:", e);
        }

        // 8. Load WORM Snapshot Retention Table
        try {
            const snaps = await api.getSnapshots();
            const wormTbody = document.getElementById("worm-snapshots-table-body");
            if (wormTbody) {
                wormTbody.innerHTML = "";
                if (!snaps || snaps.length === 0) {
                    wormTbody.innerHTML = "<tr><td colspan='7' style='text-align:center;'>No snapshots available yet.</td></tr>";
                } else {
                    snaps.forEach(s => {
                        const tr = document.createElement("tr");
                        const isLocked = s.is_locked || s.is_immutable;
                        const retentionMode = s.retention_mode || (isLocked ? "SIMULATED" : "NONE");
                        const lockType = s.provider_lock_type || (isLocked ? "MOCK_SIMULATED" : "UNLOCKED");
                        const expiryText = isLocked && s.lock_until ? formatDate(s.lock_until) : "Not Locked";

                        const modeBadge = isLocked ? (
                            retentionMode === "PROVIDER_ENFORCED" ?
                                `<span class="badge badge-passed">Provider-Enforced</span>` :
                                `<span class="badge badge-mock">Simulated WORM</span>`
                        ) : `<span class="badge badge-secondary">Unlocked</span>`;

                        const actionBtn = isLocked ?
                            `<span class="badge badge-passed" style="font-size:0.75rem;">🔒 Locked</span>` :
                            `<button class="btn btn-outline-accent btn-sm lock-worm-btn" data-snap-id="${s.id}">🔒 Lock WORM</button>`;

                        tr.innerHTML = `
                            <td><strong>#${s.snapshot_number}</strong></td>
                            <td>${escapeHTML(s.name)}</td>
                            <td style="font-size:0.8rem;">${formatDate(s.created_at)}</td>
                            <td>${modeBadge}</td>
                            <td><code>${escapeHTML(lockType)}</code></td>
                            <td style="font-size:0.8rem;${isLocked ? 'color:#34d399;' : ''}">${expiryText}</td>
                            <td>${actionBtn}</td>
                        `;
                        wormTbody.appendChild(tr);
                    });

                    // Bind lock WORM buttons
                    wormTbody.querySelectorAll(".lock-worm-btn").forEach(btn => {
                        btn.onclick = async () => {
                            const snapId = btn.dataset.snapId;
                            const daysStr = prompt("Enter WORM retention period in days (e.g., 30):", "30");
                            if (!daysStr) return;
                            const days = parseInt(daysStr, 10);
                            if (isNaN(days) || days <= 0) {
                                showToast("Please enter a valid positive number of days.", "error");
                                return;
                            }
                            try {
                                btn.disabled = true;
                                btn.textContent = "Locking...";
                                const res = await api.lockSnapshotWORM(snapId, days);
                                showToast(res.message || "Snapshot locked with immutable retention policy!", "success");
                                loadSecurityCenter();
                            } catch (err) {
                                showToast("Failed to lock snapshot: " + err.message, "error");
                                btn.disabled = false;
                                btn.textContent = "🔒 Lock WORM";
                            }
                        };
                    });
                }
            }
        } catch (e) {
            console.warn("Could not load WORM snapshots:", e);
        }

        // 9. Bind Audit Chain Verification Button
        const verifyAuditBtn = document.getElementById("verify-audit-chain-btn");
        if (verifyAuditBtn && !verifyAuditBtn.dataset.bound) {
            verifyAuditBtn.dataset.bound = "true";
            verifyAuditBtn.onclick = async () => {
                const badge = document.getElementById("audit-chain-badge");
                verifyAuditBtn.disabled = true;
                verifyAuditBtn.textContent = "Verifying...";
                try {
                    const res = await api.verifyAuditTrail();
                    if (res.is_valid) {
                        badge.className = "badge badge-passed";
                        badge.textContent = `⛓️ Hash Chain: Verified (${res.verified_entries} Blocks Intact)`;
                        showToast(`Audit hash chain 100% verified! ${res.verified_entries} sequential blocks intact.`, "success");
                    } else {
                        badge.className = "badge badge-quarantined";
                        badge.textContent = "🚨 Hash Chain: TAMPERED";
                        showToast(`Audit discrepancy detected at block ${res.broken_entry_id}: ${res.error_message}`, "error");
                    }
                } catch (e) {
                    showToast("Could not verify audit chain: " + e.message, "error");
                } finally {
                    verifyAuditBtn.disabled = false;
                    verifyAuditBtn.textContent = "Verify Hash Chain";
                }
            };
        }

    } catch (err) {
        console.error("Security Center load error:", err);
        showToast("Could not load security center: " + err.message, "error");
    }
}

// MFA Setup & Management Modal View Controller
async function openMFAModal(mfaStatus) {
    const modal = document.getElementById("mfa-modal");
    const body = document.getElementById("mfa-modal-body");
    const title = document.getElementById("mfa-modal-title");
    if (!modal || !body) return;

    modal.style.display = "flex";

    if (!mfaStatus.mfa_enabled) {
        // ENROLLMENT FLOW
        title.textContent = "📱 Set Up Two-Factor Authentication";
        body.innerHTML = `
            <div style="text-align:center;padding:1rem;">
                <p style="font-size:0.875rem;color:var(--text-secondary);margin-bottom:1rem;">
                    Loading authenticator key...
                </p>
            </div>
        `;

        try {
            const setupData = await api.setupMFA();
            body.innerHTML = `
                <div style="font-size:0.875rem;color:var(--text-secondary);margin-bottom:1rem;">
                    <p>1. Open your authenticator app (<strong>Google Authenticator</strong>, <strong>Microsoft Authenticator</strong>, or <strong>Authy</strong>).</p>
                    <p style="margin-top:0.5rem;">2. Add an account and enter this secret key manually:</p>
                </div>
                <div style="background:rgba(0,0,0,0.3);padding:0.75rem 1rem;border-radius:6px;font-family:monospace;font-size:1.1rem;text-align:center;letter-spacing:2px;color:#38bdf8;border:1px solid var(--border-color);margin-bottom:1rem;user-select:all;">
                    ${setupData.secret}
                </div>
                <div style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:1.25rem;">
                    <p>3. Enter the 6-digit confirmation code generated by your authenticator app:</p>
                </div>
                <form id="mfa-enable-form" style="display:flex;flex-direction:column;gap:0.75rem;">
                    <input type="text" id="mfa-enroll-code" maxlength="6" placeholder="000000" style="text-align:center;font-size:1.5rem;letter-spacing:4px;padding:0.5rem;font-family:monospace;" required autocomplete="off">
                    <button type="submit" class="btn btn-primary" style="width:100%;">Verify & Enable 2FA</button>
                </form>
            `;

            document.getElementById("mfa-enable-form").onsubmit = async (e) => {
                e.preventDefault();
                const code = document.getElementById("mfa-enroll-code").value.trim();
                try {
                    const enableRes = await api.enableMFA(setupData.secret, code);
                    const recoveryCodes = enableRes.recovery_codes || [];
                    title.textContent = "🎉 MFA Enabled Successfully!";
                    body.innerHTML = `
                        <div style="font-size:0.875rem;color:var(--text-secondary);margin-bottom:1rem;">
                            <p style="color:#10b981;font-weight:600;">Two-Factor Authentication is now active on your CloudVault account.</p>
                            <p style="margin-top:0.5rem;color:#f59e0b;"><strong>⚠️ Save Your Emergency Recovery Codes:</strong></p>
                            <p>Each code can be used once to access your account if you lose access to your authenticator device. These will not be displayed again.</p>
                        </div>
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;background:rgba(0,0,0,0.3);padding:1rem;border-radius:6px;font-family:monospace;font-size:0.9rem;border:1px solid var(--border-color);margin-bottom:1rem;">
                            ${recoveryCodes.map(c => `<div style="color:#38bdf8;padding:0.25rem;">• ${c}</div>`).join("")}
                        </div>
                        <div style="display:flex;gap:0.75rem;">
                            <button id="copy-rec-codes-btn" class="btn btn-secondary btn-sm" style="flex:1;">📋 Copy Codes</button>
                            <button class="btn btn-primary btn-sm" style="flex:1;" onclick="document.getElementById('mfa-modal').style.display='none';loadSecurityCenter();">Done</button>
                        </div>
                    `;

                    document.getElementById("copy-rec-codes-btn").onclick = () => {
                        navigator.clipboard.writeText(recoveryCodes.join("\n"));
                        showToast("Recovery codes copied to clipboard!", "success");
                    };
                    showToast("MFA successfully activated!", "success");
                } catch (err) {
                    showToast("Failed to enable MFA: " + err.message, "error");
                }
            };
        } catch (err) {
            body.innerHTML = `<div style="color:#ef4444;padding:1rem;">Could not initialize MFA setup: ${err.message}</div>`;
        }
    } else {
        // MANAGEMENT / DISABLE FLOW
        title.textContent = "📱 Manage Two-Factor Authentication";
        body.innerHTML = `
            <div style="font-size:0.875rem;color:var(--text-secondary);margin-bottom:1.25rem;">
                <p>MFA is currently <strong style="color:#10b981;">Active</strong>. You have <strong>${mfaStatus.recovery_codes_remaining}</strong> unused emergency recovery codes.</p>
            </div>
            
            <div style="border-top:1px solid var(--border-color);padding-top:1rem;margin-bottom:1rem;">
                <h4 style="margin:0 0 0.5rem 0;font-size:0.95rem;">Regenerate Emergency Recovery Codes</h4>
                <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem;">Requires your current password and a valid 6-digit TOTP code.</p>
                <form id="mfa-regen-form" style="display:flex;flex-direction:column;gap:0.5rem;">
                    <input type="password" id="mfa-regen-pw" placeholder="Current Account Password" required style="padding:0.4rem;">
                    <input type="text" id="mfa-regen-code" maxlength="6" placeholder="Current 6-Digit TOTP Code" required style="padding:0.4rem;font-family:monospace;">
                    <button type="submit" class="btn btn-secondary btn-sm">Regenerate 8 New Codes</button>
                </form>
            </div>

            <div style="border-top:1px solid var(--border-color);padding-top:1rem;">
                <h4 style="margin:0 0 0.5rem 0;font-size:0.95rem;color:#ef4444;">Disable Two-Factor Authentication</h4>
                <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:0.75rem;">Disabling MFA reduces account security. Requires password and TOTP verification.</p>
                <form id="mfa-disable-form" style="display:flex;flex-direction:column;gap:0.5rem;">
                    <input type="password" id="mfa-disable-pw" placeholder="Current Account Password" required style="padding:0.4rem;">
                    <input type="text" id="mfa-disable-code" maxlength="6" placeholder="Current 6-Digit TOTP Code" required style="padding:0.4rem;font-family:monospace;">
                    <button type="submit" class="btn btn-warning btn-sm">Confirm & Disable MFA</button>
                </form>
            </div>
        `;

        document.getElementById("mfa-regen-form").onsubmit = async (e) => {
            e.preventDefault();
            const pw = document.getElementById("mfa-regen-pw").value;
            const code = document.getElementById("mfa-regen-code").value.trim();
            try {
                const res = await api.regenerateRecoveryCodes(pw, code);
                const codes = res.recovery_codes || [];
                alert("New Recovery Codes Generated:\n\n" + codes.join("\n") + "\n\nSave these codes securely!");
                showToast("8 fresh recovery codes generated!", "success");
                loadSecurityCenter();
            } catch (err) {
                showToast("Regeneration failed: " + err.message, "error");
            }
        };

        document.getElementById("mfa-disable-form").onsubmit = async (e) => {
            e.preventDefault();
            const pw = document.getElementById("mfa-disable-pw").value;
            const code = document.getElementById("mfa-disable-code").value.trim();
            try {
                await api.disableMFA(pw, code);
                showToast("Multi-Factor Authentication disabled.", "info");
                document.getElementById("mfa-modal").style.display = "none";
                loadSecurityCenter();
            } catch (err) {
                showToast("Failed to disable MFA: " + err.message, "error");
            }
        };
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
