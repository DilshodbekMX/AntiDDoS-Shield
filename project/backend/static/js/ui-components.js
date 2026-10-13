/**
 * Anti-DDoS Dashboard UI Components
 * Reusable JavaScript UI utilities
 */

// ============================================================================
// Toast Notifications
// ============================================================================

const Toast = {
    container: null,

    init() {
        if (this.container) return;
        this.container = document.createElement('div');
        this.container.className = 'toast-container';
        this.container.setAttribute('role', 'alert');
        this.container.setAttribute('aria-live', 'polite');
        document.body.appendChild(this.container);
    },

    show(message, type = 'info', duration = 5000) {
        this.init();

        const toast = document.createElement('div');
        toast.className = `toast toast--${type}`;
        toast.innerHTML = `
            <span class="toast__message">${this.escapeHtml(message)}</span>
            <button class="toast__close" aria-label="Close notification">&times;</button>
        `;

        const closeBtn = toast.querySelector('.toast__close');
        closeBtn.addEventListener('click', () => this.dismiss(toast));

        this.container.appendChild(toast);

        // Auto dismiss
        if (duration > 0) {
            setTimeout(() => this.dismiss(toast), duration);
        }

        return toast;
    },

    dismiss(toast) {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    },

    success(message) { return this.show(message, 'success'); },
    error(message) { return this.show(message, 'error'); },
    warning(message) { return this.show(message, 'warning'); },
    info(message) { return this.show(message, 'info'); },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// ============================================================================
// Modal Dialog
// ============================================================================

const Modal = {
    activeModal: null,

    open(options) {
        const {
            title = 'Dialog',
            content = '',
            confirmText = 'Confirm',
            cancelText = 'Cancel',
            onConfirm = null,
            onCancel = null,
            dangerous = false
        } = options;

        // Close any existing modal
        this.close();

        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop is-open';
        backdrop.setAttribute('role', 'dialog');
        backdrop.setAttribute('aria-modal', 'true');
        backdrop.setAttribute('aria-labelledby', 'modal-title');

        backdrop.innerHTML = `
            <div class="modal">
                <div class="modal__header">
                    <h2 class="modal__title" id="modal-title">${this.escapeHtml(title)}</h2>
                    <button class="modal__close" aria-label="Close dialog">&times;</button>
                </div>
                <div class="modal__body">
                    ${content}
                </div>
                <div class="modal__footer">
                    <button class="btn btn--secondary" data-action="cancel">${this.escapeHtml(cancelText)}</button>
                    <button class="btn ${dangerous ? 'btn--danger' : 'btn--primary'}" data-action="confirm">${this.escapeHtml(confirmText)}</button>
                </div>
            </div>
        `;

        // Event handlers
        const closeBtn = backdrop.querySelector('.modal__close');
        const confirmBtn = backdrop.querySelector('[data-action="confirm"]');
        const cancelBtn = backdrop.querySelector('[data-action="cancel"]');

        const handleClose = () => {
            if (onCancel) onCancel();
            this.close();
        };

        const handleConfirm = () => {
            if (onConfirm) onConfirm();
            this.close();
        };

        closeBtn.addEventListener('click', handleClose);
        cancelBtn.addEventListener('click', handleClose);
        confirmBtn.addEventListener('click', handleConfirm);

        // Close on backdrop click
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) handleClose();
        });

        // Close on Escape key
        const handleKeydown = (e) => {
            if (e.key === 'Escape') {
                handleClose();
                document.removeEventListener('keydown', handleKeydown);
            }
        };
        document.addEventListener('keydown', handleKeydown);

        document.body.appendChild(backdrop);
        this.activeModal = backdrop;

        // Focus trap
        confirmBtn.focus();

        return backdrop;
    },

    close() {
        if (this.activeModal) {
            this.activeModal.classList.remove('is-open');
            setTimeout(() => {
                this.activeModal?.remove();
                this.activeModal = null;
            }, 300);
        }
    },

    confirm(message, onConfirm) {
        return this.open({
            title: 'Confirm Action',
            content: `<p>${this.escapeHtml(message)}</p>`,
            onConfirm
        });
    },

    confirmDanger(message, onConfirm) {
        return this.open({
            title: 'Are you sure?',
            content: `<p style="color: var(--color-danger);">${this.escapeHtml(message)}</p>`,
            confirmText: 'Delete',
            dangerous: true,
            onConfirm
        });
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// ============================================================================
// Loading States
// ============================================================================

const Loading = {
    show(element, text = 'Loading...') {
        element.style.position = 'relative';
        const overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div style="display: flex; flex-direction: column; align-items: center; gap: 12px;">
                <div class="spinner"></div>
                <span style="color: var(--color-text-secondary); font-size: 14px;">${text}</span>
            </div>
        `;
        element.appendChild(overlay);
        return overlay;
    },

    hide(element) {
        const overlay = element.querySelector('.loading-overlay');
        if (overlay) overlay.remove();
    },

    skeleton(count = 3, type = 'text') {
        return Array(count).fill(0).map(() =>
            `<div class="skeleton skeleton--${type}"></div>`
        ).join('');
    }
};

// ============================================================================
// Form Validation
// ============================================================================

const Validator = {
    isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipv4Regex.test(ip);
    },

    isValidCIDR(cidr) {
        const parts = cidr.split('/');
        if (parts.length !== 2) return false;
        if (!this.isValidIP(parts[0])) return false;
        const prefix = parseInt(parts[1], 10);
        return prefix >= 0 && prefix <= 32;
    },

    isValidPort(port) {
        const p = parseInt(port, 10);
        return !isNaN(p) && p >= 0 && p <= 65535;
    },

    sanitizeDescription(text, maxLength = 100) {
        return text
            .replace(/[<>'"&]/g, '')
            .trim()
            .slice(0, maxLength);
    }
};

// ============================================================================
// Format Utilities
// ============================================================================

const Format = {
    number(n, decimals = 0) {
        return new Intl.NumberFormat().format(Number(n).toFixed(decimals));
    },

    bytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
    },

    bps(bps, decimals = 2) {
        if (bps === 0) return '0 bps';
        const k = 1000;
        const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
        const i = Math.floor(Math.log(bps) / Math.log(k));
        return parseFloat((bps / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
    },

    pps(pps, decimals = 1) {
        if (pps === 0) return '0 pps';
        const k = 1000;
        const sizes = ['pps', 'Kpps', 'Mpps', 'Gpps'];
        const i = Math.floor(Math.log(pps) / Math.log(k));
        return parseFloat((pps / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
    },

    duration(seconds) {
        if (seconds < 60) return `${seconds.toFixed(1)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    },

    relativeTime(date) {
        const now = new Date();
        const diff = (now - date) / 1000;

        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
        return `${Math.floor(diff / 86400)} days ago`;
    },

    ip(ipInt) {
        if (!ipInt) return '0.0.0.0';
        return [
            (ipInt >>> 24) & 255,
            (ipInt >>> 16) & 255,
            (ipInt >>> 8) & 255,
            ipInt & 255
        ].join('.');
    },

    percentage(value, total, decimals = 1) {
        if (total === 0) return '0%';
        return ((value / total) * 100).toFixed(decimals) + '%';
    }
};

// ============================================================================
// API Client with Error Handling
// ============================================================================

const API = {
    baseUrl: '',

    async request(endpoint, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        try {
            const response = await fetch(
                `${this.baseUrl}${endpoint}`,
                { ...defaultOptions, ...options }
            );

            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.error || `HTTP ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            Toast.error(`API Error: ${error.message}`);
            throw error;
        }
    },

    get(endpoint) {
        return this.request(endpoint);
    },

    post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },

    put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    }
};

// ============================================================================
// Keyboard Shortcuts
// ============================================================================

const Shortcuts = {
    handlers: new Map(),

    init() {
        document.addEventListener('keydown', (e) => {
            // Ignore if typing in input
            if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;

            const key = [
                e.ctrlKey && 'ctrl',
                e.shiftKey && 'shift',
                e.altKey && 'alt',
                e.key.toLowerCase()
            ].filter(Boolean).join('+');

            const handler = this.handlers.get(key);
            if (handler) {
                e.preventDefault();
                handler();
            }
        });
    },

    register(key, handler, description = '') {
        this.handlers.set(key.toLowerCase(), handler);
    },

    unregister(key) {
        this.handlers.delete(key.toLowerCase());
    }
};

// ============================================================================
// Chart Helpers
// ============================================================================

const ChartHelpers = {
    defaultConfig: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
            legend: {
                labels: {
                    color: '#94a3b8',
                    usePointStyle: true,
                    padding: 20,
                }
            },
            tooltip: {
                backgroundColor: '#1e293b',
                titleColor: '#e2e8f0',
                bodyColor: '#94a3b8',
                borderColor: '#334155',
                borderWidth: 1,
                padding: 12,
                displayColors: true,
            }
        },
        scales: {
            x: {
                display: false,
            },
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(51, 65, 85, 0.5)',
                },
                ticks: {
                    color: '#94a3b8',
                }
            }
        }
    },

    createDataset(label, color, data = []) {
        return {
            label,
            data,
            borderColor: color,
            backgroundColor: `${color}20`,
            fill: true,
            tension: 0.3,
            pointRadius: 0,
            pointHoverRadius: 4,
        };
    },

    pushAndLimit(array, value, maxLength = 60) {
        array.push(value);
        if (array.length > maxLength) {
            array.shift();
        }
    }
};

// ============================================================================
// Initialize
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    Shortcuts.init();

    // Register common shortcuts
    Shortcuts.register('?', () => {
        Modal.open({
            title: 'Keyboard Shortcuts',
            content: `
                <table class="table" style="font-size: 14px;">
                    <tr><td><kbd>?</kbd></td><td>Show this help</td></tr>
                    <tr><td><kbd>Esc</kbd></td><td>Close modal/dialog</td></tr>
                    <tr><td><kbd>r</kbd></td><td>Refresh data</td></tr>
                </table>
            `,
            confirmText: 'Close',
            cancelText: '',
        });
    });
});

// Export for use
window.UI = { Toast, Modal, Loading, Validator, Format, API, Shortcuts, ChartHelpers };
