/**
 * Modern JavaScript enhancements for CyberCheck dashboard
 * Provides real-time updates, better UX, and advanced interactions
 */

(function() {
    'use strict';

    // Real-time update system
    class RealTimeUpdater {
        constructor() {
            this.intervals = new Map();
            this.eventSource = null;
        }

        startPolling(endpoint, callback, interval = 5000) {
            const existing = this.intervals.get(endpoint);
            if (existing) {
                clearInterval(existing);
            }

            const poll = async () => {
                try {
                    const response = await fetch(endpoint);
                    if (response.ok) {
                        const data = await response.json();
                        callback(data);
                    }
                } catch (error) {
                    console.error(`Polling error for ${endpoint}:`, error);
                }
            };

            // Initial call
            poll();
            const intervalId = setInterval(poll, interval);
            this.intervals.set(endpoint, intervalId);
        }

        stopPolling(endpoint) {
            const intervalId = this.intervals.get(endpoint);
            if (intervalId) {
                clearInterval(intervalId);
                this.intervals.delete(endpoint);
            }
        }

        stopAll() {
            this.intervals.forEach(id => clearInterval(id));
            this.intervals.clear();
        }
    }

    // Toast notification system
    class ToastManager {
        constructor() {
            this.container = this.createContainer();
        }

        createContainer() {
            let container = document.getElementById('toast-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'toast-container';
                container.className = 'toast-container';
                document.body.appendChild(container);
            }
            return container;
        }

        show(message, type = 'info', duration = 5000) {
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = `
                <div class="d-flex align-items-center justify-content-between">
                    <span>${message}</span>
                    <button class="btn-close btn-close-white ms-3" onclick="this.closest('.toast').remove()"></button>
                </div>
            `;
            
            this.container.appendChild(toast);
            
            // Auto remove
            setTimeout(() => {
                toast.style.animation = 'fade-out 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        success(message, duration) {
            this.show(message, 'success', duration);
        }

        error(message, duration) {
            this.show(message, 'error', duration);
        }

        info(message, duration) {
            this.show(message, 'info', duration);
        }
    }

    // Form validation enhancements
    class FormValidator {
        static validate(target) {
            const form = typeof target === 'string' ? document.querySelector(target) : target;
            if (!form) return false;

            let isValid = true;
            const requiredFields = form.querySelectorAll('[required]');
            
            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    field.classList.add('is-invalid');
                    isValid = false;
                } else {
                    field.classList.remove('is-invalid');
                }
            });

            // Custom validation
            form.querySelectorAll('[data-validate]').forEach(field => {
                const validator = field.dataset.validate;
                const value = field.value.trim();
                
                if (value && !this[validator](value)) {
                    field.classList.add('is-invalid');
                    isValid = false;
                } else {
                    field.classList.remove('is-invalid');
                }
            });

            return isValid;
        }

        static ip(value) {
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return ipRegex.test(value);
        }

        static url(value) {
            try {
                new URL(value);
                return true;
            } catch {
                return false;
            }
        }

        static port(value) {
            const port = parseInt(value, 10);
            return !isNaN(port) && port >= 1 && port <= 65535;
        }
    }

    // Live stats updater
    class LiveStatsUpdater {
        constructor(containerSelector) {
            this.container = document.querySelector(containerSelector);
            this.realTimeUpdater = new RealTimeUpdater();
        }

        start() {
            // Update dashboard stats
            this.realTimeUpdater.startPolling('/api/runs', (data) => {
                this.updateStats(data);
            }, 10000); // Update every 10 seconds
        }

        updateStats(data) {
            if (!this.container) return;

            // Update metrics with animation
            const stats = this.container.querySelectorAll('.stat-number');
            stats.forEach(stat => {
                const newValue = stat.dataset.value;
                if (stat.textContent !== newValue) {
                    stat.style.animation = 'pulse 0.5s ease';
                    setTimeout(() => {
                        stat.textContent = newValue;
                        stat.style.animation = '';
                    }, 500);
                }
            });
        }
    }

    // Network activity visualizer
    class NetworkVisualizer {
        constructor(canvasSelector) {
            this.canvas = document.querySelector(canvasSelector);
            if (!this.canvas) return;
            
            this.ctx = this.canvas.getContext('2d');
            this.points = [];
            this.maxPoints = 100;
            this.setupCanvas();
        }

        setupCanvas() {
            this.canvas.width = this.canvas.offsetWidth;
            this.canvas.height = this.canvas.offsetHeight;
            
            window.addEventListener('resize', () => {
                this.canvas.width = this.canvas.offsetWidth;
                this.canvas.height = this.canvas.offsetHeight;
            });
        }

        addDataPoint(value, maxValue = 100) {
            const normalized = (value / maxValue) * this.canvas.height;
            this.points.push({
                x: this.canvas.width,
                y: this.canvas.height - normalized,
                value: normalized
            });

            if (this.points.length > this.maxPoints) {
                this.points.shift();
            }

            // Shift all points left
            this.points.forEach(point => {
                point.x -= 5;
            });

            // Remove off-screen points
            this.points = this.points.filter(p => p.x > 0);

            this.draw();
        }

        draw() {
            // Clear canvas
            this.ctx.fillStyle = 'rgba(10, 14, 26, 0.9)';
            this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

            if (this.points.length < 2) return;

            // Draw gradient line
            const gradient = this.ctx.createLinearGradient(0, 0, 0, this.canvas.height);
            gradient.addColorStop(0, 'rgba(0, 240, 255, 0.8)');
            gradient.addColorStop(1, 'rgba(0, 240, 255, 0.2)');

            this.ctx.strokeStyle = gradient;
            this.ctx.lineWidth = 2;
            this.ctx.beginPath();

            this.points.forEach((point, index) => {
                if (index === 0) {
                    this.ctx.moveTo(point.x, point.y);
                } else {
                    this.ctx.lineTo(point.x, point.y);
                }
            });

            this.ctx.stroke();

            // Draw glow effect
            this.ctx.shadowColor = 'rgba(0, 240, 255, 0.5)';
            this.ctx.shadowBlur = 10;
            this.ctx.stroke();
            this.ctx.shadowBlur = 0;
        }
    }

    // Copy to clipboard utility
    function copyToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        } else {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            } finally {
                document.body.removeChild(textarea);
            }
        }
    }

    // Auto-refresh for scan results
    function setupAutoRefresh() {
        const refreshInterval = 30000; // 30 seconds
        let lastCheck = Date.now();

        document.querySelectorAll('[data-auto-refresh]').forEach(element => {
            const endpoint = element.dataset.autoRefresh;
            if (!endpoint) return;

            setInterval(async () => {
                try {
                    const response = await fetch(endpoint);
                    if (response.ok) {
                        const data = await response.json();
                        // Update element content
                        if (element.dataset.refreshProperty) {
                            element[element.dataset.refreshProperty] = data[element.dataset.refreshKey];
                        } else {
                            element.textContent = JSON.stringify(data, null, 2);
                        }
                    }
                } catch (error) {
                    console.error('Auto-refresh error:', error);
                }
            }, refreshInterval);
        });
    }

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize global instances
        window.toastManager = new ToastManager();
        window.realTimeUpdater = new RealTimeUpdater();
        
        // Setup form validation
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function(e) {
                if (!FormValidator.validate(this)) {
                    e.preventDefault();
                    window.toastManager.error('Please fill in all required fields correctly.');
                }
            });
        });

        // Add copy buttons to code blocks
        document.querySelectorAll('pre code, .result-pre').forEach(block => {
            const button = document.createElement('button');
            button.className = 'btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2';
            button.textContent = 'Copy';
            button.style.zIndex = '10';
            
            button.addEventListener('click', function() {
                const text = block.textContent;
                copyToClipboard(text).then(() => {
                    button.textContent = 'Copied!';
                    setTimeout(() => {
                        button.textContent = 'Copy';
                    }, 2000);
                }).catch(() => {
                    window.toastManager.error('Failed to copy to clipboard');
                });
            });

            const wrapper = document.createElement('div');
            wrapper.style.position = 'relative';
            block.parentNode.insertBefore(wrapper, block);
            wrapper.appendChild(block);
            wrapper.appendChild(button);
        });

        // Setup auto-refresh
        setupAutoRefresh();

        // Add loading states to buttons
        document.querySelectorAll('form button[type="submit"]').forEach(button => {
            button.addEventListener('click', function() {
                if (!this.form.checkValidity()) return;
                
                this.disabled = true;
                this.dataset.originalText = this.textContent;
                this.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
                
                // Re-enable if form submission fails
                setTimeout(() => {
                    this.disabled = false;
                    this.textContent = this.dataset.originalText || 'Submit';
                }, 10000);
            });
        });
    });

    // Export for global use
    window.CyberCheck = {
        ToastManager,
        RealTimeUpdater,
        FormValidator,
        LiveStatsUpdater,
        NetworkVisualizer,
        copyToClipboard
    };

})();

