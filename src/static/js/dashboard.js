/**
 * Spotify Auto-Discovery Bot Dashboard JavaScript
 * Sichere Client-Side Logik für das Dashboard
 * CWE-79: XSS Prevention durch HTML Escaping
 */

class SpotifyDashboard {
    constructor() {
        this.refreshInterval = null;
        this.activityChart = null;
        this.isInitialized = false;
        
        // Configuration
        this.config = {
            refreshIntervalMs: 30000,  // 30 seconds
            chartRefreshMs: 300000,    // 5 minutes
            timeUpdateMs: 1000         // 1 second
        };
        
        this.init();
    }
    
    init() {
        if (this.isInitialized) return;
        
        console.log('Initializing Spotify Dashboard...');
        
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupDashboard());
        } else {
            this.setupDashboard();
        }
        
        this.isInitialized = true;
    }
    
    setupDashboard() {
        try {
            // Load initial data
            this.loadActivityChart();
            
            // Setup auto-refresh
            this.startAutoRefresh();
            
            // Setup time updates
            this.startTimeUpdates();
            
            console.log('Dashboard initialized successfully');
            
        } catch (error) {
            console.error('Dashboard initialization failed:', error);
            this.showError('Dashboard konnte nicht initialisiert werden');
        }
    }
    
    // Utility Functions
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    formatTime(date) {
        return date.toLocaleTimeString('de-DE', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }
    
    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('de-DE', {
            month: 'short',
            day: 'numeric'
        });
    }
    
    // API Calls with Error Handling
    async fetchApi(endpoint, options = {}) {
        try {
            const response = await fetch(endpoint, {
                timeout: 10000,  // 10 second timeout
                ...options
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
            
        } catch (error) {
            console.error(`API call failed for ${endpoint}:`, error);
            throw error;
        }
    }
    
    // Chart Management
    async loadActivityChart() {
        try {
            const data = await this.fetchApi('/api/activity?days=30');
            
            if (!Array.isArray(data)) {
                throw new Error('Invalid activity data received');
            }
            
            this.renderActivityChart(data);
            
        } catch (error) {
            console.error('Failed to load activity chart:', error);
            this.showChartError();
        }
    }
    
    renderActivityChart(data) {
        const canvas = document.getElementById('activityChart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        
        // Prepare data (reverse to show chronological order)
        const labels = data.map(day => this.formatDate(day.date)).reverse();
        const tracksPlayed = data.map(day => Math.max(0, day.tracks_played || 0)).reverse();
        const tracksAdded = data.map(day => Math.max(0, day.tracks_added || 0)).reverse();
        
        // Destroy existing chart
        if (this.activityChart) {
            this.activityChart.destroy();
        }
        
        // Create new chart
        this.activityChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Songs gehört',
                    data: tracksPlayed,
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }, {
                    label: 'Songs hinzugefügt',
                    data: tracksAdded,
                    borderColor: '#1db954',
                    backgroundColor: 'rgba(29, 185, 84, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            padding: 20
                        }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        borderColor: '#1db954',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            callback: function(value) {
                                return Number.isInteger(value) ? value : '';
                            }
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        });
    }
    
    showChartError() {
        const canvas = document.getElementById('activityChart');
        if (!canvas) return;
        
        const container = canvas.parentElement;
        container.innerHTML = `
            <div class="text-center text-muted py-5">
                <i class="fas fa-chart-line fa-3x mb-3"></i>
                <p>Chart konnte nicht geladen werden</p>
                <button class="btn btn-outline-secondary btn-sm" onclick="dashboard.loadActivityChart()">
                    Erneut versuchen
                </button>
            </div>
        `;
    }
    
    // Statistics Updates
    async updateStatistics() {
        try {
            const data = await this.fetchApi('/api/statistics?days=7');
            
            // Update metric cards with validation
            this.updateElement('total-tracks', Math.max(0, data.total_tracks_played || 0));
            this.updateElement('added-tracks', Math.max(0, data.tracks_added_to_playlist || 0));
            this.updateElement('discovery-rate', (Math.max(0, data.discovery_rate || 0)).toFixed(1) + '%');
            this.updateElement('avg-duration', Math.round(Math.max(0, data.average_listening_duration_seconds || 0)) + 's');
            
            // Update top artists list
            this.updateTopArtists(data.top_artists || []);
            
        } catch (error) {
            console.error('Failed to update statistics:', error);
        }
    }
    
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }
    
    updateTopArtists(artists) {
        const container = document.getElementById('top-artists-list');
        if (!container) return;
        
        if (!Array.isArray(artists) || artists.length === 0) {
            container.innerHTML = '<p class="text-muted text-center">Noch keine Daten verfügbar</p>';
            return;
        }
        
        const html = artists.slice(0, 5).map(artist => {
            const name = this.escapeHtml(artist.artist_name || 'Unknown');
            const count = Math.max(0, artist.play_count || 0);
            
            return `
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="text-truncate" title="${name}">${name}</span>
                    <span class="badge bg-spotify rounded-pill">${count}</span>
                </div>
            `;
        }).join('');
        
        container.innerHTML = html;
    }
    
    // Status Updates
    async updateStatus() {
        try {
            const data = await this.fetchApi('/api/status');
            
            // Update listening duration if track is playing
            if (data.current_track && typeof data.current_track.listening_duration === 'number') {
                this.updateElement('listening-duration', Math.max(0, data.current_track.listening_duration));
            }
            
            // Update refresh indicator
            this.updateRefreshIndicator();
            
        } catch (error) {
            console.error('Failed to update status:', error);
        }
    }
    
    updateRefreshIndicator() {
        const indicator = document.getElementById('refresh-indicator');
        const lastUpdate = document.getElementById('last-update');
        
        if (indicator) {
            indicator.textContent = '🔄';
            indicator.classList.add('loading');
            setTimeout(() => indicator.classList.remove('loading'), 1000);
        }
        
        if (lastUpdate) {
            lastUpdate.textContent = this.formatTime(new Date());
        }
    }
    
    // Auto-refresh Management
    startAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        
        let chartRefreshCounter = 0;
        
        this.refreshInterval = setInterval(() => {
            this.updateStatistics();
            this.updateStatus();
            
            // Refresh chart every 5 minutes
            chartRefreshCounter++;
            if (chartRefreshCounter >= (this.config.chartRefreshMs / this.config.refreshIntervalMs)) {
                this.loadActivityChart();
                chartRefreshCounter = 0;
            }
            
        }, this.config.refreshIntervalMs);
        
        console.log(`Auto-refresh started (${this.config.refreshIntervalMs / 1000}s interval)`);
    }
    
    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
            console.log('Auto-refresh stopped');
        }
    }
    
    // Time Updates
    startTimeUpdates() {
        setInterval(() => {
            const timeElement = document.getElementById('current-time');
            if (timeElement) {
                timeElement.textContent = this.formatTime(new Date());
            }
        }, this.config.timeUpdateMs);
    }
    
    // Service Control
    async controlService(action) {
        const button = event.target;
        const originalText = button.innerHTML;
        
        try {
            // Update button state
            button.disabled = true;
            button.innerHTML = action === 'start' ? 'Startet...' : 'Stoppt...';
            
            const response = await this.fetchApi(`/service/${action}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (response.success) {
                // Show success message
                this.showNotification(response.message, 'success');
                
                // Reload page after short delay
                setTimeout(() => location.reload(), 1500);
            } else {
                this.showNotification('Fehler: ' + response.message, 'error');
                button.disabled = false;
                button.innerHTML = originalText;
            }
            
        } catch (error) {
            console.error('Service control error:', error);
            this.showNotification('Fehler beim ' + (action === 'start' ? 'Starten' : 'Stoppen') + ' des Services', 'error');
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }
    
    // UI Helpers
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type === 'error' ? 'danger' : 'success'} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        notification.innerHTML = `
            ${this.escapeHtml(message)}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
    
    showError(message) {
        this.showNotification(message, 'error');
    }
    
    // Cleanup
    destroy() {
        this.stopAutoRefresh();
        
        if (this.activityChart) {
            this.activityChart.destroy();
            this.activityChart = null;
        }
        
        console.log('Dashboard destroyed');
    }
}

// Global instance
let dashboard = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new SpotifyDashboard();
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (dashboard) {
        dashboard.destroy();
    }
});

// Global function for service control (called from HTML)
function controlService(action) {
    if (dashboard) {
        dashboard.controlService(action);
    }
}