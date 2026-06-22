/**
 * Nakul Dashboard — Core JavaScript
 * ====================================
 * Handles real-time updates, API calls, chart rendering,
 * and interactive UI behavior.
 */

const Nakul = {
  // Configuration
  API_BASE: '/api',
  SSE_URL: '/api/stream',
  REFRESH_INTERVAL: 15000, // 15 seconds

  // State
  eventSource: null,
  charts: {},
  refreshTimer: null,

  /**
   * Initialize the dashboard
   */
  init() {
    this.setupNavigation();
    this.setupSSE();
    this.startAutoRefresh();
    this.setupEventListeners();
    console.log('🛡️ Nakul Dashboard initialized');
  },

  /**
   * Navigation highlighting
   */
  setupNavigation() {
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-item').forEach(item => {
      const href = item.getAttribute('href');
      if (href === currentPath || (currentPath === '/' && href === '/')) {
        item.classList.add('active');
      }
    });
  },

  /**
   * Server-Sent Events for real-time updates
   */
  setupSSE() {
    if (typeof EventSource === 'undefined') return;

    try {
      this.eventSource = new EventSource(this.SSE_URL);

      this.eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.updateDashboard(data);
        } catch (e) {
          console.warn('SSE parse error:', e);
        }
      };

      this.eventSource.onerror = () => {
        console.warn('SSE connection lost, will reconnect...');
        setTimeout(() => this.setupSSE(), 5000);
      };
    } catch (e) {
      console.warn('SSE not available:', e);
    }
  },

  /**
   * Auto-refresh fallback
   */
  startAutoRefresh() {
    this.refreshTimer = setInterval(() => {
      this.fetchSummary();
    }, this.REFRESH_INTERVAL);
  },

  /**
   * Event listeners
   */
  setupEventListeners() {
    // Alert acknowledge buttons
    document.querySelectorAll('[data-action="acknowledge"]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const alertId = e.target.dataset.alertId;
        this.acknowledgeAlert(alertId);
      });
    });

    // Incident state buttons
    document.querySelectorAll('[data-action="update-state"]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const incidentId = e.target.dataset.incidentId;
        const newState = e.target.dataset.state;
        this.updateIncidentState(incidentId, newState);
      });
    });

    // Logout
    document.querySelectorAll('[data-action="logout"]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        this.logout();
      });
    });

    // Mobile sidebar toggle
    const menuToggle = document.getElementById('menu-toggle');
    if (menuToggle) {
      menuToggle.addEventListener('click', () => {
        document.querySelector('.sidebar').classList.toggle('open');
      });
    }

    // Log filter form
    const logFilter = document.getElementById('log-filter-form');
    if (logFilter) {
      logFilter.addEventListener('submit', (e) => {
        e.preventDefault();
        this.fetchFilteredLogs();
      });
    }
  },

  /**
   * Update dashboard elements with new data
   */
  updateDashboard(data) {
    // Update health indicator
    const healthEl = document.getElementById('server-health');
    if (healthEl && data.server_health) {
      healthEl.className = `health-indicator ${data.server_health}`;
      healthEl.querySelector('.health-text').textContent = data.server_health.charAt(0).toUpperCase() + data.server_health.slice(1);
    }

    // Update stat values
    if (data.system) {
      this.updateElement('cpu-value', `${(data.system.cpu_percent || 0).toFixed(1)}%`);
      this.updateElement('memory-value', `${(data.system.memory_percent || 0).toFixed(1)}%`);
      this.updateElement('disk-value', `${(data.system.disk_percent || 0).toFixed(1)}%`);
      this.updateElement('load-value', `${(data.system.load_1 || 0).toFixed(2)}`);

      // Update progress bars
      this.updateProgress('cpu-progress', data.system.cpu_percent || 0);
      this.updateProgress('memory-progress', data.system.memory_percent || 0);
      this.updateProgress('disk-progress', data.system.disk_percent || 0);
    }

    // Update alert counts
    if (data.alerts) {
      this.updateElement('alerts-critical', data.alerts.critical || 0);
      this.updateElement('alerts-warning', data.alerts.warning || 0);
      this.updateElement('alerts-total', data.alerts.total || 0);
      this.updateElement('alerts-unack', data.alerts.unacknowledged || 0);

      // Update nav badge
      const navBadge = document.getElementById('alerts-nav-badge');
      if (navBadge) {
        const count = data.alerts.unacknowledged || 0;
        navBadge.textContent = count;
        navBadge.style.display = count > 0 ? 'inline' : 'none';
      }
    }

    // Update events count
    if (data.events_last_hour !== undefined) {
      this.updateElement('events-count', data.events_last_hour);
    }

    // Update active incidents
    if (data.incidents) {
      this.updateElement('active-incidents', data.incidents.active || 0);
    }
  },

  /**
   * Safely update element text
   */
  updateElement(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  },

  /**
   * Update progress bar
   */
  updateProgress(id, percent) {
    const el = document.getElementById(id);
    if (!el) return;

    const fill = el.querySelector('.progress-fill') || el;
    fill.style.width = `${Math.min(100, percent)}%`;

    // Update color class
    fill.classList.remove('success', 'warning', 'danger');
    if (percent >= 90) fill.classList.add('danger');
    else if (percent >= 75) fill.classList.add('warning');
    else fill.classList.add('success');
  },

  /**
   * API Calls
   */
  async fetchSummary() {
    try {
      const response = await fetch(`${this.API_BASE}/summary`);
      if (response.ok) {
        const data = await response.json();
        this.updateDashboard(data);
      }
    } catch (e) {
      console.warn('Failed to fetch summary:', e);
    }
  },

  async acknowledgeAlert(alertId) {
    try {
      const response = await fetch(`${this.API_BASE}/alerts/${alertId}/acknowledge`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
      });
      if (response.ok) {
        const btn = document.querySelector(`[data-alert-id="${alertId}"]`);
        if (btn) {
          btn.textContent = '✓ Acknowledged';
          btn.disabled = true;
          btn.classList.add('success');
        }
      }
    } catch (e) {
      console.error('Failed to acknowledge alert:', e);
    }
  },

  async updateIncidentState(incidentId, newState) {
    const notes = prompt('Add notes (optional):') || '';
    const formData = new FormData();
    formData.append('new_state', newState);
    formData.append('notes', notes);

    try {
      const response = await fetch(`${this.API_BASE}/incidents/${incidentId}/state`, {
        method: 'PUT',
        body: formData,
      });
      if (response.ok) {
        location.reload();
      }
    } catch (e) {
      console.error('Failed to update incident:', e);
    }
  },

  async fetchFilteredLogs() {
    const form = document.getElementById('log-filter-form');
    if (!form) return;

    const formData = new FormData(form);
    const params = new URLSearchParams();

    for (const [key, value] of formData.entries()) {
      if (value) params.append(key, value);
    }

    try {
      const response = await fetch(`${this.API_BASE}/events?${params.toString()}`);
      if (response.ok) {
        const data = await response.json();
        this.renderLogTable(data.events);
      }
    } catch (e) {
      console.error('Failed to fetch logs:', e);
    }
  },

  renderLogTable(events) {
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;

    if (!events || events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="empty-icon">📋</div><h3>No events found</h3></td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td class="mono" style="font-size:0.75rem;">${(e.timestamp || '').substring(0, 19)}</td>
        <td><span class="badge ${e.severity}">${e.severity}</span></td>
        <td>${e.source || '—'}</td>
        <td>${e.category || '—'}</td>
        <td class="truncate" style="max-width:300px;" title="${this.escapeHtml(e.message || '')}">${this.escapeHtml((e.message || '').substring(0, 100))}</td>
        <td>${e.account || '—'}</td>
        <td>${e.ip_address || '—'}</td>
      </tr>
    `).join('');
  },

  async logout() {
    try {
      await fetch(`${this.API_BASE}/logout`, { method: 'POST' });
    } catch (e) { /* ignore */ }
    document.cookie = 'nakul_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    window.location.href = '/login';
  },

  /**
   * Initialize Chart.js charts
   */
  initResourceCharts(snapshots) {
    if (typeof Chart === 'undefined' || !snapshots || snapshots.length === 0) return;

    const labels = snapshots.map(s => (s.timestamp || '').substring(11, 16)).reverse();
    const cpuData = snapshots.map(s => s.cpu_percent || 0).reverse();
    const memData = snapshots.map(s => s.memory_percent || 0).reverse();
    const loadData = snapshots.map(s => s.load_1 || 0).reverse();

    const chartOptions = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: {
          ticks: { color: '#64748b', font: { size: 10 } },
          grid: { color: 'rgba(148,163,184,0.06)' },
        },
        y: {
          ticks: { color: '#64748b', font: { size: 10 } },
          grid: { color: 'rgba(148,163,184,0.06)' },
          beginAtZero: true,
        },
      },
      elements: {
        point: { radius: 0, hoverRadius: 4 },
        line: { tension: 0.4, borderWidth: 2 },
      },
    };

    // CPU Chart
    const cpuCanvas = document.getElementById('cpu-chart');
    if (cpuCanvas) {
      this.charts.cpu = new Chart(cpuCanvas, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            data: cpuData,
            borderColor: '#06b6d4',
            backgroundColor: 'rgba(6, 182, 212, 0.08)',
            fill: true,
          }],
        },
        options: { ...chartOptions, scales: { ...chartOptions.scales, y: { ...chartOptions.scales.y, max: 100 } } },
      });
    }

    // Memory Chart
    const memCanvas = document.getElementById('memory-chart');
    if (memCanvas) {
      this.charts.memory = new Chart(memCanvas, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            data: memData,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.08)',
            fill: true,
          }],
        },
        options: { ...chartOptions, scales: { ...chartOptions.scales, y: { ...chartOptions.scales.y, max: 100 } } },
      });
    }

    // Load Chart
    const loadCanvas = document.getElementById('load-chart');
    if (loadCanvas) {
      this.charts.load = new Chart(loadCanvas, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            data: loadData,
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.08)',
            fill: true,
          }],
        },
        options: chartOptions,
      });
    }
  },

  /**
   * Update existing charts with new data
   */
  updateResourceCharts(snapshots) {
    if (!snapshots || snapshots.length === 0) return;

    const labels = snapshots.map(s => {
      // If we are showing days, adjust label format. But for simplicity, just use substring
      return (s.timestamp || '').substring(11, 16);
    });
    const cpuData = snapshots.map(s => s.cpu_percent || 0);
    const memData = snapshots.map(s => s.memory_percent || 0);
    const loadData = snapshots.map(s => s.load_1 || 0);

    if (this.charts.cpu) {
      this.charts.cpu.data.labels = labels;
      this.charts.cpu.data.datasets[0].data = cpuData;
      this.charts.cpu.update();
    }
    if (this.charts.memory) {
      this.charts.memory.data.labels = labels;
      this.charts.memory.data.datasets[0].data = memData;
      this.charts.memory.update();
    }
    if (this.charts.load) {
      this.charts.load.data.labels = labels;
      this.charts.load.data.datasets[0].data = loadData;
      this.charts.load.update();
    }
  },

  /**
   * Utility: HTML escape
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  /**
   * Format relative time
   */
  timeAgo(timestamp) {
    if (!timestamp) return 'N/A';
    const now = new Date();
    const then = new Date(timestamp);
    const diff = Math.floor((now - then) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  },
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => Nakul.init());
