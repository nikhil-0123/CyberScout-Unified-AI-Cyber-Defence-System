import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Helper to extract CSRF token cookie if set
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
    },
    // CRITICAL: withCredentials ensures HTTP-only cookies flow across Cloudflare Pages and Render API
    withCredentials: true,
});

// Attach Authorization Bearer token and CSRF token automatically
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('cyberscout_access_token') || localStorage.getItem('phishguard_access_token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    const csrfToken = getCookie('cyberscout_csrf_token') || sessionStorage.getItem('cyberscout_csrf_token');
    if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
}, (error) => Promise.reject(error));

// Response interceptor: automatically handles silent token refresh via HTTP-only cookie
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
    failedQueue.forEach(prom => {
        if (error) {
            prom.reject(error);
        } else {
            prom.resolve(token);
        }
    });
    failedQueue = [];
};

api.interceptors.response.use(
    (response) => {
        // Store CSRF token if returned in response
        if (response.data && response.data.csrf_token) {
            sessionStorage.setItem('cyberscout_csrf_token', response.data.csrf_token);
        }
        return response;
    },
    async (error) => {
        const originalRequest = error.config;

        if (error.response && error.response.status === 401 && !originalRequest._retry) {
            // Do not retry refresh for auth endpoints themselves
            if (originalRequest.url.includes('/api/auth/')) {
                return Promise.reject(error);
            }

            if (isRefreshing) {
                return new Promise((resolve, reject) => {
                    failedQueue.push({ resolve, reject });
                }).then((token) => {
                    originalRequest.headers.Authorization = `Bearer ${token}`;
                    return api(originalRequest);
                }).catch((err) => Promise.reject(err));
            }

            originalRequest._retry = true;
            isRefreshing = true;

            try {
                // Call refresh endpoint - HTTP-only cookie is passed automatically by browser
                const res = await api.post('/api/auth/refresh');
                const { access_token } = res.data;

                localStorage.setItem('cyberscout_access_token', access_token);
                localStorage.setItem('phishguard_access_token', access_token);

                api.defaults.headers.common.Authorization = `Bearer ${access_token}`;
                processQueue(null, access_token);

                originalRequest.headers.Authorization = `Bearer ${access_token}`;
                return api(originalRequest);
            } catch (refreshErr) {
                processQueue(refreshErr, null);
                // Clear state on revoked or expired session
                localStorage.removeItem('cyberscout_access_token');
                localStorage.removeItem('cyberscout_currentUser');
                localStorage.removeItem('phishguard_access_token');
                localStorage.removeItem('phishguard_currentUser');
                sessionStorage.removeItem('cyberscout_csrf_token');

                if (window.location.pathname.startsWith('/dashboard')) {
                    window.location.href = '/login';
                }
                return Promise.reject(refreshErr);
            } finally {
                isRefreshing = false;
            }
        }

        return Promise.reject(error);
    }
);

// Security & Authentication API (Phase 2)
export const registerUser = (name, email, password) => api.post('/api/auth/register', { name, email, password });
export const loginUser = (email, password) => api.post('/api/auth/login', { email, password });
export const getCurrentUser = () => api.get('/api/auth/me');
export const refreshAuthToken = () => api.post('/api/auth/refresh');
export const logoutUser = async () => {
    try {
        await api.post('/api/auth/logout');
    } catch (e) {
        // Continue clearing client storage regardless of network result
    } finally {
        localStorage.removeItem('cyberscout_access_token');
        localStorage.removeItem('cyberscout_refresh_token');
        localStorage.removeItem('cyberscout_currentUser');
        localStorage.removeItem('phishguard_access_token');
        localStorage.removeItem('phishguard_refresh_token');
        localStorage.removeItem('phishguard_currentUser');
        sessionStorage.removeItem('cyberscout_csrf_token');
    }
};

// URL & Forensic Analysis API
export const fetchUrlHtml = (url) => api.post('/api/fetch-url', { url });
export const extractUrlSignals = (url, html) => api.post('/api/extract-url-signals', { url, html });
export const analyzeUrl = (url, html, user_id) => api.post('/api/analyze-url', { url, html, user_id });

// Email Phishing Analysis API
export const extractEmailSignals = (email_text) => api.post('/api/extract-email-signals', { email_text });
export const analyzeEmail = (email_text, user_id) => api.post('/api/analyze-email', { email_text, user_id });
export const fetchDashboardStats = (user_id) => api.get('/api/dashboard-stats', { params: user_id ? { user_id } : {} });

// Blocklist Management
export const fetchBlocklist = () => api.get('/api/blocklist');
export const markUrlSafe = (url) => api.post(`/api/mark-safe?url=${encodeURIComponent(url)}`);
export const removeFromBlocklist = (url) => api.delete(`/api/blocklist?url=${encodeURIComponent(url)}`);
export const fetchDomTree = (url, html) => api.post('/api/fetch-dom-tree', { url, html });

export default api;
