// API Utility Functions

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

async function fetchApi(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('email_account_id');
      window.location.href = '/login';
      return null;
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Request failed with status ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error(`API Error (${endpoint}):`, error);
    throw error;
  }
}

export const api = {
  globalSearch: async (query) => {
    if (!query || query.trim() === '') return { emails: [], iocs: [], threats: [] };
    return fetchApi(`/api/search?q=${encodeURIComponent(query)}`);
  },
  getDashboardSummary: () => fetchApi('/api/dashboard/summary'),
  
  getEmails: (limit = 50, search = "") => fetchApi(`/api/emails?limit=${limit}${search ? `&search=${encodeURIComponent(search)}` : ''}`),
  getEmail: (id) => fetchApi(`/api/emails/${id}`),
  
  getEmailReport: (id) => fetchApi(`/api/emails/${id}/report`),
  

  getNotifications: (limit = 20) => fetchApi(`/api/notifications?limit=${limit}`),
  getSettingsInfo: () => fetchApi('/api/settings/info'),

  getThreats: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.risk_level) params.append('risk_level', filters.risk_level);
    if (filters.classification) params.append('classification', filters.classification);
    if (filters.search) params.append('search', filters.search);
    const qs = params.toString();
    return fetchApi(`/api/threats${qs ? `?${qs}` : ''}`);
  },
  
  getIocs: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.ioc_type) params.append('ioc_type', filters.ioc_type);
    if (filters.verdict) params.append('verdict', filters.verdict);
    if (filters.search) params.append('search', filters.search);
    const qs = params.toString();
    return fetchApi(`/api/iocs${qs ? `?${qs}` : ''}`);
  },
  
  syncGmail: (emailAccountId, limit = 50) => 
    fetchApi(`/api/gmail/${emailAccountId}/messages?limit=${limit}`, { method: 'POST' }),
    
  getSyncStatus: (emailAccountId) =>
    fetchApi(`/api/gmail/${emailAccountId}/sync-status`),

    
  uploadEmail: async (file, emailAccountId = null) => {
    const formData = new FormData();
    formData.append("file", file);
    if (emailAccountId) {
      formData.append("email_account_id", emailAccountId);
    }
    
    const token = localStorage.getItem('token');
    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const response = await fetch('/api/emails/upload', {
        method: 'POST',
        body: formData,
        headers, // No Content-Type header needed for FormData (browser sets it with boundary)
      });

      if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('email_account_id');
        window.location.href = '/login';
        return null;
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Upload failed with status ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Upload Error:', error);
      throw error;
    }
  }
};
