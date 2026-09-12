/**
 * Centralized API client for the frontend.
 */

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function fetchApi(endpoint, options = {}) {
  try {
    const response = await fetch(endpoint, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new ApiError(`API Error: ${response.statusText}`, response.status);
    }

    if (response.status === 204) return null;

    return await response.json();
  } catch (error) {
    console.error(`[API Fetch Failed] ${endpoint}:`, error);
    throw error;
  }
}

export const api = {
  getDashboardSummary: () => fetchApi('/api/dashboard/summary'),
  getEmails: (limit = 50) => fetchApi(`/api/emails?limit=${limit}`),
  syncGmail: (emailAccountId, limit = 50) => fetchApi(`/api/gmail/${emailAccountId}/messages?limit=${limit}`),
  uploadEmail: async (file) => {
    const formData = new FormData();
    formData.append("file", file);
    
    try {
      const response = await fetch('/api/emails/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new ApiError(`API Error: ${response.statusText}`, response.status);
      }

      return await response.json();
    } catch (error) {
      console.error(`[API Fetch Failed] /api/emails/upload`);
      throw new Error("Failed to upload email. Please try again.", { cause: error });
    }
  },
};
