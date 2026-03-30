import axios from 'axios';

const API = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('evoting_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Auto logout on 401
API.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('evoting_token');
      localStorage.removeItem('evoting_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default API;

// ── Auth ──────────────────────────────────────────────────────────────────────
export const authAPI = {
  register: (data) => API.post('/auth/register', data),
  login: (data) => API.post('/auth/login', data),
  getOTP: (userId) => API.get(`/auth/otp/${userId}`),
};

// ── Voter ─────────────────────────────────────────────────────────────────────
export const voterAPI = {
  getActiveElections: () => API.get('/voter/elections/active'),
  getBallot: (electionId) => API.get(`/voter/ballot/${electionId}`),
  castVote: (data) => API.post('/voter/cast', data),
  getStatus: () => API.get('/voter/status'),
};

// ── Admin ─────────────────────────────────────────────────────────────────────
export const adminAPI = {
  getDashboard: () => API.get('/admin/dashboard'),
  getElections: () => API.get('/admin/elections'),
  createElection: (data) => API.post('/admin/election', data),
  activateElection: (id) => API.patch(`/admin/election/${id}/activate`),
  closeElection: (id) => API.patch(`/admin/election/${id}/close`),
  getCandidates: (electionId) => API.get(`/admin/candidates/${electionId}`),
  addCandidate: (data) => API.post('/admin/candidate', data),
  deleteCandidate: (id) => API.delete(`/admin/candidate/${id}`),
  getVoters: () => API.get('/admin/voters'),
  getResults: (electionId) => API.post(`/admin/results/${electionId}`),
  getAuditLogs: (flaggedOnly = false) => API.get(`/admin/audit-logs?flagged_only=${flaggedOnly}`),
  createAdmin: (data) => API.post('/admin/voter/create-admin', data),
};
