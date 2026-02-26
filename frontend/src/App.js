import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { ToastContainer, toast } from 'react-toastify';
import '@stripe/stripe-js';

axios.defaults.baseURL = '/api';

// Helper function to format date/time in 12-hour format
const formatDateTime = (dateString) => {
  if (!dateString) return '';
  const date = new Date(dateString);
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });
};

function App() {
  const [currentPage, setCurrentPage] = useState('login');
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({ storageUsed: 0, storageLimit: null, isPremium: false });
  const [currentVault, setCurrentVault] = useState(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const token = localStorage.getItem('token');
        if (token) {
          axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
          const response = await axios.get('/auth/me');
          setUser(response.data);
          setCurrentPage('dashboard');

          const statsResponse = await axios.get('/user/stats');
          setStats(statsResponse.data);
        }
      } catch (error) {
        localStorage.removeItem('token');
        delete axios.defaults.headers.common['Authorization'];
        setUser(null);
      }
    };

    checkAuth();
  }, []);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('premium') === 'success') {
      const fetchUser = async () => {
        try {
          const response = await axios.get('/auth/me');
          setUser(response.data);

          const statsResponse = await axios.get('/user/stats');
          setStats(statsResponse.data);

          toast.success('🎉 Premium upgrade successful!');
          window.history.replaceState({}, document.title, window.location.pathname);
        } catch (error) {
          console.error('Failed to refresh user data');
        }
      };

      fetchUser();
    }
  }, []);

  const handleLogin = async (email, password) => {
    setLoading(true);
    try {
      const response = await axios.post('/auth/login', { email, password });
      localStorage.setItem('token', response.data.token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      setUser(response.data.user);
      setCurrentPage('dashboard');

      const statsResponse = await axios.get('/user/stats');
      setStats(statsResponse.data);

      toast.success('Welcome back!');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (email, password, firstName, lastName) => {
    setLoading(true);
    try {
      const response = await axios.post('/auth/register', {
        email,
        password,
        firstName,
        lastName
      });
      localStorage.setItem('token', response.data.token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      setUser(response.data.user);
      setCurrentPage('dashboard');

      const statsResponse = await axios.get('/user/stats');
      setStats(statsResponse.data);

      toast.success('Account created successfully!');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    setCurrentPage('login');
    toast.info('Logged out successfully');
  };

  const handleUpgrade = async () => {
    try {
      const response = await axios.post('/stripe/create-checkout-session');
      window.location.href = response.data.url;
    } catch (error) {
      toast.error(error.response?.data?.error || 'Upgrade failed');
    }
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'login':
        return <LoginPage onLogin={handleLogin} onSwitchToRegister={() => setCurrentPage('register')} loading={loading} />;
      case 'register':
        return <RegisterPage onRegister={handleRegister} onSwitchToLogin={() => setCurrentPage('login')} loading={loading} />;
      case 'dashboard':
        return <DashboardPage
          user={user}
          onLogout={handleLogout}
          stats={stats}
          onNavigate={setCurrentPage}
          setCurrentVault={setCurrentVault}
        />;
      case 'createVault':
        return <CreateVaultPage
          user={user}
          onBack={() => setCurrentPage('dashboard')}
          stats={stats}
        />;
      case 'vaultDetail':
        return <VaultDetailPage
          vault={currentVault}
          onBack={() => {
            setCurrentVault(null);
            setCurrentPage('dashboard');
          }}
          user={user}
        />;
      case 'premium':
        return <PremiumPage
          onUpgrade={handleUpgrade}
          onBack={() => setCurrentPage('dashboard')}
          isPremium={stats.isPremium}
        />;
      case 'admin':
        return <AdminPage
          onBack={() => setCurrentPage('dashboard')}
        />;
      default:
        return <LoginPage onLogin={handleLogin} onSwitchToRegister={() => setCurrentPage('register')} loading={loading} />;
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <AnimatePresence mode="wait">
        <motion.div
          key={currentPage}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.3 }}
          className="w-full max-w-4xl"
        >
          {renderPage()}
        </motion.div>
      </AnimatePresence>
      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
    </div>
  );
}

// Login Page Component
function LoginPage({ onLogin, onSwitchToRegister, loading }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    onLogin(email, password);
  };

  return (
    <div className="glass-card">
      <div className="flex flex-col items-center mb-8">
        <div className="w-24 h-24 rounded-full bg-gradient-to-r from-primary-500 to-secondary-500 flex items-center justify-center mb-4">
          <span className="text-4xl">⏰</span>
        </div>
        <h1 className="text-3xl font-bold">ChronoVault</h1>
        <p className="text-gray-300 mt-2">Secure time-locked digital vault</p>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label htmlFor="email" className="block text-sm font-medium mb-2">Email</label>
          <input
            type="email"
            id="email"
            className="input-field"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>

        <div className="mb-6">
          <label htmlFor="password" className="block text-sm font-medium mb-2">Password</label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              id="password"
              className="input-field pr-10"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button
              type="button"
              className="absolute inset-y-0 right-0 pr-3 flex items-center"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-400" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                  <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
                </svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" clipRule="evenodd" />
                  <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
                </svg>
              )}
            </button>
          </div>
        </div>

        <button
          type="submit"
          className="btn-primary w-full py-3"
          disabled={loading}
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>

        <div className="mt-4 text-center">
          <button
            type="button"
            className="text-primary-400 hover:text-primary-300 text-sm"
            onClick={onSwitchToRegister}
          >
            Don't have an account? Sign up
          </button>
        </div>
      </form>
    </div>
  );
}

// Register Page Component
function RegisterPage({ onRegister, onSwitchToLogin, loading }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    onRegister(email, password, firstName, lastName);
  };

  return (
    <div className="glass-card">
      <div className="flex flex-col items-center mb-8">
        <div className="w-24 h-24 rounded-full bg-gradient-to-r from-primary-500 to-secondary-500 flex items-center justify-center mb-4">
          <span className="text-4xl">⏰</span>
        </div>
        <h1 className="text-3xl font-bold">Create Account</h1>
        <p className="text-gray-300 mt-2">Join ChronoVault today</p>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label htmlFor="firstName" className="block text-sm font-medium mb-2">First Name</label>
            <input
              type="text"
              id="firstName"
              className="input-field"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              required
            />
          </div>
          <div>
            <label htmlFor="lastName" className="block text-sm font-medium mb-2">Last Name</label>
            <input
              type="text"
              id="lastName"
              className="input-field"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="mb-4">
          <label htmlFor="email" className="block text-sm font-medium mb-2">Email</label>
          <input
            type="email"
            id="email"
            className="input-field"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>

        <div className="mb-6">
          <label htmlFor="password" className="block text-sm font-medium mb-2">Password</label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              id="password"
              className="input-field pr-10"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button
              type="button"
              className="absolute inset-y-0 right-0 pr-3 flex items-center"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-400" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                  <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
                </svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" clipRule="evenodd" />
                  <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
                </svg>
              )}
            </button>
          </div>
        </div>

        <button
          type="submit"
          className="btn-primary w-full py-3"
          disabled={loading}
        >
          {loading ? 'Creating account...' : 'Create Account'}
        </button>

        <div className="mt-4 text-center">
          <button
            type="button"
            className="text-primary-400 hover:text-primary-300 text-sm"
            onClick={onSwitchToLogin}
          >
            Already have an account? Sign in
          </button>
        </div>
      </form>
    </div>
  );
}

// Dashboard Page Component
function DashboardPage({ user, onLogout, stats, onNavigate, setCurrentVault }) {
  const [vaults, setVaults] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchVaults = async () => {
      try {
        const response = await axios.get('/vaults');
        setVaults(response.data);
      } catch (error) {
        toast.error('Failed to fetch vaults');
      } finally {
        setLoading(false);
      }
    };

    fetchVaults();
  }, []);

  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  const storagePercentage = stats.storageLimit
    ? Math.min(100, (stats.storageUsed / stats.storageLimit) * 100)
    : 0;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Welcome back, {user.first_name}!</h1>
          <p className="text-gray-300">Manage your secure time-locked vaults</p>
        </div>
        <div className="flex space-x-3">
          {!stats.isPremium && (
            <button
              onClick={() => onNavigate('premium')}
              className="btn-outline"
            >
              Upgrade to Premium
            </button>
          )}
          {user.role === 'admin' && (
            <button
              onClick={() => onNavigate('admin')}
              className="btn-outline bg-blue-600 hover:bg-blue-700 text-white"
            >
              Admin Dashboard
            </button>
          )}
          <button
            onClick={onLogout}
            className="btn-outline"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-card">
          <h3 className="text-lg font-semibold mb-2">Storage Used</h3>
          <div className="text-2xl font-bold">
            {formatBytes(stats.storageUsed)}
            {stats.storageLimit && ` / ${formatBytes(stats.storageLimit)}`}
          </div>
          {stats.storageLimit && (
            <div className="mt-3 w-full bg-gray-700 rounded-full h-2.5">
              <div
                className="bg-gradient-to-r from-primary-500 to-secondary-500 h-2.5 rounded-full"
                style={{ width: `${storagePercentage}%` }}
              ></div>
            </div>
          )}
        </div>

        <div className="glass-card">
          <h3 className="text-lg font-semibold mb-2">Vaults</h3>
          <div className="text-2xl font-bold">{vaults.length}</div>
          <div className="mt-2 text-sm text-gray-400">
            {stats.isPremium ? 'Unlimited' : '3 per week'}
          </div>
        </div>

        <div className="glass-card">
          <h3 className="text-lg font-semibold mb-2">Account Status</h3>
          <div className={`status-badge ${stats.isPremium ? 'status-premium' : 'bg-gray-500/20 text-gray-400'}`}>
            {stats.isPremium ? 'Premium' : 'Free'}
          </div>
          {!stats.isPremium && (
            <button
              onClick={() => onNavigate('premium')}
              className="btn-primary mt-3 w-full"
            >
              Upgrade Now
            </button>
          )}
        </div>
      </div>

      {/* Vault Actions */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Your Vaults</h2>
        <button
          onClick={() => onNavigate('createVault')}
          className="btn-primary"
        >
          Create New Vault
        </button>
      </div>

      {/* Vaults Grid */}
      {loading ? (
        <div className="glass-card text-center py-12">
          Loading your vaults...
        </div>
      ) : vaults.length === 0 ? (
        <div className="glass-card text-center py-12">
          <p className="text-gray-400">You don't have any vaults yet.</p>
          <button
            onClick={() => onNavigate('createVault')}
            className="btn-primary mt-4"
          >
            Create Your First Vault
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {vaults.map(vault => {
            const isLocked = vault.unlock_time && new Date(vault.unlock_time) > new Date();
            const totalSize = vault.total_size ? formatBytes(vault.total_size) : '0 Bytes';

            return (
              <div
                key={vault.id}
                className="glass-card hover:bg-white/15 transition cursor-pointer"
                onClick={() => {
                  axios.get(`/vaults/${vault.id}`)
                    .then(response => {
                      setCurrentVault(response.data);
                      onNavigate('vaultDetail');
                    })
                    .catch(error => {
                      console.error('Vault fetch error:', error);
                      toast.error('Failed to load vault details');
                    });
                }}
              >
                <div className="flex justify-between items-start">
                  <h3 className="text-xl font-bold truncate">{vault.name}</h3>
                  <span className={`status-badge ${isLocked ? 'status-locked' : 'status-unlocked'}`}>
                    {isLocked ? 'Locked' : 'Unlocked'}
                  </span>
                </div>
                <p className="text-gray-300 mt-2 line-clamp-2">{vault.description || 'No description'}</p>

                {/* Encryption details */}
                <div className="mt-2 text-xs text-gray-400 space-y-1">
                  <div>🔒 <span className="text-primary-300">AES-256-GCM</span></div>
                  {vault.required_sigs > 1 && (
                    <div>👥 <span className="text-primary-300">{vault.required_sigs} of {vault.trustee_count || 5}</span></div>
                  )}
                </div>

                <div className="mt-3 flex justify-between text-sm">
                  <span>{vault.file_count} file{vault.file_count !== 1 ? 's' : ''}</span>
                  <span>{totalSize}</span>
                </div>
                {vault.unlock_time && (
                  <div className="mt-2 text-xs text-yellow-400">
                    ⏰ Unlocks: {formatDateTime(vault.unlock_time)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// Create Vault Page Component (Part 1 - Due to length, splitting into two parts)
// Create Vault Page Component
function CreateVaultPage({ user, onBack, stats }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [unlockTime, setUnlockTime] = useState('');
  const [requiredSigs, setRequiredSigs] = useState(1);
  const [files, setFiles] = useState([]);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [trusteeEmails, setTrusteeEmails] = useState(['', '', '', '', '']);

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFiles([...files, ...Array.from(e.dataTransfer.files)]);
    }
  };

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFiles([...files, ...Array.from(e.target.files)]);
    }
  };

  const removeFile = (index) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name || files.length === 0) {
      toast.error('Please provide a name and at least one file');
      return;
    }

    // Check storage limit
    const totalFileSize = files.reduce((sum, file) => sum + file.size, 0);
    if (!stats.isPremium && stats.storageUsed + totalFileSize > 21474836480) {
      toast.error('Free accounts are limited to 20GB total storage');
      return;
    }

    setUploading(true);

    const formData = new FormData();
    formData.append('name', name);
    formData.append('description', description);

    if (unlockTime) {
      formData.append('unlockTime', unlockTime);
    }

    formData.append('required_sigs', requiredSigs);
    formData.append('trusteeEmails', JSON.stringify(trusteeEmails.filter(e => e.trim() !== '')));

    files.forEach(file => {
      formData.append('files', file);
    });

    try {
      await axios.post('/vaults/create', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });

      const trusteeCount = trusteeEmails.filter(e => e.trim() !== '').length;
      toast.success(`Vault created successfully! ${requiredSigs > 1 ? `${trusteeCount} trustee(s) will receive their shares via email.` : ''}`);
      onBack();
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to create vault');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Create New Vault</h1>
        <button
          onClick={onBack}
          className="btn-outline"
        >
          Back to Dashboard
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="glass-card">
          <h2 className="text-xl font-semibold mb-4">Vault Details</h2>

          <div className="mb-4">
            <label htmlFor="name" className="block text-sm font-medium mb-2">Vault Name *</label>
            <input
              type="text"
              id="name"
              className="input-field"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div className="mb-4">
            <label htmlFor="description" className="block text-sm font-medium mb-2">Description</label>
            <textarea
              id="description"
              className="input-field"
              rows="3"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            ></textarea>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="unlockTime" className="block text-sm font-medium mb-2">Unlock Time (Optional)</label>
              <input
                type="datetime-local"
                id="unlockTime"
                className="input-field"
                value={unlockTime}
                onChange={(e) => setUnlockTime(e.target.value)}
              />
              <p className="text-xs text-gray-400 mt-1">
                Files will be automatically unlocked at this time
              </p>
            </div>

            <div>
              <label htmlFor="requiredSigs" className="block text-sm font-medium mb-2">
                Security Level
              </label>
              <select
                id="requiredSigs"
                className="input-field"
                value={requiredSigs}
                onChange={(e) => setRequiredSigs(parseInt(e.target.value))}
                style={{ color: '#ffffff', backgroundColor: 'rgba(255, 255, 255, 0.1)' }}
              >
                <option value="1" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Standard (Single Key)</option>
                <option value="2" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Enhanced (2 of 5 Trustees)</option>
                <option value="3" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Military Grade (3 of 5 Trustees)</option>
                <option value="4" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Maximum Security (4 of 5 Trustees)</option>
                <option value="5" style={{ backgroundColor: '#1f2937', color: '#ffffff' }}>Ultimate Security (5 of 5 Trustees)</option>
              </select>
              <p className="text-xs text-gray-400 mt-1">
                {requiredSigs > 1
                  ? `Requires ${requiredSigs} trustees to unlock early`
                  : 'No multi-signature required'}
              </p>
            </div>
          </div>
        </div>

        {requiredSigs > 1 && (
          <div className="glass-card">
            <h2 className="text-xl font-semibold mb-4">📧 Trustee Email Addresses</h2>
            <p className="text-sm text-gray-300 mb-3">
              Enter email addresses of trustees who will receive their unique shares.
            </p>

            <div className="space-y-2">
              {[0, 1, 2, 3, 4].map(i => (
                <input
                  key={i}
                  type="email"
                  placeholder={`Trustee ${i + 1} email`}
                  className="input-field text-sm"
                  value={trusteeEmails[i]}
                  onChange={(e) => {
                    const newEmails = [...trusteeEmails];
                    newEmails[i] = e.target.value;
                    setTrusteeEmails(newEmails);
                  }}
                />
              ))}
            </div>

            <p className="text-xs text-gray-400 mt-2">
              We'll automatically email each trustee their unique share when the vault is created.
            </p>
          </div>
        )}

        <div
          className={`glass-card border-2 border-dashed ${dragActive ? 'border-primary-500' : 'border-white/20'} transition`}
          onDragEnter={(e) => {
            e.preventDefault();
            e.stopPropagation();
            setDragActive(true);
          }}
          onDragLeave={(e) => {
            e.preventDefault();
            e.stopPropagation();
            setDragActive(false);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
          onDrop={handleDrop}
        >
          <h2 className="text-xl font-semibold mb-4">Upload Files</h2>

          <div className="border-2 border-dashed border-white/30 rounded-lg p-8 text-center cursor-pointer"
               onClick={() => document.getElementById('fileInput').click()}>
            <div className="text-4xl mb-3">📁</div>
            <p className="mb-2">
              {files.length === 0
                ? 'Drag & drop files here or click to browse'
                : `${files.length} file${files.length !== 1 ? 's' : ''} selected`}
            </p>
            <p className="text-sm text-gray-400">Max file size: 2GB per file</p>
          </div>

          <input
            id="fileInput"
            type="file"
            multiple
            className="hidden"
            onChange={handleFileInput}
          />

          {files.length > 0 && (
            <div className="mt-4 space-y-2 max-h-60 overflow-y-auto">
              {files.map((file, index) => (
                <div key={index} className="flex justify-between items-center p-2 bg-white/5 rounded">
                  <div className="truncate">{file.name}</div>
                  <div className="flex space-x-2">
                    <span className="text-sm text-gray-400">
                      {(file.size / (1024 * 1024)).toFixed(2)} MB
                    </span>
                    <button
                      type="button"
                      onClick={() => removeFile(index)}
                      className="text-red-400 hover:text-red-300"
                    >
                      ×
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex justify-end space-x-3">
          <button
            type="button"
            onClick={onBack}
            className="btn-outline"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn-primary"
            disabled={uploading || !name || files.length === 0}
          >
            {uploading ? 'Creating Vault...' : 'Create Vault'}
          </button>
        </div>
      </form>
    </div>
  );
}

// Vault Detail Page Component
function VaultDetailPage({ vault, onBack, user }) {
  const [vaultData, setVaultData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showEmergencyUnlock, setShowEmergencyUnlock] = useState(false);
  const [trusteeEmail, setTrusteeEmail] = useState('');
  const [trusteeShare, setTrusteeShare] = useState('');
  const [submittedShares, setSubmittedShares] = useState(0);

  useEffect(() => {
    const fetchVaultDetails = async () => {
      try {
        const response = await axios.get(`/vaults/${vault.id}`);
        setVaultData(response.data);
      } catch (error) {
        console.error('Vault detail fetch error:', error);
        toast.error('Failed to load vault details');
        onBack();
      } finally {
        setLoading(false);
      }
    };

    fetchVaultDetails();
  }, [vault.id, onBack]);

  const downloadFile = async (fileId) => {
    try {
      const response = await axios.get(`/files/${fileId}/download`, {
        responseType: 'blob'
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      // Try to get filename from Content-Disposition header
      const contentDisposition = response.headers['content-disposition'];
      let filename = 'download';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?(.+)"?/i);
        if (filenameMatch) filename = filenameMatch[1];
      }
      
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      toast.success('File downloaded successfully!');
    } catch (error) {
      if (error.response?.status === 403 && error.response?.data?.timeLeftSeconds) {
        const timeLeft = error.response.data.timeLeftSeconds;
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        toast.error(`File locked! Unlocks in ${minutes}m ${seconds}s`);
      } else {
        toast.error(error.response?.data?.error || 'Download failed');
      }
    }
  };

  const handleSubmitShare = async () => {
    if (!trusteeEmail || !trusteeShare) {
      toast.error('Please provide trustee email and share');
      return;
    }

    try {
      const response = await axios.post(`/vaults/${vault.id}/submit-share`, {
        trusteeEmail,
        share: trusteeShare
      });

      setSubmittedShares(response.data.submittedCount);
      toast.success(`Share submitted! ${response.data.submittedCount} of ${response.data.requiredCount} shares received`);

      setTrusteeEmail('');
      setTrusteeShare('');

      if (response.data.canUnlock) {
        toast.info('Sufficient shares received! You can now perform emergency unlock.');
      }
    } catch (error) {
      toast.error(error.response?.data?.error || 'Failed to submit share');
    }
  };

  const handleEmergencyUnlock = async () => {
    if (!window.confirm('Are you sure you want to perform emergency unlock? This will reconstruct the encryption key from trustee shares.')) {
      return;
    }

    try {
      await axios.post(`/vaults/${vault.id}/emergency-unlock`);
      toast.success('🎉 Vault unlocked successfully via emergency protocol!');

      // Wait a moment for database to commit, then refresh
      setTimeout(async () => {
        try {
          const response = await axios.get(`/vaults/${vault.id}`);
          setVaultData(response.data);
          setShowEmergencyUnlock(false);
        } catch (error) {
          console.error('Failed to refresh vault:', error);
          // Refresh anyway to update UI
          window.location.reload();
        }
      }, 500);
    } catch (error) {
      toast.error(error.response?.data?.error || 'Emergency unlock failed');
    }
  };

  const handleResetShares = async () => {
    if (!window.confirm('Are you sure you want to clear all submitted shares? This will reset the emergency unlock process.')) {
      return;
    }

    try {
      await axios.delete(`/vaults/${vault.id}/reset-shares`);
      setSubmittedShares(0);
      setTrusteeEmail('');
      setTrusteeShare('');
      toast.success('All shares cleared. You can start over.');
    } catch (error) {
      toast.error('Failed to reset shares');
    }
  };

  if (loading) {
    return (
      <div className="glass-card text-center py-12">
        Loading vault details...
      </div>
    );
  }

  if (!vaultData) {
    return (
      <div className="glass-card text-center py-12">
        <p>Vault not found</p>
        <button onClick={onBack} className="btn-primary mt-4">Back to Dashboard</button>
      </div>
    );
  }

  const isLocked = !vaultData.isUnlocked;
  const isMultiSig = vaultData.required_sigs > 1;

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">{vaultData.name}</h1>
        <button onClick={onBack} className="btn-outline">Back to Dashboard</button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Vault Info */}
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-card">
            <h2 className="text-xl font-semibold mb-4">Vault Information</h2>
            <div className="space-y-3">
              <div>
                <span className="text-gray-400">Description:</span>
                <p className="mt-1">{vaultData.description || 'No description'}</p>
              </div>
              <div>
                <span className="text-gray-400">Encryption:</span>
                <p className="mt-1">
                  <span className="text-primary-300 font-mono">AES-256-GCM</span>
                  {isMultiSig && (
                    <span className="ml-2 px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-xs">
                      Multi-Signature ({vaultData.required_sigs} of {vaultData.trustee_count})
                    </span>
                  )}
                </p>
              </div>
              {vaultData.unlock_time && (
                <div>
                  <span className="text-gray-400">Scheduled Unlock:</span>
                  <p className="mt-1 text-yellow-400">
                    {formatDateTime(vaultData.unlock_time)}
                    {isLocked && vaultData.timeLeft && (
                      <span className="ml-2">({Math.floor(vaultData.timeLeft/60)}m {vaultData.timeLeft%60}s remaining)</span>
                    )}
                  </p>
                </div>
              )}
              <div>
                <span className="text-gray-400">Status:</span>
                <span className={`ml-2 status-badge ${isLocked ? 'status-locked' : 'status-unlocked'}`}>
                  {isLocked ? '🔒 Locked' : '🔓 Unlocked'}
                </span>
              </div>
            </div>
          </div>

          {/* Files */}
          <div className="glass-card">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-semibold">Files ({vaultData.files.length})</h2>
              {!isLocked && (
                <span className="text-green-400">Ready for download</span>
              )}
            </div>

            {vaultData.files.length === 0 ? (
              <p className="text-gray-400">No files in this vault</p>
            ) : (
              <div className="space-y-3">
                {vaultData.files.map(file => (
                  <div key={file.id} className="flex justify-between items-center p-3 bg-white/5 rounded">
                    <div>
                      <div className="font-medium">{file.filename}</div>
                      <div className="text-sm text-gray-400">{(file.filesize / (1024*1024)).toFixed(2)} MB</div>
                    </div>
                    <button
                      onClick={() => downloadFile(file.id)}
                      disabled={isLocked}
                      className={`px-4 py-2 rounded-lg ${
                        isLocked
                          ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                          : 'bg-green-600 hover:bg-green-700 text-white'
                      }`}
                    >
                      {isLocked ? 'Locked' : 'Download'}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Security Panel */}
        <div className="space-y-6">
          {isMultiSig && isLocked && (
            <div className="glass-card">
              <h2 className="text-xl font-semibold mb-4">🔐 Emergency Unlock</h2>

              <p className="text-sm text-gray-300 mb-3">
                Submit trustee shares to unlock this vault before the scheduled time.
              </p>

              <div className="text-center py-4 bg-blue-500/10 rounded mb-4">
                <div className="text-lg font-bold text-blue-400">
                  {vaultData.required_sigs} of {vaultData.trustee_count} signatures required
                </div>
                <div className="text-sm text-gray-400 mt-1">
                  {submittedShares} shares submitted
                </div>
              </div>

              {!showEmergencyUnlock ? (
                <button
                  onClick={() => setShowEmergencyUnlock(true)}
                  className="btn-primary w-full"
                >
                  Start Emergency Unlock
                </button>
              ) : (
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm mb-1">Trustee Email</label>
                    <input
                      type="email"
                      className="input-field text-sm"
                      value={trusteeEmail}
                      onChange={(e) => setTrusteeEmail(e.target.value)}
                      placeholder="trustee@example.com"
                    />
                  </div>

                  <div>
                    <label className="block text-sm mb-1">Cryptographic Share</label>
                    <textarea
                      className="input-field text-sm font-mono"
                      rows="3"
                      value={trusteeShare}
                      onChange={(e) => setTrusteeShare(e.target.value)}
                      placeholder="Paste trustee's share here..."
                    />
                  </div>

                  <button
                    onClick={handleSubmitShare}
                    className="btn-primary w-full"
                  >
                    Submit Share
                  </button>

                  {submittedShares > 0 && (
                    <button
                      onClick={handleResetShares}
                      className="bg-yellow-600 hover:bg-yellow-700 text-white py-2 px-4 rounded-lg w-full"
                    >
                      🔄 Reset All Shares ({submittedShares} submitted)
                    </button>
                  )}

                  {submittedShares >= vaultData.required_sigs && (
                    <button
                      onClick={handleEmergencyUnlock}
                      className="bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded-lg w-full"
                    >
                      ✅ Unlock Vault Now
                    </button>
                  )}

                  <button
                    onClick={() => setShowEmergencyUnlock(false)}
                    className="btn-outline w-full"
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          )}

          {isLocked && !isMultiSig && vaultData.unlock_time && (
            <div className="glass-card">
              <h2 className="text-xl font-semibold mb-4">⏰ Time-Lock Puzzle</h2>
              <p className="text-sm text-gray-300 mb-3">
                This vault uses military-grade time-lock encryption. Files will automatically unlock at the scheduled time.
              </p>
              <div className="text-center py-4 bg-yellow-500/10 rounded">
                <div className="text-2xl font-bold text-yellow-400">
                  {Math.floor(vaultData.timeLeft/60)}:{(vaultData.timeLeft%60).toString().padStart(2, '0')}
                </div>
                <div className="text-sm text-gray-400">Time remaining</div>
              </div>
            </div>
          )}

          {/* Vault Management */}
          <div className="glass-card">
            <h2 className="text-xl font-semibold mb-4">⚙️ Vault Management</h2>

            <button
              onClick={async () => {
                if (window.confirm('Are you sure you want to delete this vault? This cannot be undone.')) {
                  try {
                    await axios.delete(`/vaults/${vault.id}`);
                    toast.success('Vault deleted successfully!');
                    onBack();
                  } catch (error) {
                    toast.error('Failed to delete vault');
                  }
                }
              }}
              className="bg-red-600 hover:bg-red-700 text-white py-3 px-4 rounded-lg transition w-full"
            >
              🗑️ Delete Vault
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// Continue with Premium and Admin pages...
// Premium Page Component
function PremiumPage({ onUpgrade, onBack, isPremium }) {
  if (isPremium) {
    return (
      <div className="glass-card text-center py-12">
        <div className="text-5xl mb-4">🎉</div>
        <h2 className="text-2xl font-bold mb-2">You're Already Premium!</h2>
        <p className="text-gray-300 mb-6">Enjoy unlimited vaults and storage.</p>
        <button
          onClick={onBack}
          className="btn-primary"
        >
          Back to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Upgrade to Premium</h1>
        <button
          onClick={onBack}
          className="btn-outline"
        >
          Back to Dashboard
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="glass-card">
          <h2 className="text-xl font-semibold mb-4">Free Plan</h2>
          <ul className="space-y-3">
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>3 vaults per week</span>
            </li>
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>20GB total storage</span>
            </li>
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>Basic encryption</span>
            </li>
            <li className="flex items-start text-gray-500">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
              <span>No multi-signature support</span>
            </li>
            <li className="flex items-start text-gray-500">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
              <span>No priority support</span>
            </li>
          </ul>
        </div>

        <div className="glass-card border-2 border-primary-500/50 relative">
          <div className="absolute top-0 right-0 bg-gradient-to-r from-primary-500 to-secondary-500 text-white text-xs font-bold px-3 py-1 rounded-bl-lg">
            POPULAR
          </div>
          <h2 className="text-xl font-semibold mb-4">Premium Plan</h2>
          <div className="text-3xl font-bold mb-4">$9.99<span className="text-lg font-normal">/month</span></div>
          <ul className="space-y-3">
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>Unlimited vaults</span>
            </li>
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>Unlimited storage</span>
            </li>
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>Military-grade AES-256-GCM encryption</span>
            </li>
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>Multi-signature support (up to 5 of 5)</span>
            </li>
            <li className="flex items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-400 mr-2 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>Priority 24/7 support</span>
            </li>
          </ul>
          <button
            onClick={onUpgrade}
            className="btn-primary w-full mt-6"
          >
            Upgrade Now
          </button>
        </div>
      </div>
    </div>
  );
}

// Admin Page Component
function AdminPage({ onBack }) {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const response = await axios.get('/admin/dashboard');
        setDashboardData(response.data);
      } catch (error) {
        toast.error('Failed to fetch admin data');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboard();
  }, []);

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Admin Dashboard</h1>
        <button
          onClick={onBack}
          className="btn-outline"
        >
          Back to Dashboard
        </button>
      </div>

      {loading ? (
        <div className="glass-card text-center py-12">
          Loading admin data...
        </div>
      ) : !dashboardData ? (
        <div className="glass-card text-center py-12">
          Failed to load admin data
        </div>
      ) : (
        <>
          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-6">
            <div className="glass-card text-center">
              <div className="text-3xl font-bold text-primary-400">{dashboardData.totals.users}</div>
              <div className="text-gray-300">Total Users</div>
            </div>
            <div className="glass-card text-center">
              <div className="text-3xl font-bold text-secondary-400">{dashboardData.totals.vaults}</div>
              <div className="text-gray-300">Total Vaults</div>
            </div>
            <div className="glass-card text-center">
              <div className="text-3xl font-bold text-green-400">{dashboardData.totals.files}</div>
              <div className="text-gray-300">Total Files</div>
            </div>
            <div className="glass-card text-center">
              <div className="text-3xl font-bold text-purple-400">{dashboardData.totals.premium}</div>
              <div className="text-gray-300">Premium Users</div>
            </div>
            <div className="glass-card text-center">
              <div className="text-3xl font-bold text-yellow-400">
                {dashboardData.totals.storage ? (dashboardData.totals.storage / (1024**3)).toFixed(2) : '0'} GB
              </div>
              <div className="text-gray-300">Total Storage</div>
            </div>
          </div>

          {/* Recent Activity */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="glass-card">
              <h2 className="text-xl font-semibold mb-4">Recent Users</h2>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-gray-400 text-sm">
                      <th className="pb-2">Email</th>
                      <th className="pb-2">Name</th>
                      <th className="pb-2">Role</th>
                      <th className="pb-2">Joined</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.recentUsers.map(user => (
                      <tr key={user.id} className="border-t border-white/10">
                        <td className="py-2 text-sm">{user.email}</td>
                        <td className="py-2 text-sm">{user.first_name} {user.last_name}</td>
                        <td className="py-2">
                          <span className={`status-badge ${user.role === 'admin' ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400'}`}>
                            {user.role}
                          </span>
                        </td>
                        <td className="py-2 text-sm text-gray-400">
                          {new Date(user.created_at).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="glass-card">
              <h2 className="text-xl font-semibold mb-4">Recent Vaults</h2>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-gray-400 text-sm">
                      <th className="pb-2">Name</th>
                      <th className="pb-2">Owner</th>
                      <th className="pb-2">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.recentVaults.map(vault => (
                      <tr key={vault.id} className="border-t border-white/10">
                        <td className="py-2 text-sm">{vault.name}</td>
                        <td className="py-2 text-sm">{vault.owner_email}</td>
                        <td className="py-2 text-sm text-gray-400">
                          {new Date(vault.created_at).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default App;
