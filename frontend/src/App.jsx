import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Home from './pages/Home';
import Features from './pages/Features';
import HowItWorks from './pages/HowItWorks';
import AboutUs from './pages/AboutUs';
import Login from './pages/Login';
import Register from './pages/Register';
import DashboardLayout from './layouts/DashboardLayout';
import DashboardHome from './pages/DashboardHome';
import UrlAnalysis from './pages/UrlAnalysis';
import EmailAnalysis from './pages/EmailAnalysis';
import BlockedUrls from './pages/BlockedUrls';
import PasswordSecurity from './pages/PasswordSecurity';
import LinkSafety from './pages/LinkSafety';
import SecurityAwareness from './pages/SecurityAwareness';
import ProtectedRoute from './components/ProtectedRoute';

function App() {
  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/" element={<Home />} />
      <Route path="/features" element={<Features />} />
      <Route path="/how-it-works" element={<HowItWorks />} />
      <Route path="/about" element={<AboutUs />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      {/* CyberScout Authenticated Dashboard Routes */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <DashboardLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardHome />} />
        <Route path="url" element={<UrlAnalysis />} />
        {import.meta.env.VITE_ENABLE_EMAIL_ANALYSIS !== 'false' && (
          <Route path="email" element={<EmailAnalysis />} />
        )}
        <Route path="password" element={<PasswordSecurity />} />
        <Route path="link-safety" element={<LinkSafety />} />
        <Route path="awareness" element={<SecurityAwareness />} />
        <Route path="blocked" element={<BlockedUrls />} />
      </Route>

      {/* Fallback */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
