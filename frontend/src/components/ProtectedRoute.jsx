import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';

const ProtectedRoute = ({ children }) => {
    const location = useLocation();
    
    // Check for active token or authenticated user session
    const token = localStorage.getItem('cyberscout_access_token');
    const user = localStorage.getItem('cyberscout_currentUser') || localStorage.getItem('phishguard_currentUser');

    const isAuthenticated = Boolean(token || user);

    if (!isAuthenticated) {
        // Redirect to login while preserving target path for post-login return
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    return children;
};

export default ProtectedRoute;
