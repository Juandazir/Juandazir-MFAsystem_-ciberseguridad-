import React, { useState } from 'react';
import './App.css';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [userId, setUserId] = useState(null);
  const [otp, setOtp] = useState('');
  const [message, setMessage] = useState('');

  const handleLogin = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/accounts/login/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await response.json();
      if (data.user_id) {
        setUserId(data.user_id);
        setMessage(`Please enter OTP for user ${data.user_id}`);
      } else {
        setMessage(data.error || 'Login failed');
      }
    } catch (err) {
      setMessage('Network error');
    }
  };

  const handleMFA = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/accounts/verify-mfa/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId, otp })
      });
      const data = await response.json();
      if (data.access) {
        localStorage.setItem('access', data.access);
        setMessage('Success! You are now logged in.');
      } else {
        setMessage(data.error || 'MFA verification failed');
      }
    } catch (err) {
      setMessage('Network error during MFA verification');
    }
  };

  return (
    <div className="app-container">
      <h1>MFA Authentication System</h1>
      {!userId ? (
        <div className="login-form">
          <h2>Login</h2>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Email"
            className="input-field"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            className="input-field"
          />
          <button onClick={handleLogin} className="btn btn-primary">Login</button>
        </div>
      ) : (
        <div className="mfa-form">
          <h2>MFA Verification</h2>
          <p>Enter the OTP from your authenticator app</p>
          <input
            type="text"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            placeholder="Enter OTP"
            className="input-field"
          />
          <button onClick={handleMFA} className="btn btn-success">Verify OTP</button>
        </div>
      )}
      {message && <div className="message">{message}</div>}
    </div>
  );
}

export default App;
