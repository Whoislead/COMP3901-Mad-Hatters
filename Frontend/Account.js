import { useState } from 'react';
import axios from 'axios';
import Navbar from '../components/Navbar';

export default function Account({ username }) {
  const [password, setPassword] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const changeUsername = async () => {
    const res = await axios.post('/api/change-username', { username, password, newUsername });
    alert(res.data.message);
  };

  const changePassword = async () => {
    if (newPassword !== confirmPassword) return alert('Passwords do not match');
    const res = await axios.post('/api/change-password', { username, password, newPassword });
    alert(res.data.message);
  };

  return (
    <div>
      <Navbar username={username} />
      <h2>Account</h2>
      <div>
        <h3>Change Username</h3>
        <input placeholder="Password" type="password" onChange={e => setPassword(e.target.value)} />
        <input placeholder="New Username" onChange={e => setNewUsername(e.target.value)} />
        <button onClick={changeUsername}>Save</button>
      </div>
      <div>
        <h3>Change Password</h3>
        <input placeholder="Current Password" type="password" onChange={e => setPassword(e.target.value)} />
        <input placeholder="New Password" type="password" onChange={e => setNewPassword(e.target.value)} />
        <input placeholder="Confirm New Password" type="password" onChange={e => setConfirmPassword(e.target.value)} />
        <button onClick={changePassword}>Save</button>
      </div>
    </div>
  );
}