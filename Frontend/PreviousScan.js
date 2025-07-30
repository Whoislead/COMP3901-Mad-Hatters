import { useState, useEffect } from 'react';
import axios from 'axios';
import Navbar from '../components/Navbar';

export default function PreviousScans() {
  const [records, setRecords] = useState([]);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('SSID');

  useEffect(() => {
    axios.get('/api/scans').then(res => setRecords(res.data));
  }, []);

  const filtered = records.filter(r => r[filter].toLowerCase().includes(search.toLowerCase()));

  return (
    <div>
      <Navbar />
      <h2>Previous Scans</h2>
      <select onChange={e => setFilter(e.target.value)}>
        <option>SSID</option>
        <option>BSSID</option>
        <option>Vendor</option>
      </select>
      <input placeholder="Search..." onChange={e => setSearch(e.target.value)} />
      <ul>
        {filtered.map((r, i) => <li key={i}>{r.SSID} | {r.BSSID} | {r.Vendor}</li>)}
      </ul>
    </div>
  );
}
