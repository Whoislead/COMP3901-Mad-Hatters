import { useState } from 'react';
import axios from 'axios';
import Navbar from '../components/Navbar';

export default function Scan() {
  const [result, setResult] = useState('');

  const handleScan = async (type) => {
    const res = await axios.get(`/api/scan?type=${type}`);
    setResult(res.data.output);
  };

  return (
    <div>
      <Navbar />
      <h2>Scan</h2>
      <button onClick={() => handleScan('connected')}>Connected</button>
      <p>For when you're testing the wifi you are currently connected to</p>
      <button onClick={() => handleScan('unconnected')}>Unconnected</button>
      <p>For when you want to test the wifis around you</p>
      <pre>{result}</pre>
    </div>
  );
}
