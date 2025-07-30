
import Navbar from '../components/Navbar';

export default function About() {
  return (
    <div>
      <Navbar />
      <h2>About</h2>
      <p>This site was created by [Your Name].</p>
      <p>It was built to help detect Evil Twin WiFi access points.</p>
      <p>Built using: React, SQL, Python, Flask/Express (for backend).</p>
      <p>Resources: Scapy, React Router, Axios, Bootstrap, MDN Web Docs.</p>
    </div>
  );
}