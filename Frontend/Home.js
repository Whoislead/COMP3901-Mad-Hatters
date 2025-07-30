import Navbar from '../components/Navbar';

export default function Home({ username }) {
  return (
    <div>
      <Navbar username={username} />
      <h1>Welcome</h1>
    </div>
  );
}