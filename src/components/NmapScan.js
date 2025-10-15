import React, { useState, useEffect } from 'react';
import { Loader } from 'lucide-react';

const NmapScan = ({ target }) => {
  const [loading, setLoading] = useState(true);
  const [results, setResults] = useState(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      setResults(`
Nmap scan report for ${target}
Host is up (0.0021s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE
80/tcp    open  http
443/tcp   open  https
      `);
      setLoading(false);
    }, 5000); // Simulate a 5-second scan

    return () => clearTimeout(timer);
  }, [target]);

  return (
    <div className="bg-black text-white p-4 rounded-lg font-mono">
      {loading ? (
        <div className="flex items-center">
          <Loader className="animate-spin mr-2" />
          <span>Scanning {target}...</span>
        </div>
      ) : (
        <pre>{results}</pre>
      )}
    </div>
  );
};

export default NmapScan;