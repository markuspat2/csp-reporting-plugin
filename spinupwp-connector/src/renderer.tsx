import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import { SpinupwpClient } from './spinupwp/client';

declare const window: any;

function Panel() {
  const [token, setToken] = useState<string>('');
  const [servers, setServers] = useState<any[]>([]);
  const [status, setStatus] = useState<string>('');

  const client = new SpinupwpClient(() => token);

  async function loadServers() {
    setStatus('Loading servers...');
    try {
      const response = await client.getServers();
      setServers(response?.data ?? []);
      setStatus('');
    } catch (error: any) {
      setStatus(error?.message || 'Failed to load servers');
    }
  }

  useEffect(() => {
    const unsub = window.localRenderer?.onIPCEvent?.('spinupwp:open', () => {
      // Panel open event; could load defaults
    });
    return () => unsub?.();
  }, []);

  return (
    <div style={{ padding: 16 }}>
      <h2>SpinupWP Connector</h2>
      <label>
        API Token
        <input
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="Paste SpinupWP API token"
          style={{ width: '100%' }}
        />
      </label>
      <div style={{ marginTop: 8 }}>
        <button onClick={loadServers} disabled={!token}>
          List Servers
        </button>
      </div>
      {status && <p>{status}</p>}
      {!!servers.length && (
        <ul>
          {servers.map((s) => (
            <li key={s.id}>{s.name}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function mount() {
  const root = document.getElementById('spinupwp-connector-root') || (() => {
    const el = document.createElement('div');
    el.id = 'spinupwp-connector-root';
    document.body.appendChild(el);
    return el;
  })();
  ReactDOM.render(<Panel />, root);
}

// Local will call default export with renderer context in real add-on
export default function renderer() {
  mount();
}

