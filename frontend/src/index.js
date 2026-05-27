import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Mounts the background React context engine without replacing your public/index.html design
const rootElement = document.getElementById('root');
if (rootElement) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}
