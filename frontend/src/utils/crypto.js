/**
 * RSA Client-Side Vote Encryption
 * 
 * Votes are encrypted IN THE BROWSER before transmission.
 * Uses the election's public key — even a backend breach reveals no votes.
 * 
 * Encryption: c = m^e (mod n)
 */

/**
 * Encrypt a vote (candidate ID as string) using the election's RSA public key.
 * Returns base64-encoded ciphertext.
 */
export async function encryptVoteRSA(plainVote, publicKeyPem) {
  try {
    // Import the public key
    const pemBody = publicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '');
    
    const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
    
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      binaryDer.buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    const encoder = new TextEncoder();
    const voteBytes = encoder.encode(String(plainVote));

    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      voteBytes
    );

    // Convert to base64
    const encryptedArray = new Uint8Array(encrypted);
    const base64 = btoa(String.fromCharCode(...encryptedArray));
    return base64;
  } catch (err) {
    console.error('RSA encryption error:', err);
    throw new Error('Failed to encrypt vote. Please try again.');
  }
}

/**
 * Compute SHA-256 hash in the browser (for display/verification purposes).
 */
export async function sha256Browser(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
