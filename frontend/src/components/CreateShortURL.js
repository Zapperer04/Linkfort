import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:5000';

function CreateShortURL() {
  const [url, setUrl] = useState('');
  const [customCode, setCustomCode] = useState('');
  const [expirationDays, setExpirationDays] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [codeAvailability, setCodeAvailability] = useState(null);
  const [checkingCode, setCheckingCode] = useState(false);

  const checkCodeAvailability = async (code) => {
    if (!code || code.length < 3) {
      setCodeAvailability(null);
      return;
    }

    setCheckingCode(true);
    try {
      const response = await axios.get(`${API_BASE}/api/check-code/${code}`);
      setCodeAvailability(response.data);
    } catch (err) {
      setCodeAvailability(null);
    }
    setCheckingCode(false);
  };

  React.useEffect(() => {
    const timer = setTimeout(() => {
      if (customCode) {
        checkCodeAvailability(customCode);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [customCode]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const response = await axios.post(`${API_BASE}/api/shorten`, {
        url: url,
        custom_code: customCode || undefined,
        expiration_days: expirationDays ? parseInt(expirationDays) : undefined
      });

      setResult(response.data);
      setUrl('');
      setCustomCode('');
      setExpirationDays('');
      setCodeAvailability(null);
    } catch (err) {
      setError(err.response?.data || { error: 'An error occurred' });
    }

    setLoading(false);
  };

  const getAvailabilityColor = () => {
    if (!codeAvailability) return '#718096';
    return codeAvailability.available ? '#48bb78' : '#f56565';
  };

  const getAvailabilityIcon = () => {
    if (checkingCode) return '⏳';
    if (!codeAvailability) return '';
    return codeAvailability.available ? '✅' : '❌';
  };

  return (
    <div className="create-short-url">
      <h2 style={{
        color: 'white',
        marginBottom: '32px',
        fontSize: '32px',
        fontWeight: '800',
        letterSpacing: '-0.5px'
      }}>
        ✨ Create Short URL
      </h2>

      <div className="stat-card" style={{ maxWidth: '800px', margin: '0 auto' }}>
        <form onSubmit={handleSubmit}>
          {/* Original URL Input */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              marginBottom: '8px',
              color: '#2d3748',
              fontWeight: '600',
              fontSize: '14px'
            }}>
              Enter URL to shorten
            </label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/very/long/url"
              required
              style={{
                width: '100%',
                padding: '14px 18px',
                border: '2px solid rgba(102, 126, 234, 0.2)',
                borderRadius: '12px',
                fontSize: '16px',
                transition: 'all 0.3s',
                background: 'rgba(255, 255, 255, 0.9)'
              }}
            />
          </div>

          {/* Custom Code Input */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              marginBottom: '8px',
              color: '#2d3748',
              fontWeight: '600',
              fontSize: '14px'
            }}>
              Custom Short Code (Optional)
            </label>
            <div style={{ position: 'relative' }}>
              <div style={{
                position: 'absolute',
                left: '18px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#718096',
                fontWeight: '600',
                pointerEvents: 'none'
              }}>
                linkfort.com/
              </div>
              <input
                type="text"
                value={customCode}
                onChange={(e) => setCustomCode(e.target.value.toLowerCase())}
                placeholder="my-awesome-link"
                style={{
                  width: '100%',
                  padding: '14px 18px 14px 140px',
                  border: `2px solid ${codeAvailability ? (codeAvailability.available ? '#48bb78' : '#f56565') : 'rgba(102, 126, 234, 0.2)'}`,
                  borderRadius: '12px',
                  fontSize: '16px',
                  transition: 'all 0.3s',
                  background: 'rgba(255, 255, 255, 0.9)',
                  fontFamily: 'monospace'
                }}
              />
              {customCode && (
                <div style={{
                  position: 'absolute',
                  right: '18px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  fontSize: '18px'
                }}>
                  {getAvailabilityIcon()}
                </div>
              )}
            </div>
            
            {customCode && codeAvailability && (
              <div style={{
                marginTop: '8px',
                fontSize: '13px',
                fontWeight: '600',
                color: getAvailabilityColor(),
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}>
                {getAvailabilityIcon()} {codeAvailability.reason}
              </div>
            )}
            
            <p style={{
              marginTop: '8px',
              fontSize: '13px',
              color: '#718096'
            }}>
              Leave blank for auto-generated. 3-20 chars, letters/numbers/hyphens/underscores only.
            </p>
          </div>

          {/* Expiration Input - NEW */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              marginBottom: '8px',
              color: '#2d3748',
              fontWeight: '600',
              fontSize: '14px'
            }}>
              ⏰ Link Expiration (Optional)
            </label>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <input
                type="number"
                value={expirationDays}
                onChange={(e) => setExpirationDays(e.target.value)}
                placeholder="7"
                min="1"
                max="365"
                style={{
                  flex: 1,
                  padding: '14px 18px',
                  border: '2px solid rgba(102, 126, 234, 0.2)',
                  borderRadius: '12px',
                  fontSize: '16px',
                  transition: 'all 0.3s',
                  background: 'rgba(255, 255, 255, 0.9)'
                }}
              />
              <span style={{ color: '#718096', fontWeight: '600', fontSize: '15px' }}>days</span>
            </div>
            <p style={{
              marginTop: '8px',
              fontSize: '13px',
              color: '#718096'
            }}>
              Leave blank for permanent link. Link will auto-expire after specified days (1-365).
            </p>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="btn-primary"
            disabled={loading || (customCode && codeAvailability && !codeAvailability.available)}
            style={{ width: '100%' }}
          >
            {loading ? '⏳ Shortening...' : '🔗 Shorten URL'}
          </button>
        </form>

        {/* Success Result */}
        {result && !error && (
          <div className="result-box result-success">
            <h3 style={{ margin: '0 0 12px 0', fontSize: '18px', fontWeight: '700', color: '#2f855a' }}>
              ✅ URL Shortened Successfully
              {result.custom_code_used && (
                <span style={{ fontSize: '14px', fontWeight: '500', marginLeft: '8px', color: '#38a169' }}>
                  (Custom code used!)
                </span>
              )}
            </h3>
            
            <div className="short-url-box">
              <strong>Short URL:</strong>{' '}
              <a href={result.data.short_url} target="_blank" rel="noopener noreferrer">
                {result.data.short_url}
              </a>
            </div>

            <div style={{ marginTop: '16px', fontSize: '14px', color: '#2d3748' }}>
              <strong>Threat Score:</strong> {result.data.threat_score.toFixed(2)} / 1.00
              <br />
              <strong>Verdict:</strong>{' '}
              <span style={{
                color: result.data.threat_verdict === 'SAFE' ? '#48bb78' :
                       result.data.threat_verdict === 'WARN' ? '#ed8936' : '#f56565',
                fontWeight: '600'
              }}>
                {result.data.threat_verdict}
              </span>
              {result.data.threat_verdict === 'SAFE' && ' (All layers passed)'}
              
              {/* Show expiration if set */}
              {result.data.expires_at && (
                <>
                  <br />
                  <strong>⏰ Expires:</strong>{' '}
                  <span style={{ color: '#ed8936', fontWeight: '600' }}>
                    {new Date(result.data.expires_at).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </span>
                </>
              )}
            </div>
          </div>
        )}

        {/* Error Result */}
        {error && (
          <div className={`result-box ${error.error === 'URL blocked' ? 'result-error' : 'result-warning'}`}>
            <h3 style={{
              margin: '0 0 12px 0',
              fontSize: '18px',
              fontWeight: '700',
              color: error.error === 'URL blocked' ? '#c53030' : '#c05621'
            }}>
              {error.error === 'URL blocked' ? '⛔ URL Blocked' : '⚠️ Error'}
            </h3>

            <p style={{ marginBottom: '12px', fontSize: '15px', fontWeight: '500' }}>
              {error.message || error.error}
            </p>

            {error.reasons && error.reasons.length > 0 && (
              <div>
                <strong>Reasons:</strong>
                <ul style={{ marginTop: '8px', paddingLeft: '20px' }}>
                  {error.reasons.map((reason, index) => (
                    <li key={index} style={{ marginBottom: '4px' }}>
                      {reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {error.threat_score !== undefined && (
              <div style={{ marginTop: '12px', fontSize: '14px' }}>
                <strong>Threat Score:</strong> {error.threat_score.toFixed(2)} / 1.00
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default CreateShortURL;