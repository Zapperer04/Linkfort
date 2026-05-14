import React, { useEffect, useMemo, useState } from 'react';
import './Homepage.css';

const highlightCards = [
  {
    icon: '[L]',
    title: 'Short Links',
    description: 'Create clear, compact links that are easy to share and easy to manage.'
  },
  {
    icon: '[R]',
    title: 'Risk Review',
    description: 'Check destination safety before publishing a link.'
  },
  {
    icon: '[P]',
    title: 'Protected Redirects',
    description: 'Control redirect behavior with safe, warning, and blocked states.'
  },
  {
    icon: '[A]',
    title: 'Click Analytics',
    description: 'Track link activity and monitor performance over time.'
  }
];

const featureGrid = [
  { title: 'Clean Short Links', copy: 'Create concise links for sharing anywhere.' },
  { title: 'Custom Aliases', copy: 'Create readable aliases for key destinations.' },
  { title: 'Link Expiration', copy: 'Set links to expire when they are no longer needed.' },
  { title: 'Password Protection', copy: 'Add an extra access step for private links.' },
  { title: 'Safety Status', copy: 'See whether each link is Safe, Warning, or Blocked.' },
  { title: 'Warning Pages', copy: 'Show a warning page before opening risky destinations.' },
  { title: 'Blocked Redirects', copy: 'Stop redirects when a destination is unsafe.' },
  { title: 'Click Tracking', copy: 'Monitor activity for every short link you create.' }
];

const useCases = [
  { title: 'Campaign links' },
  { title: 'Portfolio links' },
  { title: 'Social media links' },
  { title: 'QR code sharing' },
  { title: 'Internal resource sharing' },
  { title: 'Safer redirect testing' }
];

const faqs = [
  {
    q: 'What can I do with LinkFort?',
    a: 'Create short links for any URL, set custom aliases, add password protection, track clicks in real-time, and review the safety status of your destinations. Control how redirects behave with Safe, Warning, and Blocked states.'
  },
  {
    q: 'How does the safety check work?',
    a: 'LinkFort analyzes destination URLs for suspicious patterns and can show users a warning page before they redirect, or block the redirect entirely based on the detected risk level.'
  },
  {
    q: 'Can links expire?',
    a: 'Yes. You can set an expiration date for any short link. After expiration, the link becomes inactive and won\'t redirect.'
  },
  {
    q: 'How do I track link performance?',
    a: 'The dashboard shows total clicks, active links, top referrers, and safety status for all your links. Click on any link to see detailed activity.'
  },
  {
    q: 'Can I require a password for links?',
    a: 'Yes. Add password protection to any link to restrict access. Visitors must enter the correct password before being redirected to the destination.'
  }
];

function Homepage({ onNavigateToAuth, onNavigateToSignup }) {
  const [particles, setParticles] = useState([]);
  const [activeFaq, setActiveFaq] = useState(0);

  const dashboardBars = useMemo(() => [72, 88, 54, 91, 67, 84, 77], []);

  useEffect(() => {
    const newParticles = Array.from({ length: 28 }).map((_, index) => ({
      id: index,
      left: Math.random() * 100,
      top: Math.random() * 100,
      delay: Math.random() * 8,
      duration: 14 + Math.random() * 12,
      size: 2 + Math.random() * 4
    }));
    setParticles(newParticles);
  }, []);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('visible');
          }
        });
      },
      { threshold: 0.22 }
    );

    const revealTargets = document.querySelectorAll('.lf-reveal');
    revealTargets.forEach((el) => observer.observe(el));

    return () => {
      revealTargets.forEach((el) => observer.unobserve(el));
      observer.disconnect();
    };
  }, []);

  // Demo shortener removed from public homepage — creation is sign-in only.

  return (
    <div className="lf-homepage">
      <div className="lf-bg-grid" />
      <div className="lf-bg-glow lf-bg-glow-a" />
      <div className="lf-bg-glow lf-bg-glow-b" />

      <div className="lf-particles" aria-hidden="true">
        {particles.map((particle) => (
          <span
            key={particle.id}
            className="lf-particle"
            style={{
              left: `${particle.left}%`,
              top: `${particle.top}%`,
              width: `${particle.size}px`,
              height: `${particle.size}px`,
              animationDelay: `${particle.delay}s`,
              animationDuration: `${particle.duration}s`
            }}
          />
        ))}
      </div>

      <header className="lf-nav">
        <div className="lf-brand">LinkFort</div>
        <nav className="lf-nav-links" aria-label="Homepage sections">
          <a href="#overview" className="lf-nav-link">Overview</a>
          <a href="#features" className="lf-nav-link">Features</a>
          <a href="#security" className="lf-nav-link">Security</a>
          <a href="#analytics" className="lf-nav-link">Analytics</a>
          <a href="#faq" className="lf-nav-link">FAQ</a>
        </nav>
        <div className="lf-nav-actions">
          <button className="lf-btn lf-btn-ghost" onClick={onNavigateToAuth}>Log in</button>
          <button className="lf-btn lf-btn-primary" onClick={onNavigateToSignup}>Join Now</button>
        </div>
      </header>

      <section id="overview" className="lf-hero lf-shell">
        <div className="lf-hero-copy lf-reveal">
          <p className="lf-kicker">Secure URL shortening</p>
          <h1>Secure short links with smarter redirects.</h1>
          <p className="lf-subcopy">
            LinkFort helps you shorten URLs, review destination risk, and track link activity from one dashboard.
          </p>
          <div className="lf-cta-row">
            <button className="lf-btn lf-btn-primary" onClick={onNavigateToAuth}>Create Link</button>
            <a className="lf-link" href="#features">View Features</a>
          </div>
          <p className="lf-mini-note">Create, protect, and manage short links in one place.</p>
        </div>
      </section>

      <section className="lf-shell lf-section lf-reveal">
        <div className="lf-highlight-grid">
          {highlightCards.map((card) => (
            <article key={card.title}>
              <span>{card.icon}</span>
              <h3>{card.title}</h3>
              <p>{card.description}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="how-it-works" className="lf-shell lf-section lf-reveal">
        <div className="lf-section-title">
          <p className="lf-kicker">How it works</p>
          <h2>Three simple steps.</h2>
        </div>
        <div className="lf-steps">
          <article>
            <span>01</span>
            <h3>Paste a destination URL</h3>
            <p>Add the link you want to shorten.</p>
          </article>
          <article>
            <span>02</span>
            <h3>Review the safety status</h3>
            <p>Check whether the destination is marked Safe, Warning, or Blocked.</p>
          </article>
          <article>
            <span>03</span>
            <h3>Share the short link and track clicks</h3>
            <p>Publish the link and monitor activity in your dashboard.</p>
          </article>
        </div>
      </section>

      <section id="security" className="lf-shell lf-section lf-ai lf-reveal">
        <div>
          <p className="lf-kicker">Security</p>
          <h2>Check destinations before users click.</h2>
          <p>
            LinkFort reviews destination URLs for suspicious signals and can show warnings or block unsafe redirects.
          </p>
          <p className="lf-mini-note">LinkFort helps reduce risky redirects, but no automated check can guarantee perfect detection.</p>
        </div>
        <div className="lf-ai-panel">
          <div className="lf-ring" />
          <ul>
            <li>Suspicious URL checks</li>
            <li>Safe / Warning / Blocked statuses</li>
            <li>Warning screen for risky links</li>
            <li>Redirect blocking for unsafe links</li>
            <li>Expiry controls</li>
            <li>Password protection</li>
          </ul>
        </div>
      </section>

      <section id="analytics" className="lf-shell lf-section lf-reveal">
        <div className="lf-section-title">
          <p className="lf-kicker">Analytics</p>
          <h2>See how every link performs.</h2>
          <p className="lf-subcopy">Track link activity through a clean dashboard.</p>
        </div>
        <div className="lf-dashboard">
          <div className="lf-dash-chart">
            {dashboardBars.map((value, index) => (
              <span key={index} style={{ height: `${value}%` }} />
            ))}
          </div>
          <div className="lf-dash-cards">
            <article>
              <h4>Total Clicks</h4>
              <p>4,382</p>
            </article>
            <article>
              <h4>Active Links</h4>
              <p>132</p>
            </article>
            <article>
              <h4>Top Referrers</h4>
              <p>Social / Direct</p>
            </article>
            <article>
              <h4>Risk Status</h4>
              <p>Safe / Warning / Blocked</p>
            </article>
          </div>
        </div>
      </section>

      <section id="features" className="lf-shell lf-section lf-reveal">
        <div className="lf-section-title">
          <p className="lf-kicker">Features</p>
          <h2>Everything you need to shorten, protect, and track links.</h2>
        </div>
        <div className="lf-feature-grid">
          {featureGrid.map((feature) => (
            <article key={feature.title}>
              <h3>{feature.title}</h3>
              <p>{feature.copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="lf-shell lf-section lf-reveal">
        <div className="lf-section-title">
          <p className="lf-kicker">Use cases</p>
          <h2>Practical ways to use LinkFort.</h2>
        </div>
        <div className="lf-use-cases lf-list-grid">
          {useCases.map((item) => (
            <article key={item.title}>
              <h3>{item.title}</h3>
            </article>
          ))}
        </div>
      </section>

      <section id="faq" className="lf-shell lf-section lf-faq lf-reveal">
        <div className="lf-section-title">
          <p className="lf-kicker">FAQ</p>
          <h2>Common questions.</h2>
        </div>
        <div className="lf-faq-list">
          {faqs.map((item, index) => (
            <article key={item.q}>
              <button
                className="lf-faq-question"
                onClick={() => setActiveFaq((prev) => (prev === index ? -1 : index))}
              >
                <span>{item.q}</span>
                <span>{activeFaq === index ? '-' : '+'}</span>
              </button>
              {activeFaq === index && <p>{item.a}</p>}
            </article>
          ))}
        </div>
      </section>

      <section className="lf-shell lf-final-cta lf-reveal">
        <h2>Create safer short links with LinkFort.</h2>
        <p>Shorten URLs, review destination risk, and track every link from one clean dashboard.</p>
        <div className="lf-cta-row" style={{ justifyContent: 'center' }}>
          <button className="lf-btn lf-btn-primary" onClick={onNavigateToSignup}>Join Now</button>
          <a className="lf-link" href="#features">View Features</a>
        </div>
      </section>

      <footer className="lf-footer">
        <div className="lf-footer-container">
          <div className="lf-footer-shell">
            <div className="lf-footer-brand">
              <div className="lf-footer-logo">LinkFort</div>
              <p>
                Secure short links with risk checks, click tracking, and a premium dashboard experience.
              </p>
              <div className="lf-footer-badges">
                <span>Threat Detection</span>
                <span>Click Analytics</span>
                <span>Expiration Control</span>
              </div>
            </div>

            <div className="lf-footer-column">
              <h3>Product</h3>
              <a href="#overview">Overview</a>
              <a href="#features">Features</a>
              <a href="#security">Security</a>
              <a href="#analytics">Analytics</a>
            </div>

            <div className="lf-footer-column">
              <h3>Support</h3>
              <a href="#faq">FAQ</a>
              <a href="mailto:support@linkfort.local">Contact Support</a>
              <a href="#overview">Getting Started</a>
              <a href="#security">Safety Guide</a>
            </div>

            <div className="lf-footer-column">
              <h3>Actions</h3>
              <button className="lf-footer-action" onClick={onNavigateToSignup}>Join Now</button>
              <button className="lf-footer-action secondary" onClick={onNavigateToAuth}>Log in</button>
            </div>
          </div>

          <div className="lf-footer-bottom">
            <span>© 2026 LinkFort</span>
            <span>Shorten, protect, and track your links.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default Homepage;
