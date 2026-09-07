import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';

// Test that the app can render without crashing
describe('App', () => {
  it('renders without crashing', async () => {
    const { default: App } = await import('../App');
    const { container } = render(<App />);
    expect(container).toBeTruthy();
  });

  it('renders router and suspense boundary', async () => {
    const { default: App } = await import('../App');
    const { container } = render(<App />);
    // Should have rendered something within a router
    expect(container.innerHTML.length).toBeGreaterThan(0);
  });
});

// Test configuration module
describe('Config', () => {
  it('exports API_BASE_URL', async () => {
    const { API_BASE_URL } = await import('../config');
    expect(API_BASE_URL).toBeDefined();
    expect(typeof API_BASE_URL).toBe('string');
  });

  it('exports WS_BASE_URL derived from API_BASE_URL', async () => {
    const { WS_BASE_URL } = await import('../config');
    expect(WS_BASE_URL).toMatch(/^ws/);
  });

  it('exports AUTH_CONFIG with cookie auth setting', async () => {
    const { AUTH_CONFIG } = await import('../config');
    expect(AUTH_CONFIG).toBeDefined();
    expect(AUTH_CONFIG).toHaveProperty('useCookieAuth');
  });
});
