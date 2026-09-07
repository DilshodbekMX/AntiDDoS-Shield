/**
 * Centralized error logger.
 *
 * In production, suppresses stack traces and could be wired
 * to an external error reporting service (e.g., Sentry).
 * In development, logs full details to console.
 */

const IS_PRODUCTION = import.meta.env.PROD;

export function logError(context: string, error: unknown): void {
  if (IS_PRODUCTION) {
    // Production: log minimal info, no stack traces
    const message = error instanceof Error ? error.message : String(error);
    // eslint-disable-next-line no-console
    console.error(`[${context}] ${message}`);
  } else {
    // Development: full details
    // eslint-disable-next-line no-console
    console.error(`[${context}]`, error);
  }
}
