/**
 * Form Validation Utilities
 *
 * Provides type-safe form validation with clear error messages.
 */

// ==================== Validation Result Types ====================

export interface ValidationError {
  field: string;
  message: string;
  code?: string;
}

export interface ValidationResult<T> {
  valid: boolean;
  data?: T;
  errors: ValidationError[];
}

// ==================== Basic Validators ====================

/**
 * Check if value is not empty (null, undefined, or empty string)
 */
export function isRequired(value: unknown, fieldName: string): ValidationError | null {
  if (value === null || value === undefined || value === '') {
    return { field: fieldName, message: `${fieldName} is required`, code: 'required' };
  }
  return null;
}

/**
 * Check minimum length for strings
 */
export function minLength(value: string, min: number, fieldName: string): ValidationError | null {
  if (value.length < min) {
    return {
      field: fieldName,
      message: `${fieldName} must be at least ${min} characters`,
      code: 'min_length',
    };
  }
  return null;
}

/**
 * Check maximum length for strings
 */
export function maxLength(value: string, max: number, fieldName: string): ValidationError | null {
  if (value.length > max) {
    return {
      field: fieldName,
      message: `${fieldName} must be at most ${max} characters`,
      code: 'max_length',
    };
  }
  return null;
}

/**
 * Validate email format
 */
export function isEmail(value: string, fieldName: string): ValidationError | null {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(value)) {
    return { field: fieldName, message: `${fieldName} must be a valid email address`, code: 'invalid_email' };
  }
  return null;
}

/**
 * Validate IPv4 address format
 */
export function isIPv4(value: string, fieldName: string): ValidationError | null {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (!ipv4Regex.test(value)) {
    return { field: fieldName, message: `${fieldName} must be a valid IPv4 address`, code: 'invalid_ipv4' };
  }
  return null;
}

/**
 * Validate IPv6 address format (simplified)
 */
export function isIPv6(value: string, fieldName: string): ValidationError | null {
  // Basic IPv6 validation - allows full and compressed formats
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$/;
  if (!ipv6Regex.test(value)) {
    return { field: fieldName, message: `${fieldName} must be a valid IPv6 address`, code: 'invalid_ipv6' };
  }
  return null;
}

/**
 * Validate IP address (v4 or v6)
 */
export function isIP(value: string, fieldName: string): ValidationError | null {
  const ipv4Error = isIPv4(value, fieldName);
  const ipv6Error = isIPv6(value, fieldName);

  if (ipv4Error && ipv6Error) {
    return { field: fieldName, message: `${fieldName} must be a valid IP address`, code: 'invalid_ip' };
  }
  return null;
}

/**
 * Validate CIDR notation (e.g., 192.168.1.0/24)
 */
export function isCIDR(value: string, fieldName: string): ValidationError | null {
  const parts = value.split('/');
  if (parts.length !== 2) {
    return { field: fieldName, message: `${fieldName} must be in CIDR notation (e.g., 192.168.1.0/24)`, code: 'invalid_cidr' };
  }

  const [ip, prefix] = parts;
  const prefixNum = parseInt(prefix, 10);

  // Check if prefix is valid
  if (isNaN(prefixNum) || prefixNum < 0) {
    return { field: fieldName, message: `${fieldName} has invalid prefix length`, code: 'invalid_cidr' };
  }

  // Determine if IPv4 or IPv6 and validate
  if (ip.includes(':')) {
    // IPv6
    if (prefixNum > 128) {
      return { field: fieldName, message: `IPv6 prefix must be 0-128`, code: 'invalid_cidr' };
    }
    const ipError = isIPv6(ip, fieldName);
    if (ipError) {
      return { field: fieldName, message: `${fieldName} must be a valid CIDR notation`, code: 'invalid_cidr' };
    }
  } else {
    // IPv4
    if (prefixNum > 32) {
      return { field: fieldName, message: `IPv4 prefix must be 0-32`, code: 'invalid_cidr' };
    }
    const ipError = isIPv4(ip, fieldName);
    if (ipError) {
      return { field: fieldName, message: `${fieldName} must be a valid CIDR notation`, code: 'invalid_cidr' };
    }
  }

  return null;
}

/**
 * Validate IP or CIDR notation
 */
export function isIPOrCIDR(value: string, fieldName: string): ValidationError | null {
  if (value.includes('/')) {
    return isCIDR(value, fieldName);
  }
  return isIP(value, fieldName);
}

/**
 * Validate number is within range
 */
export function inRange(
  value: number,
  min: number,
  max: number,
  fieldName: string
): ValidationError | null {
  if (value < min || value > max) {
    return {
      field: fieldName,
      message: `${fieldName} must be between ${min} and ${max}`,
      code: 'out_of_range',
    };
  }
  return null;
}

/**
 * Validate positive number
 */
export function isPositive(value: number, fieldName: string): ValidationError | null {
  if (value <= 0) {
    return { field: fieldName, message: `${fieldName} must be a positive number`, code: 'not_positive' };
  }
  return null;
}

/**
 * Validate URL format
 */
export function isURL(value: string, fieldName: string): ValidationError | null {
  try {
    new URL(value);
    return null;
  } catch {
    return { field: fieldName, message: `${fieldName} must be a valid URL`, code: 'invalid_url' };
  }
}

/**
 * Validate against a regex pattern
 */
export function matchesPattern(
  value: string,
  pattern: RegExp,
  fieldName: string,
  message?: string
): ValidationError | null {
  if (!pattern.test(value)) {
    return {
      field: fieldName,
      message: message || `${fieldName} has invalid format`,
      code: 'invalid_pattern',
    };
  }
  return null;
}

// ==================== Validation Builder ====================

/**
 * Create a validator function for a specific field
 */
export function createFieldValidator<T>(
  fieldName: string,
  validators: Array<(value: T, field: string) => ValidationError | null>
) {
  return (value: T): ValidationError | null => {
    for (const validator of validators) {
      const error = validator(value, fieldName);
      if (error) return error;
    }
    return null;
  };
}

/**
 * Run multiple validators and collect all errors
 */
export function validateAll(...validators: Array<() => ValidationError | null>): ValidationError[] {
  const errors: ValidationError[] = [];
  for (const validator of validators) {
    const error = validator();
    if (error) errors.push(error);
  }
  return errors;
}

// ==================== Common Form Validators ====================

/**
 * Validate login credentials
 */
export function validateLoginCredentials(
  username: string,
  password: string
): ValidationResult<{ username: string; password: string }> {
  const errors: ValidationError[] = [];

  const usernameRequired = isRequired(username, 'Username');
  if (usernameRequired) errors.push(usernameRequired);
  else {
    const usernameLength = minLength(username, 3, 'Username');
    if (usernameLength) errors.push(usernameLength);
  }

  const passwordRequired = isRequired(password, 'Password');
  if (passwordRequired) errors.push(passwordRequired);
  else {
    const passwordLength = minLength(password, 8, 'Password');
    if (passwordLength) errors.push(passwordLength);
  }

  return {
    valid: errors.length === 0,
    data: errors.length === 0 ? { username, password } : undefined,
    errors,
  };
}

/**
 * Validate IP list entry
 */
export function validateIPEntry(
  ip: string,
  description?: string
): ValidationResult<{ ip: string; description?: string }> {
  const errors: ValidationError[] = [];

  const ipRequired = isRequired(ip, 'IP Address');
  if (ipRequired) errors.push(ipRequired);
  else {
    const ipValid = isIPOrCIDR(ip, 'IP Address');
    if (ipValid) errors.push(ipValid);
  }

  if (description) {
    const descLength = maxLength(description, 255, 'Description');
    if (descLength) errors.push(descLength);
  }

  return {
    valid: errors.length === 0,
    data: errors.length === 0 ? { ip, description } : undefined,
    errors,
  };
}

/**
 * Validate policy form
 */
export function validatePolicy(data: {
  name: string;
  action: string;
  priority?: number;
}): ValidationResult<typeof data> {
  const errors: ValidationError[] = [];

  const nameRequired = isRequired(data.name, 'Name');
  if (nameRequired) errors.push(nameRequired);
  else {
    const nameLength = minLength(data.name, 3, 'Name');
    if (nameLength) errors.push(nameLength);
    const nameMax = maxLength(data.name, 100, 'Name');
    if (nameMax) errors.push(nameMax);
  }

  const actionRequired = isRequired(data.action, 'Action');
  if (actionRequired) errors.push(actionRequired);

  if (data.priority !== undefined) {
    const priorityRange = inRange(data.priority, 1, 1000, 'Priority');
    if (priorityRange) errors.push(priorityRange);
  }

  return {
    valid: errors.length === 0,
    data: errors.length === 0 ? data : undefined,
    errors,
  };
}

/**
 * Validate webhook form
 */
export function validateWebhook(data: {
  url: string;
  events: string[];
}): ValidationResult<typeof data> {
  const errors: ValidationError[] = [];

  const urlRequired = isRequired(data.url, 'URL');
  if (urlRequired) errors.push(urlRequired);
  else {
    const urlValid = isURL(data.url, 'URL');
    if (urlValid) errors.push(urlValid);
  }

  if (!data.events || data.events.length === 0) {
    errors.push({ field: 'Events', message: 'At least one event must be selected', code: 'required' });
  }

  return {
    valid: errors.length === 0,
    data: errors.length === 0 ? data : undefined,
    errors,
  };
}

// ==================== Error Display Helpers ====================

/**
 * Get first error message for a field
 */
export function getFieldError(errors: ValidationError[], field: string): string | undefined {
  return errors.find((e) => e.field.toLowerCase() === field.toLowerCase())?.message;
}

/**
 * Check if field has error
 */
export function hasFieldError(errors: ValidationError[], field: string): boolean {
  return errors.some((e) => e.field.toLowerCase() === field.toLowerCase());
}

/**
 * Convert errors to a map by field name
 */
export function errorsToMap(errors: ValidationError[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const error of errors) {
    if (!map[error.field]) {
      map[error.field] = error.message;
    }
  }
  return map;
}
