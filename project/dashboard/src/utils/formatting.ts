/**
 * Shared formatting utilities
 *
 * Consolidated from duplicated definitions across pages and components.
 */

export function formatBytes(bytes: number | undefined | null): string {
  if (!bytes || bytes === 0 || !isFinite(bytes)) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function formatNumber(num: number | undefined | null): string {
  if (num === undefined || num === null) return '0';
  if (num >= 1000000000) return (num / 1000000000).toFixed(2) + 'B';
  if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

export function formatPPS(pps: number): string {
  if (pps >= 1000000) return (pps / 1000000).toFixed(2) + ' Mpps';
  if (pps >= 1000) return (pps / 1000).toFixed(1) + ' Kpps';
  return pps.toFixed(0) + ' pps';
}

export function formatBPS(bps: number): string {
  if (bps >= 1000000000) return (bps / 1000000000).toFixed(2) + ' Gbps';
  if (bps >= 1000000) return (bps / 1000000).toFixed(2) + ' Mbps';
  if (bps >= 1000) return (bps / 1000).toFixed(1) + ' Kbps';
  return bps.toFixed(0) + ' bps';
}

export function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}
