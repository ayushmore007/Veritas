export const colors = {
  bg: '#070a12',
  card: '#0f1626',
  cardAlt: '#141c30',
  border: 'rgba(255,255,255,0.09)',
  text: '#f3f4f6',
  textDim: '#9ca3af',
  textMuted: '#6b7280',
  cyan: '#06b6d4',
  emerald: '#10b981',
  amber: '#f59e0b',
  crimson: '#ef4444',
  violet: '#8b5cf6',
};

export const space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24 };

export function statusColor(status: string): string {
  switch (status) {
    case 'passed':
    case 'defended':
      return colors.emerald;
    case 'warning':
      return colors.amber;
    case 'failed':
      return colors.crimson;
    default:
      return colors.textDim;
  }
}

export function scoreColor(score: number): string {
  if (score >= 80) return colors.emerald;
  if (score >= 55) return colors.amber;
  return colors.crimson;
}
