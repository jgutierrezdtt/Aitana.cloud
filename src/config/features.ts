/**
 * Feature Flags Configuration
 * 
 * Controla qué características están habilitadas en cada entorno:
 * - Development: Todas las features habilitadas
 * - Production: Solo Blue Team + AI Red Team Lab
 */

export const FEATURES = {
  // Blue Team Labs (Production + Development)
  BLUE_TEAM: true, // Siempre habilitado
  
  // Red Team Labs - AI (Production + Development)
  RED_TEAM_AI: true, // Siempre habilitado
  PROMPT_INJECTION: true, // Siempre habilitado
  
  // Red Team Labs - Traditional (Solo Development)
  RED_TEAM_TRADITIONAL: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  SQLI: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  XSS: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  AUTH: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  SENSITIVE_DATA: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  ACCESS_CONTROL: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  MISCONFIG: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  COMMAND_INJECTION: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  XXE: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  LDAP: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  SSTI: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  SESSION_FIXATION: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  CSP: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  FILE_UPLOAD: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
  
  // Other Features (Solo Development)
  SSDLC_ASSESSMENT: process.env.NEXT_PUBLIC_ENABLE_SSDLC === 'true',
  API_DOCS: process.env.NEXT_PUBLIC_ENABLE_DOCS === 'true',
  COMPLIANCE_MATRIX: process.env.NEXT_PUBLIC_ENABLE_MATRIX === 'true',
  SSDLC_GUIDES: process.env.NEXT_PUBLIC_ENABLE_GUIDES === 'true',
  
  // Analytics
  ANALYTICS: process.env.NEXT_PUBLIC_ANALYTICS === 'true',
} as const;

/**
 * Verifica si una feature está habilitada
 * @param feature - Nombre de la feature
 * @returns boolean - true si está habilitada
 */
export function isFeatureEnabled(feature: keyof typeof FEATURES): boolean {
  return FEATURES[feature];
}

/**
 * Obtiene el entorno actual
 * @returns 'development' | 'production'
 */
export function getEnvironment(): 'development' | 'production' {
  return (process.env.NEXT_PUBLIC_ENV as 'development' | 'production') || 'development';
}

/**
 * Verifica si estamos en producción
 * @returns boolean
 */
export function isProduction(): boolean {
  return getEnvironment() === 'production';
}

/**
 * Verifica si estamos en desarrollo
 * @returns boolean
 */
export function isDevelopment(): boolean {
  return getEnvironment() === 'development';
}
