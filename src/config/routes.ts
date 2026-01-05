/**
 * Routes Configuration with Feature Flags
 * 
 * Define las rutas disponibles según el entorno y feature flags
 */

import { FEATURES } from './features';

export interface Route {
  path: string;
  label: string;
  enabled: boolean;
  icon?: string;
  category: 'blue-team' | 'red-team' | 'tools' | 'docs';
  description?: string;
}

export const ROUTES: Route[] = [
  // Blue Team (Siempre visible)
  {
    path: '/blue-team',
    label: 'Blue Team Defense',
    enabled: FEATURES.BLUE_TEAM,
    icon: '🛡️',
    category: 'blue-team',
    description: 'Defensive security operations and monitoring'
  },
  
  // Labs Overview Pages - ESTAS SON LAS PRINCIPALES
  {
    path: '/labs/blue-team',
    label: 'Blue Team Labs',
    enabled: true,
    category: 'red-team',
    description: '13 labs de OWASP Top 10 - Vulnerabilidades Web'
  },
  {
    path: '/labs/ai-red-team',
    label: 'AI Red Team Labs',
    enabled: true,
    category: 'red-team',
    description: '10 labs de AI Security - OWASP LLM Top 10'
  },
  
  // Red Team - Traditional (Solo Desarrollo)
  {
    path: '/lab/sqli',
    label: 'SQL Injection',
    enabled: FEATURES.SQLI,
    icon: '💉',
    category: 'red-team',
    description: 'OWASP A03:2021 - Database attacks'
  },
  {
    path: '/lab/xss',
    label: 'Cross-Site Scripting',
    enabled: FEATURES.XSS,
    icon: '⚡',
    category: 'red-team',
    description: 'OWASP A03:2021 - Client-side injection'
  },
  {
    path: '/lab/auth',
    label: 'Broken Authentication',
    enabled: FEATURES.AUTH,
    icon: '🔐',
    category: 'red-team',
    description: 'OWASP A07:2021 - Authentication bypass'
  },
  {
    path: '/lab/sensitive-data',
    label: 'Sensitive Data Exposure',
    enabled: FEATURES.SENSITIVE_DATA,
    icon: '📡',
    category: 'red-team',
    description: 'OWASP A02:2021 - Data leakage'
  },
  {
    path: '/lab/access-control',
    label: 'Broken Access Control',
    enabled: FEATURES.ACCESS_CONTROL,
    icon: '🔑',
    category: 'red-team',
    description: 'OWASP A01:2021 - Authorization flaws'
  },
  {
    path: '/lab/misconfig',
    label: 'Security Misconfiguration',
    enabled: FEATURES.MISCONFIG,
    icon: '⚙️',
    category: 'red-team',
    description: 'OWASP A05:2021 - Configuration errors'
  },
  {
    path: '/lab/command-injection',
    label: 'Command Injection',
    enabled: FEATURES.COMMAND_INJECTION,
    icon: '💻',
    category: 'red-team',
    description: 'OS command execution vulnerabilities'
  },
  {
    path: '/lab/xxe',
    label: 'XML External Entities',
    enabled: FEATURES.XXE,
    icon: '📄',
    category: 'red-team',
    description: 'XML parsing vulnerabilities'
  },
  {
    path: '/lab/ldap',
    label: 'LDAP Injection',
    enabled: FEATURES.LDAP,
    icon: '🌐',
    category: 'red-team',
    description: 'Directory service injection'
  },
  {
    path: '/lab/ssti',
    label: 'Server-Side Template Injection',
    enabled: FEATURES.SSTI,
    icon: '📝',
    category: 'red-team',
    description: 'Template engine exploitation'
  },
  {
    path: '/lab/session-fixation',
    label: 'Session Fixation',
    enabled: FEATURES.SESSION_FIXATION,
    icon: '🍪',
    category: 'red-team',
    description: 'Session management flaws'
  },
  {
    path: '/lab/csp',
    label: 'CSP Bypass',
    enabled: FEATURES.CSP,
    icon: '🔒',
    category: 'red-team',
    description: 'Content Security Policy bypass'
  },
  {
    path: '/lab/file-upload',
    label: 'Unrestricted File Upload',
    enabled: FEATURES.FILE_UPLOAD,
    icon: '📤',
    category: 'red-team',
    description: 'File upload vulnerabilities'
  },
  
  // Tools (Solo Desarrollo)
  {
    path: '/evaluacion-madurez',
    label: 'SSDLC Assessment',
    enabled: FEATURES.SSDLC_ASSESSMENT,
    icon: '📊',
    category: 'tools',
    description: 'Security maturity evaluation tool'
  },
  {
    path: '/matriz-normativas',
    label: 'Compliance Matrix',
    enabled: FEATURES.COMPLIANCE_MATRIX,
    icon: '📋',
    category: 'tools',
    description: 'Regulatory compliance mapping'
  },
  
  // Docs (Solo Desarrollo)
  {
    path: '/guias',
    label: 'SSDLC Guides',
    enabled: FEATURES.SSDLC_GUIDES,
    icon: '📚',
    category: 'docs',
    description: 'Secure development lifecycle guides'
  },
  {
    path: '/docs',
    label: 'API Documentation',
    enabled: FEATURES.API_DOCS,
    icon: '📖',
    category: 'docs',
    description: 'OpenAPI 3.0 documentation'
  },
];

/**
 * Obtiene solo las rutas habilitadas
 */
export function getEnabledRoutes(): Route[] {
  return ROUTES.filter(route => route.enabled);
}

/**
 * Obtiene rutas habilitadas por categoría
 */
export function getRoutesByCategory(category: Route['category']): Route[] {
  return getEnabledRoutes().filter(route => route.category === category);
}

/**
 * Verifica si una ruta está habilitada
 */
export function isRouteEnabled(path: string): boolean {
  const route = ROUTES.find(r => r.path === path);
  return route ? route.enabled : false;
}
