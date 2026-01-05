import type { NextConfig } from "next";
import createNextIntlPlugin from 'next-intl/plugin';

const withNextIntl = createNextIntlPlugin();

const nextConfig: NextConfig = {
  // Optimización para despliegues en Vercel (reduce tamaño y evita errores de symlinks)
  output: 'standalone',

  // Configuración de Turbopack (requerido en Next.js 16+)
  turbopack: {},
  
  // Configurar dominios de imágenes permitidos
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'images.unsplash.com',
        port: '',
        pathname: '/**',
      },
    ],
  },
  
  typescript: {
    // Ignorar errores de TypeScript durante el build si es necesario
    ignoreBuildErrors: true,
  },
  
  // Headers de seguridad débiles para vulnerabilidades educativas
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // ❌ VULNERABILIDAD: CSP muy permisiva para permitir ataques XSS
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self' 'unsafe-inline' 'unsafe-eval' *; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; style-src 'self' 'unsafe-inline' *;"
          },
          // ❌ VULNERABILIDAD: Permitir embebido en frames (clickjacking)
          {
            key: 'X-Frame-Options',
            value: 'ALLOWALL'
          },
          // Warning educativo
          {
            key: 'X-Educational-Warning',
            value: 'VULNERABLE-BY-DESIGN-FOR-EDUCATIONAL-PURPOSES-ONLY'
          },
          // ❌ VULNERABILIDAD: Información sensible en headers
          {
            key: 'X-Debug-Info',
            value: 'version=vulnerable-1.0,environment=lab'
          },
          // ❌ VULNERABILIDAD: Deshabilitar protecciones del navegador
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          }
        ],
      },
    ]
  }
};

export default withNextIntl(nextConfig);
