'use client';

import Image from 'next/image';
import Link from 'next/link';
import { useTheme } from '@/hooks/useTheme';

interface LogoProps {
  variant?: 'header' | 'footer' | 'navigator';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export default function Logo({ variant = 'navigator', size = 'md', className = '' }: LogoProps) {
  const { effectiveTheme } = useTheme();
  
  // Determinar qué logo usar según variante y tema
  const getLogoSrc = () => {
    if (variant === 'footer') {
      // Footer cambia según tema
      return effectiveTheme === 'dark'
        ? '/logos/logo-footer.png'
        : '/logos/logo-footer-black.png';
    }
    
    if (variant === 'navigator') {
      // Navigator es para favicon del navegador, siempre blanco
      return '/logos/logo-navigator-white.png';
    }
    
    // Variante 'header' - cambia con el tema (para barra de navegación)
    return effectiveTheme === 'dark'
      ? '/logos/logo-white.png'
      : '/logos/logo-black.png';
  };
  
  // Dimensiones según tamaño
  const dimensions = {
    sm: { width: 120, height: 30 },
    md: { width: 180, height: 45 },
    lg: { width: 240, height: 60 }
  };
  
  const { width, height } = dimensions[size];
  
  const logoSrc = getLogoSrc();
  
  return (
    <Link href="/" className={`inline-block ${className}`}>
      <Image
        key={`${variant}-${effectiveTheme}`}
        src={logoSrc}
        alt="Aitana Security Lab - Enterprise Security Training Platform"
        width={width}
        height={height}
        priority
        className="transition-opacity hover:opacity-80"
        onError={(e) => {
          // Fallback a logo white por defecto si falla la carga
          e.currentTarget.src = '/logos/logo-white.png';
        }}
      />
    </Link>
  );
}
