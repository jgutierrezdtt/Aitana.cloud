/**
 * Environment Badge Component
 * 
 * Muestra un badge flotante indicando el entorno actual.
 * Solo visible en modo desarrollo para ayudar a los developers.
 */

'use client';

import { getEnvironment, isDevelopment } from '@/config/features';
import { useState, useEffect } from 'react';

export default function EnvironmentBadge() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Solo renderizar en cliente
  if (!mounted) return null;

  const env = getEnvironment();
  const showBadge = isDevelopment();

  // No mostrar en producción
  if (!showBadge) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 pointer-events-none">
      <div className="bg-gradient-to-r from-green-500 to-emerald-500 text-white px-4 py-2 rounded-full shadow-lg font-urbanist font-bold text-sm flex items-center gap-2 pointer-events-auto">
        <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
        <span>ENV: {env.toUpperCase()}</span>
      </div>
    </div>
  );
}
