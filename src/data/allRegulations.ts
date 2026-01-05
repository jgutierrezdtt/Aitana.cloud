// Consolidador de todas las normativas (originales + adicionales)
import { regulationsData as baseRegulations } from './regulations';
import { additionalRegulationsData } from './additionalRegulations';
import type { Regulation } from './regulations';

// Combinar todas las normativas
export const allRegulationsData: Record<string, Regulation> = {
  ...baseRegulations,
  ...additionalRegulationsData
};

// Re-exportar el tipo
export type { Regulation } from './regulations';

// Helper para obtener regulaciones por categoría
export const getRegulationsByCategory = (category: string) => {
  return Object.values(allRegulationsData).filter(reg => reg.category === category);
};

// Helper para obtener regulaciones por fase SSDLC
export const getRegulationsByPhase = (phase: string) => {
  return Object.values(allRegulationsData).filter(reg =>
    reg.keyRequirements.some(req => req.ssdlcPhases.includes(phase))
  );
};

// Helper para obtener regulaciones obligatorias
export const getMandatoryRegulations = () => {
  return Object.values(allRegulationsData).filter(reg => reg.mandatoryCompliance);
};

// Helper para obtener regulaciones por jurisdicción
export const getRegulationsByJurisdiction = (jurisdiction: string) => {
  return Object.values(allRegulationsData).filter(reg => 
    reg.jurisdiction.includes(jurisdiction)
  );
};

// Exportar categorías completas
export const regulationCategories = [
  { id: 'privacy', name: 'Privacidad', icon: '🔒', color: 'blue' },
  { id: 'security', name: 'Seguridad', icon: '🛡️', color: 'purple' },
  { id: 'financial', name: 'Financiero', icon: '💳', color: 'green' },
  { id: 'healthcare', name: 'Salud', icon: '🏥', color: 'red' },
  { id: 'european', name: 'Marco Europeo', icon: '🇪🇺', color: 'blue' },
  { id: 'spanish', name: 'Marco Español', icon: '🇪🇸', color: 'yellow' },
  { id: 'industrial', name: 'Industrial/OT', icon: '🏭', color: 'orange' },
  { id: 'automotive', name: 'Automotriz', icon: '🚗', color: 'cyan' },
  { id: 'ai', name: 'Inteligencia Artificial', icon: '🤖', color: 'pink' },
  { id: 'general', name: 'General', icon: '📋', color: 'gray' }
] as const;

// Estadísticas
export const getRegulationsStats = () => {
  const all = Object.values(allRegulationsData);
  return {
    total: all.length,
    mandatory: all.filter(r => r.mandatoryCompliance).length,
    withCertification: all.filter(r => r.certificationRequired).length,
    totalArticles: all.reduce((sum, r) => sum + r.keyRequirements.length, 0),
    byCategory: regulationCategories.map(cat => ({
      ...cat,
      count: all.filter(r => r.category === cat.id).length
    }))
  };
};
