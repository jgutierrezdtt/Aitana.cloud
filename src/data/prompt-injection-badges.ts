import { Badge } from '@/types/prompt-injection';

/**
 * Badges and Achievements for Prompt Injection Lab
 */

export const badges: Badge[] = [
  // ==================== BEGINNER BADGES ====================
  {
    id: 'first-jailbreak',
    name: '🔓 Primer Jailbreak',
    description: 'Completaste tu primer bypass de seguridad',
    icon: '🔓',
    category: 'jailbreak',
    requirement: 'Completa cualquier desafío de jailbreak',
    rarity: 'common',
  },
  {
    id: 'prompt-leaker',
    name: '🕵️ Espía de Prompts',
    description: 'Extrajiste tu primer system prompt',
    icon: '🕵️',
    category: 'prompt-leaking',
    requirement: 'Completa un desafío de prompt-leaking',
    rarity: 'common',
  },

  // ==================== INTERMEDIATE BADGES ====================
  {
    id: 'data-thief',
    name: '💎 Ladrón de Datos',
    description: 'Robaste información confidencial exitosamente',
    icon: '💎',
    category: 'data-extraction',
    requirement: 'Completa 3 desafíos de data-extraction',
    rarity: 'rare',
  },
  {
    id: 'role-master',
    name: '🎭 Maestro del Engaño',
    description: 'Manipulaste la IA para asumir roles prohibidos',
    icon: '🎭',
    category: 'role-playing',
    requirement: 'Completa todos los desafíos de role-playing',
    rarity: 'rare',
  },

  // ==================== ADVANCED BADGES ====================
  {
    id: 'indirect-ninja',
    name: '🥷 Ninja de Inyección',
    description: 'Dominaste las inyecciones indirectas',
    icon: '🥷',
    category: 'indirect-injection',
    requirement: 'Completa 2 desafíos de indirect-injection',
    rarity: 'epic',
  },
  {
    id: 'chain-attacker',
    name: '⛓️ Atacante en Cadena',
    description: 'Ejecutaste un ataque multi-paso perfecto',
    icon: '⛓️',
    category: 'multi-step',
    requirement: 'Completa un desafío multi-step sin fallos',
    rarity: 'epic',
  },

  // ==================== EXPERT BADGES ====================
  {
    id: 'adversarial-god',
    name: '🧠 Dios Adversarial',
    description: 'Confundiste al modelo con técnicas avanzadas',
    icon: '🧠',
    category: 'adversarial',
    requirement: 'Completa todos los desafíos adversariales',
    rarity: 'legendary',
  },
  {
    id: 'master-hacker',
    name: '👑 Gran Maestro',
    description: 'Completaste el desafío maestro',
    icon: '👑',
    category: 'special',
    requirement: 'Completa el desafío nivel 8',
    rarity: 'legendary',
  },

  // ==================== SPECIAL ACHIEVEMENTS ====================
  {
    id: 'speedrunner',
    name: '⚡ Speedrunner',
    description: 'Completaste un desafío en menos de 2 minutos',
    icon: '⚡',
    category: 'special',
    requirement: 'Tiempo < 2 minutos en cualquier desafío',
    rarity: 'rare',
  },
  {
    id: 'perfectionist',
    name: '💯 Perfeccionista',
    description: 'Completaste todos los desafíos',
    icon: '💯',
    category: 'special',
    requirement: 'Completa los 8 niveles',
    rarity: 'legendary',
  },
  {
    id: 'no-hints',
    name: '🎯 Sin Ayuda',
    description: 'Completaste un desafío difícil sin usar pistas',
    icon: '🎯',
    category: 'special',
    requirement: 'Completa nivel ≥5 sin ver hints',
    rarity: 'epic',
  },
  {
    id: 'creative-mind',
    name: '🌟 Mente Creativa',
    description: 'Encontraste una solución alternativa no prevista',
    icon: '🌟',
    category: 'special',
    requirement: 'Usa técnica no documentada en hints',
    rarity: 'epic',
  },
  {
    id: 'streak-7',
    name: '🔥 Racha de Fuego',
    description: 'Completaste desafíos durante 7 días seguidos',
    icon: '🔥',
    category: 'special',
    requirement: 'Racha de 7 días consecutivos',
    rarity: 'rare',
  },
  {
    id: 'helper',
    name: '🤝 Colaborador',
    description: 'Ayudaste a otros usuarios en el foro',
    icon: '🤝',
    category: 'special',
    requirement: 'Responde 5 preguntas en discusiones',
    rarity: 'common',
  },
];

// Helper to check if user earned a badge
export function checkBadgeEarned(
  badgeId: string,
  userProgress: {
    completedChallenges: string[];
    attempts: any[];
    currentStreak: number;
  }
): boolean {
  const badge = badges.find(b => b.id === badgeId);
  if (!badge) return false;

  switch (badgeId) {
    case 'first-jailbreak':
      return userProgress.completedChallenges.some(id => id.startsWith('jb-'));
    
    case 'prompt-leaker':
      return userProgress.completedChallenges.some(id => id.startsWith('pl-'));
    
    case 'data-thief':
      return userProgress.completedChallenges.filter(id => id.startsWith('de-')).length >= 3;
    
    case 'role-master':
      return userProgress.completedChallenges.filter(id => id.startsWith('rp-')).length >= 2;
    
    case 'indirect-ninja':
      return userProgress.completedChallenges.filter(id => id.startsWith('ii-')).length >= 2;
    
    case 'chain-attacker':
      return userProgress.completedChallenges.some(id => id.startsWith('ms-'));
    
    case 'adversarial-god':
      return userProgress.completedChallenges.filter(id => id.startsWith('adv-')).length >= 1;
    
    case 'master-hacker':
      return userProgress.completedChallenges.includes('master-001');
    
    case 'speedrunner':
      return userProgress.attempts.some(a => a.executionTime < 120000); // 2 min
    
    case 'perfectionist':
      return userProgress.completedChallenges.length === 8;
    
    case 'streak-7':
      return userProgress.currentStreak >= 7;
    
    default:
      return false;
  }
}

// Get badge rarity color
export function getBadgeColor(rarity: Badge['rarity']): string {
  switch (rarity) {
    case 'common': return 'text-gray-600 bg-gray-100';
    case 'rare': return 'text-blue-600 bg-blue-100';
    case 'epic': return 'text-purple-600 bg-purple-100';
    case 'legendary': return 'text-yellow-600 bg-gradient-to-r from-yellow-100 to-orange-100';
  }
}
