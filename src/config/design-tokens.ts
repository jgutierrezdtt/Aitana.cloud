/**
 * Design Tokens para temas
 * Sistema centralizado de colores, tipografía y espaciado
 * 
 * USO:
 * import { themeClasses } from '@/config/design-tokens';
 * <div className={themeClasses.card.background}>
 */

export const themeClasses = {
  // BACKGROUNDS
  background: {
    primary: 'bg-white dark:bg-[#0A0525]',           // Fondo principal
    secondary: 'bg-gray-50 dark:bg-[#1B1663]',      // Fondo secundario
    tertiary: 'bg-gray-100 dark:bg-[#120d4f]',      // Fondo terciario
    elevated: 'bg-white dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525]',
  },

  // CARDS
  card: {
    background: 'bg-gray-50 dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525]',
    border: 'border border-gray-300 dark:border-blue-500/20',
    borderHover: 'hover:border-gray-400 dark:hover:border-blue-400/50',
    shadow: 'shadow-md dark:shadow-[0_0_30px_rgba(59,130,246,0.15)]',
    shadowHover: 'hover:shadow-lg dark:hover:shadow-[0_0_50px_rgba(59,130,246,0.3)]',
  },

  // TEXT COLORS
  text: {
    primary: 'text-gray-900 dark:text-white',        // Títulos principales
    secondary: 'text-gray-700 dark:text-white/80',   // Texto cuerpo
    muted: 'text-gray-600 dark:text-white/70',       // Texto secundario
    tertiary: 'text-gray-500 dark:text-white/60',    // Texto desenfatizado
    accent: {
      blue: 'text-gray-700 dark:text-blue-400',
      purple: 'text-gray-700 dark:text-purple-400',
      pink: 'text-gray-700 dark:text-pink-400',
      green: 'text-green-600 dark:text-accent-green',
      red: 'text-red-700 dark:text-red-300',
    }
  },

  // BORDERS
  border: {
    default: 'border-gray-300 dark:border-white/10',
    hover: 'hover:border-gray-400 dark:hover:border-blue-500/50',
    accent: {
      blue: 'border-gray-300 dark:border-blue-500/30',
      purple: 'border-gray-300 dark:border-purple-500/30',
      pink: 'border-gray-300 dark:border-pink-500/30',
    }
  },

  // BUTTONS
  button: {
    primary: 'bg-gray-800 dark:bg-gradient-to-r dark:from-blue-600 dark:to-indigo-600 hover:bg-gray-700 dark:hover:from-blue-500 dark:hover:to-indigo-500 text-white',
    secondary: 'bg-gray-100 dark:bg-purple-500/20 border-2 border-gray-300 dark:border-purple-500/50 text-gray-900 dark:text-purple-300',
    outline: 'bg-transparent border-2 border-gray-300 dark:border-blue-500/30 text-gray-900 dark:text-blue-400 hover:bg-gray-50 dark:hover:bg-blue-500/10',
  },

  // BADGES
  badge: {
    default: 'bg-gray-100 dark:bg-blue-500/10 border border-gray-300 dark:border-blue-500/30 text-gray-700 dark:text-accent-blue',
    purple: 'bg-gray-100 dark:bg-purple-500/10 border border-gray-300 dark:border-purple-500/30 text-gray-700 dark:text-accent-purple',
    success: 'bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/30 text-green-700 dark:text-green-400',
    danger: 'bg-red-50 dark:bg-red-500/20 border border-red-200 dark:border-red-500/40 text-red-700 dark:text-red-300',
    warning: 'bg-gray-100 dark:bg-amber-500/10 border border-gray-300 dark:border-amber-500/40 text-gray-700 dark:text-amber-300',
  },

  // ICONS
  icon: {
    container: {
      default: 'bg-gray-100 dark:bg-blue-500/20 border border-gray-300 dark:border-blue-400/30',
      purple: 'bg-gray-100 dark:bg-purple-500/20 border border-gray-300 dark:border-purple-500/30',
      gradient: 'bg-gray-100 dark:bg-gradient-to-br dark:from-blue-500/30 dark:to-purple-500/20 border border-gray-200 dark:border-blue-400/30',
    },
    color: {
      default: 'text-gray-700 dark:text-blue-400',
      purple: 'text-gray-700 dark:text-purple-400',
      green: 'text-green-600 dark:text-accent-green',
      muted: 'text-gray-400 dark:text-blue-400/30',
    }
  },

  // HOVER EFFECTS
  hover: {
    card: 'hover:scale-[1.02] transition-all duration-300',
    icon: 'group-hover:scale-110 transition-transform',
    glow: 'hover:shadow-2xl dark:hover:shadow-[0_0_50px_rgba(59,130,246,0.3)]',
  },

  // GRADIENTS
  gradient: {
    cardOverlay: 'absolute inset-0 bg-gradient-to-br from-gray-100 to-transparent dark:from-blue-600/10 dark:via-purple-600/5 dark:to-transparent opacity-0 group-hover:opacity-100 transition-opacity',
    heroFeatures: 'bg-gradient-to-b from-gray-100 to-white dark:from-[#0A0525] dark:to-[#1B1663]',
    buttonShine: 'absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent',
  },

  // OVERLAYS
  overlay: {
    card: 'absolute inset-0 bg-gradient-to-br from-gray-50 to-transparent dark:from-purple-600/10 dark:to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300',
    glow: 'absolute -inset-1 bg-gradient-to-r from-gray-300 to-gray-400 dark:from-blue-600 dark:to-purple-600 rounded-cyber opacity-0 dark:opacity-20 group-hover:opacity-30 dark:group-hover:opacity-100 blur transition-all duration-500',
  }
};

// FUNCIÓN HELPER: Combinar clases de forma segura
export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}

// EJEMPLO DE USO:
/*
import { themeClasses, cn } from '@/config/design-tokens';

// Uso básico
<div className={themeClasses.card.background}>...</div>

// Combinando con cn()
<div className={cn(
  themeClasses.card.background,
  themeClasses.card.border,
  themeClasses.card.shadow,
  'p-6 rounded-lg'
)}>
  <h3 className={themeClasses.text.primary}>Título</h3>
  <p className={themeClasses.text.secondary}>Descripción</p>
</div>

// Con props condicionales
<div className={cn(
  themeClasses.button.primary,
  isActive && 'ring-2 ring-blue-500',
  'px-4 py-2'
)}>
  Click me
</div>
*/

export default themeClasses;
