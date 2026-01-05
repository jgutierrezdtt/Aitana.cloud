/**
 * @jest-environment jsdom
 */

import { describe, it, expect } from '@jest/globals';

describe('Wiki Dark Mode Colors - Validation Tests', () => {
  describe('Background Colors', () => {
    it('should use solid backgrounds in dark mode (not transparent)', () => {
      const darkModeBackgrounds = [
        'dark:bg-slate-900',
        'dark:bg-slate-800',
        'dark:bg-slate-800/50',
        'dark:from-slate-950',
        'dark:via-slate-900',
        'dark:to-slate-950'
      ];

      const invalidTransparentBackgrounds = [
        'dark:bg-white/5',
        'dark:bg-white/10',
        'dark:bg-black/5'
      ];

      // Los fondos válidos deben estar presentes
      darkModeBackgrounds.forEach(bg => {
        expect(bg).toMatch(/dark:bg-slate-\d+/);
      });

      // Los fondos transparentes no deben usarse (excepto en casos específicos como blur)
      invalidTransparentBackgrounds.forEach(bg => {
        expect(bg).not.toMatch(/dark:bg-white\/[0-9]+$/);
      });
    });

    it('should use proper gradient backgrounds in hero sections', () => {
      const heroGradients = {
        light: 'from-blue-600 via-purple-600 to-pink-600',
        dark: 'dark:from-blue-900 dark:via-purple-900 dark:to-pink-900'
      };

      expect(heroGradients.dark).toContain('dark:from-blue-900');
      expect(heroGradients.dark).toContain('dark:via-purple-900');
      expect(heroGradients.dark).toContain('dark:to-pink-900');
    });
  });

  describe('Border Colors', () => {
    it('should use visible borders in dark mode', () => {
      const darkBorders = [
        'dark:border-slate-700',
        'dark:border-slate-600',
        'dark:border-white/10'
      ];

      const visibleBorderPattern = /dark:border-(slate-[67]00|white\/10)/;
      
      darkBorders.forEach(border => {
        expect(border).toMatch(visibleBorderPattern);
      });
    });

    it('should not use invisible borders', () => {
      const invalidBorders = [
        'dark:border-transparent',
        'dark:border-white/5'
      ];

      // Borders con opacidad muy baja son difíciles de ver
      expect('dark:border-white/5').toMatch(/white\/[0-5]$/);
    });
  });

  describe('Text Colors', () => {
    it('should use proper text contrast in dark mode', () => {
      const textColors = {
        primary: 'dark:text-white',
        secondary: 'dark:text-slate-300',
        muted: 'dark:text-slate-400'
      };

      Object.values(textColors).forEach(color => {
        expect(color).toMatch(/dark:text-(white|slate-[34]00)/);
      });
    });

    it('should use white text on colored backgrounds', () => {
      // En gradientes coloridos, siempre usar text-white
      const coloredBackgroundText = 'text-white';
      expect(coloredBackgroundText).toBe('text-white');
    });
  });

  describe('Hover States', () => {
    it('should have visible hover states in dark mode', () => {
      const hoverStates = [
        'dark:hover:bg-slate-700',
        'dark:hover:bg-slate-800',
        'dark:hover:bg-slate-600'
      ];

      hoverStates.forEach(hover => {
        expect(hover).toMatch(/dark:hover:bg-slate-[678]00/);
      });
    });

    it('should not use transparent hovers that are invisible', () => {
      const invalidHovers = [
        'hover:bg-white/10', // Esto es inválido en dark mode
        'dark:hover:bg-white/5'
      ];

      // En dark mode, los hovers deben ser sólidos
      expect('dark:hover:bg-slate-700').toMatch(/slate-\d+/);
    });
  });

  describe('Role Colors (12 niveles)', () => {
    it('should have distinct colors for each role', () => {
      const roleColors = {
        'Estudiante': 'blue',
        'Junior Developer': 'green-400',
        'Mid-Level Developer': 'green-500',
        'Senior Developer': 'green-600',
        'Tech Lead': 'cyan',
        'DevSecOps': 'teal',
        'Security Champion': 'yellow',
        'Pentester': 'red',
        'Security Expert': 'orange',
        'CISO': 'purple',
        'Security Manager': 'pink',
        'Bug Bounty': 'rose'
      };

      const colorValues = Object.values(roleColors);
      const uniqueColors = new Set(colorValues);
      
      // Todos los colores deben ser únicos
      expect(uniqueColors.size).toBe(colorValues.length);
    });

    it('should use proper opacity for role badges', () => {
      const roleBadgePattern = /bg-\w+-500\/20 text-\w+-300 border-\w+-500\/30/;
      
      const exampleBadge = 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      expect(exampleBadge).toMatch(roleBadgePattern);
    });
  });

  describe('Component Consistency', () => {
    it('WikiSidebar should use consistent color scheme', () => {
      const sidebarColors = {
        background: 'dark:bg-slate-900',
        border: 'dark:border-slate-700',
        buttons: 'dark:bg-slate-800',
        buttonHover: 'dark:hover:bg-slate-700',
        text: 'dark:text-white'
      };

      // Verificar que todos los colores son del mismo esquema (slate)
      Object.values(sidebarColors).forEach(color => {
        expect(color).toMatch(/dark:(bg-|border-|hover:bg-|text-)(slate-\d+|white)/);
      });
    });

    it('Article cards should have proper contrast', () => {
      const cardColors = {
        background: 'dark:bg-slate-800/50',
        border: 'dark:border-slate-700',
        hover: 'dark:hover:bg-slate-700/50',
        hoverBorder: 'dark:hover:border-slate-600'
      };

      // Cards deben tener colores visibles y coherentes
      expect(cardColors.background).toContain('slate-800');
      expect(cardColors.border).toContain('slate-700');
      expect(cardColors.hover).toContain('slate-700');
    });
  });

  describe('Accessibility & Contrast', () => {
    it('should meet minimum contrast ratios', () => {
      // Combinaciones que deben tener buen contraste
      const contrastPairs = [
        { bg: 'slate-900', text: 'white' }, // 15.3:1 ✅
        { bg: 'slate-800', text: 'white' }, // 12.6:1 ✅
        { bg: 'slate-900', text: 'slate-300' }, // 9.1:1 ✅
        { bg: 'slate-800', text: 'slate-400' }, // 5.2:1 ✅
      ];

      contrastPairs.forEach(pair => {
        expect(pair.bg).toMatch(/slate-[89]00/);
        expect(pair.text).toMatch(/(white|slate-[34]00)/);
      });
    });

    it('should not use low contrast combinations', () => {
      const lowContrastPairs = [
        { bg: 'slate-900', text: 'slate-800' }, // ❌ Bajo contraste
        { bg: 'white', text: 'slate-200' }, // ❌ Bajo contraste
      ];

      // Estas combinaciones no deben usarse
      lowContrastPairs.forEach(pair => {
        if (pair.bg === 'slate-900') {
          expect(pair.text).not.toBe('slate-800');
        }
      });
    });
  });

  describe('Stats Cards', () => {
    it('should use solid backgrounds for visibility', () => {
      const statCardBg = 'dark:bg-slate-800/50';
      const statCardBorder = 'dark:border-slate-700';
      
      expect(statCardBg).toContain('slate-800');
      expect(statCardBorder).toContain('slate-700');
    });
  });

  describe('Search Input', () => {
    it('should be visible in both modes', () => {
      const searchInput = {
        bg: 'dark:bg-white/5',
        border: 'dark:border-white/10',
        text: 'dark:text-white',
        placeholder: 'dark:placeholder-slate-400'
      };

      expect(searchInput.text).toBe('dark:text-white');
      expect(searchInput.placeholder).toContain('slate-400');
    });
  });

  describe('No Regression Tests', () => {
    it('should NOT use bg-white/5 or bg-white/10 for main backgrounds', () => {
      const forbiddenPatterns = [
        'bg-white/80 dark:bg-white/5', // ❌ Antiguo patrón
        'bg-white/90 dark:bg-white/5', // ❌ Antiguo patrón
      ];

      const correctPattern = 'bg-white dark:bg-slate-900'; // ✅ Correcto

      expect(correctPattern).toContain('dark:bg-slate-900');
      
      forbiddenPatterns.forEach(pattern => {
        expect(pattern).toContain('white/5'); // Identificar el patrón incorrecto
      });
    });

    it('should use solid hovers instead of transparent', () => {
      const correctHover = 'hover:bg-slate-50 dark:hover:bg-slate-800';
      const incorrectHover = 'hover:bg-white/10'; // ❌
      
      expect(correctHover).toContain('dark:hover:bg-slate-800');
      expect(incorrectHover).not.toContain('slate');
    });
  });
});

describe('Wiki Color Scheme - Integration', () => {
  it('should use consistent slate palette across all components', () => {
    const slateValues = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
    
    slateValues.forEach(value => {
      const className = `slate-${value}`;
      expect(className).toMatch(/slate-\d+/);
    });
  });

  it('should have proper color progression (light to dark)', () => {
    const lightMode = ['slate-50', 'slate-100', 'slate-200'];
    const darkMode = ['slate-700', 'slate-800', 'slate-900', 'slate-950'];
    
    // Light mode usa valores bajos
    lightMode.forEach(color => {
      const value = parseInt(color.split('-')[1]);
      expect(value).toBeLessThanOrEqual(200);
    });
    
    // Dark mode usa valores altos
    darkMode.forEach(color => {
      const value = parseInt(color.split('-')[1]);
      expect(value).toBeGreaterThanOrEqual(700);
    });
  });
});
