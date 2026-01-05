/**
 * Test para verificar consistencia de temas
 * Asegura que NO haya elementos con bg-white sin alternativa dark
 */

import { readFileSync } from 'fs';
import { join } from 'path';

describe('Theme Consistency Tests', () => {
  const pageContent = readFileSync(
    join(process.cwd(), 'src/app/page.tsx'),
    'utf-8'
  );

  test('NO debe haber bg-white sin dark:bg-* en page.tsx', () => {
    // Buscar patrones de bg-white que NO tengan dark:bg-
    const whiteBackgroundPattern = /className="[^"]*bg-white(?!\s+dark:bg-)/g;
    const matches = pageContent.match(whiteBackgroundPattern);

    if (matches) {
      console.error('❌ Encontrados bg-white sin dark mode:', matches);
    }

    expect(matches).toBeNull();
  });

  test('Todas las cards deben tener bg-gray-* en light mode', () => {
    // Verificar que las cards usen grises
    const cardPatterns = [
      /bg-gray-50\s+dark:bg-/g,
      /bg-gray-100\s+dark:bg-/g,
      /bg-gray-200\s+dark:bg-/g,
    ];

    const foundGrayBackgrounds = cardPatterns.some(pattern => 
      pattern.test(pageContent)
    );

    expect(foundGrayBackgrounds).toBe(true);
  });

  test('Hero features deben usar bg-gray-* no bg-white', () => {
    // Buscar la sección de hero features
    const heroFeaturesSection = pageContent.match(
      /Hero Features[\s\S]*?<\/div>\s*<\/div>\s*<\/div>\s*<\/section>/
    );

    if (heroFeaturesSection) {
      const hasBgWhite = /bg-white(?!\s+dark:)/.test(heroFeaturesSection[0]);
      expect(hasBgWhite).toBe(false);
    }
  });

  test('Service cards deben usar bg-gray-50 no bg-white', () => {
    // Buscar service cards
    const serviceCardsPattern = /services\.map\(([\s\S]*?)AnimatedSection>/;
    const serviceCardsSection = pageContent.match(serviceCardsPattern);

    if (serviceCardsSection) {
      const hasBgWhite = /className="[^"]*bg-white/.test(serviceCardsSection[0]);
      expect(hasBgWhite).toBe(false);

      const hasBgGray = /bg-gray-50/.test(serviceCardsSection[0]);
      expect(hasBgGray).toBe(true);
    }
  });

  test('AI Lab section debe usar bg-gray-50 no bg-white', () => {
    // Buscar AI Red Team Lab
    const aiLabPattern = /AI Red Team Lab Feature[\s\S]*?<\/section>/;
    const aiLabSection = pageContent.match(aiLabPattern);

    if (aiLabSection) {
      // Verificar container principal
      const containerHasBgGray = /overflow-hidden\s+bg-gray-50/.test(aiLabSection[0]);
      expect(containerHasBgGray).toBe(true);

      // Verificar cards de features
      const featureCardsHaveBgGray = /key={idx}\s+className="[^"]*bg-gray-50/.test(aiLabSection[0]);
      expect(featureCardsHaveBgGray).toBe(true);
    }
  });

  test('Stats cards deben usar bg-gray-50 no bg-white', () => {
    const statsPattern = /{ value: "8", label: "Niveles" }[\s\S]*?<\/div>/;
    const statsSection = pageContent.match(statsPattern);

    if (statsSection) {
      const hasBgGray = /bg-gray-50/.test(statsSection[0]);
      expect(hasBgGray).toBe(true);
    }
  });

  test('Verificar colores de texto en light mode son grises', () => {
    // Text colors deben ser text-gray-*
    const lightTextColors = [
      'text-gray-900', // Headings
      'text-gray-700', // Primary text
      'text-gray-600', // Secondary text
      'text-gray-500', // Muted text
    ];

    lightTextColors.forEach(color => {
      const hasColor = pageContent.includes(color);
      expect(hasColor).toBe(true);
    });
  });

  test('NO debe haber colores brillantes en light mode', () => {
    // Patrones que NO deben aparecer SIN dark: prefix
    const forbiddenLightPatterns = [
      /text-blue-400(?!\s)/,
      /text-purple-400(?!\s)/,
      /text-pink-400(?!\s)/,
      /bg-blue-500(?!\s)/,
      /bg-purple-500(?!\s)/,
    ];

    forbiddenLightPatterns.forEach(pattern => {
      const match = pageContent.match(pattern);
      if (match && !match[0].includes('dark:')) {
        console.error(`❌ Color brillante sin dark: encontrado: ${match[0]}`);
      }
    });
  });

  test('Borders deben ser border-gray-300 en light mode', () => {
    const hasBorderGray = /border-gray-300\s+dark:border-/.test(pageContent);
    expect(hasBorderGray).toBe(true);
  });

  test('NO debe haber border-blue sin dark: prefix', () => {
    const borderBluePattern = /border-blue-(?!.*dark:)/;
    const matches = pageContent.match(borderBluePattern);
    
    // Solo permitido si tiene dark: después
    if (matches) {
      const hasProperDark = /border-gray-\d+\s+dark:border-blue/.test(pageContent);
      expect(hasProperDark).toBe(true);
    }
  });
});

// Test visual helper
export function generateThemeReport() {
  const pageContent = readFileSync(
    join(process.cwd(), 'src/app/page.tsx'),
    'utf-8'
  );

  const report = {
    totalBgWhite: (pageContent.match(/bg-white/g) || []).length,
    totalBgGray: (pageContent.match(/bg-gray-/g) || []).length,
    totalDarkBg: (pageContent.match(/dark:bg-/g) || []).length,
    
    bgWhiteWithoutDark: (pageContent.match(/bg-white(?!\s+dark:)/g) || []).length,
    
    lightModeColors: {
      gray900: (pageContent.match(/text-gray-900/g) || []).length,
      gray700: (pageContent.match(/text-gray-700/g) || []).length,
      gray600: (pageContent.match(/text-gray-600/g) || []).length,
    },
    
    darkModeColors: {
      blue: (pageContent.match(/dark:text-blue/g) || []).length,
      purple: (pageContent.match(/dark:text-purple/g) || []).length,
      white: (pageContent.match(/dark:text-white/g) || []).length,
    }
  };

  console.log('📊 Theme Consistency Report:');
  console.log(JSON.stringify(report, null, 2));

  return report;
}
