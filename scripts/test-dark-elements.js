#!/usr/bin/env node
/**
 * Test avanzado para detectar elementos que se quedan OSCUROS en modo claro
 * Verifica que NO haya:
 * - Fondos oscuros sin variante light (bg-[#xxx] sin dark:)
 * - Textos claros en light mode (text-white sin dark:)
 * - Borders oscuros sin alternativa
 */

const fs = require('fs');
const path = require('path');

const pageFile = path.join(__dirname, '../src/app/page.tsx');
const content = fs.readFileSync(pageFile, 'utf-8');

console.log('🔍 TEST: Detectando elementos OSCUROS en modo CLARO\n');
console.log('=' .repeat(60));

let hasErrors = false;
const errors = [];

// Excluir hero slider (siempre oscuro)
const heroSliderSection = content.match(/Hero Slider[\s\S]*?{\/\* Hero Features/);
const contentWithoutHeroSlider = heroSliderSection 
  ? content.replace(heroSliderSection[0], '/* EXCLUDED: Hero Slider */')
  : content;

// TEST 1: Detectar fondos oscuros hardcodeados
console.log('\n🧪 TEST 1: Fondos oscuros hardcodeados');
console.log('-'.repeat(60));

const darkBackgroundPatterns = [
  { pattern: /className="[^"]*bg-\[#0A0525\](?![^"]*dark:)/g, name: 'bg-[#0A0525]' },
  { pattern: /className="[^"]*bg-\[#1B1663\](?![^"]*dark:)/g, name: 'bg-[#1B1663]' },
  { pattern: /className="[^"]*bg-\[#120d4f\](?![^"]*dark:)/g, name: 'bg-[#120d4f]' },
  { pattern: /className="[^"]*bg-black(?![^"]*dark:)/g, name: 'bg-black' },
  { pattern: /className="[^"]*bg-gray-900(?![^"]*dark:)/g, name: 'bg-gray-900' },
  { pattern: /className="[^"]*bg-gray-800(?![^"]*dark:)/g, name: 'bg-gray-800' },
];

darkBackgroundPatterns.forEach(({ pattern, name }) => {
  const matches = contentWithoutHeroSlider.match(pattern);
  if (matches) {
    console.error(`  ❌ FALLO: ${name} sin dark: encontrado (${matches.length}x)`);
    matches.slice(0, 3).forEach(m => console.error(`     → ${m.substring(0, 80)}...`));
    errors.push(`${name} hardcodeado sin variante light`);
    hasErrors = true;
  } else {
    console.log(`  ✅ OK: ${name}`);
  }
});

// TEST 2: Detectar texto claro en light mode
console.log('\n🧪 TEST 2: Texto claro que debe ser oscuro en light mode');
console.log('-'.repeat(60));

const lightTextPatterns = [
  { pattern: /className="[^"]*\btext-white\b(?![^"]*dark:text-white)/g, name: 'text-white' },
  { pattern: /className="[^"]*text-gray-100(?![^"]*dark:)/g, name: 'text-gray-100' },
  { pattern: /className="[^"]*text-gray-200(?![^"]*dark:)/g, name: 'text-gray-200' },
  { pattern: /className="[^"]*text-blue-400(?![^"]*dark:text-blue)/g, name: 'text-blue-400' },
  { pattern: /className="[^"]*text-purple-400(?![^"]*dark:text-purple)/g, name: 'text-purple-400' },
];

lightTextPatterns.forEach(({ pattern, name }) => {
  const matches = contentWithoutHeroSlider.match(pattern);
  if (matches) {
    console.error(`  ❌ FALLO: ${name} sin dark: encontrado (${matches.length}x)`);
    matches.slice(0, 3).forEach(m => console.error(`     → ${m.substring(0, 80)}...`));
    errors.push(`${name} hardcodeado - debe tener variante dark`);
    hasErrors = true;
  } else {
    console.log(`  ✅ OK: ${name}`);
  }
});

// TEST 3: Gradientes oscuros sin alternativa
console.log('\n🧪 TEST 3: Gradientes oscuros hardcodeados');
console.log('-'.repeat(60));

const darkGradientPattern = /className="[^"]*bg-gradient-to-[a-z]+\s+from-\[#[0-9A-F]{6}\](?![^"]*dark:)/gi;
const gradientMatches = contentWithoutHeroSlider.match(darkGradientPattern);

if (gradientMatches) {
  console.error(`  ❌ FALLO: Gradientes oscuros sin variante light (${gradientMatches.length}x)`);
  gradientMatches.slice(0, 3).forEach(m => console.error(`     → ${m.substring(0, 80)}...`));
  errors.push('Gradientes hardcodeados sin variante light');
  hasErrors = true;
} else {
  console.log('  ✅ OK: No hay gradientes hardcodeados sin dark:');
}

// TEST 4: Borders oscuros
console.log('\n🧪 TEST 4: Borders oscuros sin alternativa');
console.log('-'.repeat(60));

const darkBorderPatterns = [
  { pattern: /className="[^"]*border-\[#[0-9A-F]{6}\](?![^"]*dark:)/gi, name: 'border-[#hex]' },
  { pattern: /className="[^"]*border-blue-500(?![^"]*dark:border-blue)/g, name: 'border-blue-500' },
  { pattern: /className="[^"]*border-purple-500(?![^"]*dark:border-purple)/g, name: 'border-purple-500' },
];

darkBorderPatterns.forEach(({ pattern, name }) => {
  const matches = contentWithoutHeroSlider.match(pattern);
  if (matches) {
    console.error(`  ❌ FALLO: ${name} sin dark: encontrado (${matches.length}x)`);
    matches.slice(0, 2).forEach(m => console.error(`     → ${m.substring(0, 80)}...`));
    errors.push(`${name} hardcodeado`);
    hasErrors = true;
  } else {
    console.log(`  ✅ OK: ${name}`);
  }
});

// TEST 5: Shadows oscuros
console.log('\n🧪 TEST 5: Shadows que solo funcionan en dark');
console.log('-'.repeat(60));

const darkShadowPattern = /shadow-\[0_0_[^\]]+rgba\(59,130,246/g;
const shadowMatches = content.match(darkShadowPattern);

if (shadowMatches && shadowMatches.length > 0) {
  console.log(`  ⚠️  ADVERTENCIA: ${shadowMatches.length} shadows con color azul detectados`);
  console.log('     Estos deben tener prefijo dark: para no verse en light mode');
} else {
  console.log('  ✅ OK: No hay shadows problemáticos');
}

// TEST 6: Verificar patrón correcto (light primero, dark después)
console.log('\n🧪 TEST 6: Verificar patrón bg-gray-* dark:bg-[color]');
console.log('-'.repeat(60));

const correctPatternCount = (content.match(/bg-gray-\d+\s+dark:bg-/g) || []).length;
const totalBgClasses = (content.match(/className="[^"]*bg-/g) || []).length;
const coverage = Math.round((correctPatternCount / totalBgClasses) * 100);

console.log(`  📊 Patrón correcto: ${correctPatternCount}/${totalBgClasses} (${coverage}%)`);
if (coverage >= 70) {
  console.log('  ✅ OK: Buena cobertura de patrón adaptativo');
} else {
  console.error('  ❌ FALLO: Cobertura insuficiente del patrón adaptativo');
  errors.push('Muchos bg sin patrón light/dark');
  hasErrors = true;
}

// TEST 7: Detectar from-gray-* to-white (gradientes que deben ser adaptativos)
console.log('\n🧪 TEST 7: Gradientes que deben ser adaptativos');
console.log('-'.repeat(60));

const lightGradientPattern = /from-gray-\d+\s+to-white\s+dark:from/g;
const lightGradients = content.match(lightGradientPattern);

if (lightGradients && lightGradients.length > 0) {
  console.log(`  ✅ OK: ${lightGradients.length} gradientes adaptativos encontrados`);
} else {
  console.log('  ⚠️  ADVERTENCIA: No hay gradientes adaptativos');
}

// REPORTE FINAL
console.log('\n' + '='.repeat(60));
console.log('📊 RESUMEN DEL ANÁLISIS');
console.log('='.repeat(60));

if (hasErrors) {
  console.log('\n❌ TESTS FALLIDOS\n');
  console.log('🔴 Problemas encontrados:');
  errors.forEach((error, idx) => {
    console.log(`   ${idx + 1}. ${error}`);
  });
  
  console.log('\n💡 RECOMENDACIONES:');
  console.log('   1. Usar SIEMPRE: bg-gray-* dark:bg-[color]');
  console.log('   2. Usar SIEMPRE: text-gray-* dark:text-[color]');
  console.log('   3. Usar SIEMPRE: border-gray-* dark:border-[color]');
  console.log('   4. NO hardcodear colores oscuros sin variante light');
  console.log('   5. Considerar usar design tokens (ver mejoras sugeridas)');
  
  process.exit(1);
} else {
  console.log('\n✅ TODOS LOS TESTS PASADOS\n');
  console.log('✨ El tema es consistente:');
  console.log('   • Modo CLARO: Todos los elementos usan grises');
  console.log('   • Modo OSCURO: Todos los elementos tienen variantes dark:');
  console.log('   • No hay hardcodeo de colores oscuros');
  
  console.log('\n📈 Métricas:');
  console.log(`   • Cobertura de patrón adaptativo: ${coverage}%`);
  console.log(`   • Total de backgrounds: ${totalBgClasses}`);
  console.log(`   • Backgrounds adaptativos: ${correctPatternCount}`);
  
  process.exit(0);
}
