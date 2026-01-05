#!/usr/bin/env node
/**
 * Script de verificación de consistencia de temas
 * Verifica que NO haya bg-white sin dark:bg-* en page.tsx
 */

const fs = require('fs');
const path = require('path');

const pageFile = path.join(__dirname, '../src/app/page.tsx');
const content = fs.readFileSync(pageFile, 'utf-8');

console.log('🔍 Verificando consistencia de temas en page.tsx...\n');

let hasErrors = false;

// Test 1: NO debe haber bg-white sin dark: (excepto en hero slider)
console.log('✓ Test 1: Verificando bg-white...');
// Extraer sección del hero slider para excluirla
const heroSliderSection = content.match(/Hero Slider[\s\S]*?<\/section>/);
const contentWithoutHeroSlider = heroSliderSection 
  ? content.replace(heroSliderSection[0], '/* Hero Slider excluded from test */')
  : content;

const bgWhiteMatches = contentWithoutHeroSlider.match(/className="[^"]*\bbg-white\b(?![^"]*dark:bg-)/g);
if (bgWhiteMatches) {
  console.error('  ❌ FALLO: Encontrados bg-white sin dark:bg-* (fuera del hero slider)');
  bgWhiteMatches.forEach(match => console.error(`     ${match}`));
  hasErrors = true;
} else {
  console.log('  ✅ OK: No hay bg-white sin dark mode (excepto hero slider)');
}

// Test 2: Verificar que se usan grises
console.log('\n✓ Test 2: Verificando uso de grises...');
const grayBackgrounds = content.match(/bg-gray-(50|100|200)/g);
if (grayBackgrounds && grayBackgrounds.length > 0) {
  console.log(`  ✅ OK: Encontrados ${grayBackgrounds.length} bg-gray-*`);
} else {
  console.error('  ❌ FALLO: No se encontraron suficientes bg-gray-*');
  hasErrors = true;
}

// Test 3: Hero features
console.log('\n✓ Test 3: Hero features...');
const heroFeaturesSection = content.match(/Hero Features - CyberGuard Style[\s\S]{0,1500}/);
const hasHeroFeaturesBgGray = heroFeaturesSection && /bg-gray-50/.test(heroFeaturesSection[0]);
if (hasHeroFeaturesBgGray) {
  console.log('  ✅ OK: Hero features usan bg-gray-50');
} else {
  console.error('  ❌ FALLO: Hero features no usan bg-gray-50');
  hasErrors = true;
}

// Test 4: Service cards
console.log('\n✓ Test 4: Service cards...');
const serviceCardsMatch = content.match(/services\.map[\s\S]{0,500}bg-gray-50/);
if (serviceCardsMatch) {
  console.log('  ✅ OK: Service cards usan bg-gray-50');
} else {
  console.error('  ❌ FALLO: Service cards no usan bg-gray-50');
  hasErrors = true;
}

// Test 5: AI Lab section
console.log('\n✓ Test 5: AI Lab section...');
const aiLabContainerMatch = content.match(/AI Red Team Lab Feature[\s\S]{0,300}bg-gray-50\s+dark:bg-gradient/);
const aiLabCardsMatch = content.match(/{ icon: KeyRound[\s\S]{0,800}bg-gray-50\s+dark:bg-gradient/);
if (aiLabContainerMatch && aiLabCardsMatch) {
  console.log('  ✅ OK: AI Lab section usa bg-gray-50');
} else {
  if (!aiLabContainerMatch) console.error('  ❌ FALLO: AI Lab container no usa bg-gray-50');
  if (!aiLabCardsMatch) console.error('  ❌ FALLO: AI Lab cards no usan bg-gray-50');
  hasErrors = true;
}

// Test 6: Colores de texto
console.log('\n✓ Test 6: Colores de texto...');
const textColors = [
  'text-gray-900',
  'text-gray-700',
  'text-gray-600',
  'text-gray-500'
];
let foundTextColors = 0;
textColors.forEach(color => {
  if (content.includes(color)) foundTextColors++;
});
if (foundTextColors === textColors.length) {
  console.log('  ✅ OK: Todos los colores de texto grises presentes');
} else {
  console.error(`  ❌ FALLO: Solo ${foundTextColors}/${textColors.length} colores de texto encontrados`);
  hasErrors = true;
}

// Test 7: Borders
console.log('\n✓ Test 7: Borders...');
const borderMatches = content.match(/border-gray-300\s+dark:border-/g);
if (borderMatches && borderMatches.length > 5) {
  console.log(`  ✅ OK: ${borderMatches.length} borders usan border-gray-300`);
} else {
  console.error('  ❌ FALLO: Insuficientes border-gray-300 encontrados');
  hasErrors = true;
}

// Resumen
console.log('\n' + '='.repeat(60));
if (hasErrors) {
  console.log('❌ TESTS FALLIDOS - Hay inconsistencias de tema');
  process.exit(1);
} else {
  console.log('✅ TODOS LOS TESTS PASADOS');
  console.log('✅ El tema está consistente: grises en light, colores en dark');
  process.exit(0);
}
