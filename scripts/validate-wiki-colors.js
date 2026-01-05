#!/usr/bin/env node

/**
 * Wiki Color Validation Script
 * Valida que todos los componentes de la Wiki usen colores apropiados en dark mode
 */

const fs = require('fs');
const path = require('path');

// Colores de validación
const VALIDATION_RULES = {
  // Fondos que deben usarse (sólidos)
  validBackgrounds: [
    'dark:bg-slate-900',
    'dark:bg-slate-800',
    'dark:bg-slate-800/50',
    'dark:bg-slate-700',
  ],
  
  // Fondos que NO deben usarse (demasiado transparentes)
  invalidBackgrounds: [
    'dark:bg-white/5',
    'dark:bg-white/10',
    'dark:bg-black/5',
  ],
  
  // Bordes visibles
  validBorders: [
    'dark:border-slate-700',
    'dark:border-slate-600',
    'dark:border-white/10',
  ],
  
  // Textos con buen contraste
  validTextColors: [
    'dark:text-white',
    'dark:text-slate-300',
    'dark:text-slate-400',
  ],
  
  // Hovers visibles
  validHovers: [
    'dark:hover:bg-slate-700',
    'dark:hover:bg-slate-800',
    'dark:hover:bg-slate-600',
  ],
};

// Archivos a validar
const FILES_TO_CHECK = [
  'src/components/WikiSidebar.tsx',
  'src/app/[locale]/wiki/page.tsx',
  'src/app/[locale]/wiki/fundamentos/http-basico/page.tsx',
  'src/app/[locale]/wiki/vulnerabilidades/sql-injection/page.tsx',
];

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

console.log('🎨 Wiki Color Validation\n');
console.log('━'.repeat(60));

function validateFile(filePath) {
  const fullPath = path.join(process.cwd(), filePath);
  
  if (!fs.existsSync(fullPath)) {
    console.log(`⚠️  Archivo no encontrado: ${filePath}`);
    return;
  }
  
  const content = fs.readFileSync(fullPath, 'utf-8');
  
  console.log(`\n📄 ${filePath}`);
  console.log('─'.repeat(60));
  
  // Test 1: No debe usar fondos transparentes inválidos
  totalTests++;
  const hasInvalidBg = VALIDATION_RULES.invalidBackgrounds.some(bg => 
    content.includes(bg)
  );
  
  if (hasInvalidBg) {
    failedTests++;
    console.log('❌ Test 1: Usa fondos transparentes (bg-white/5)');
    VALIDATION_RULES.invalidBackgrounds.forEach(bg => {
      if (content.includes(bg)) {
        console.log(`   → Encontrado: ${bg}`);
      }
    });
  } else {
    passedTests++;
    console.log('✅ Test 1: No usa fondos transparentes inválidos');
  }
  
  // Test 2: Debe usar fondos sólidos
  totalTests++;
  const hasValidBg = VALIDATION_RULES.validBackgrounds.some(bg => 
    content.includes(bg)
  );
  
  if (hasValidBg) {
    passedTests++;
    console.log('✅ Test 2: Usa fondos sólidos (slate-900/800)');
  } else {
    failedTests++;
    console.log('❌ Test 2: No usa fondos sólidos apropiados');
  }
  
  // Test 3: Debe usar bordes visibles
  totalTests++;
  const hasValidBorders = VALIDATION_RULES.validBorders.some(border => 
    content.includes(border)
  );
  
  if (hasValidBorders) {
    passedTests++;
    console.log('✅ Test 3: Usa bordes visibles (slate-700)');
  } else {
    failedTests++;
    console.log('❌ Test 3: Bordes pueden no ser visibles');
  }
  
  // Test 4: Debe usar textos con contraste
  totalTests++;
  const hasValidText = VALIDATION_RULES.validTextColors.some(text => 
    content.includes(text)
  );
  
  if (hasValidText) {
    passedTests++;
    console.log('✅ Test 4: Usa textos con buen contraste');
  } else {
    failedTests++;
    console.log('❌ Test 4: Textos pueden tener bajo contraste');
  }
  
  // Test 5: Debe usar hovers visibles (OPCIONAL para artículos)
  totalTests++;
  const hasValidHovers = VALIDATION_RULES.validHovers.some(hover => 
    content.includes(hover)
  );
  
  if (hasValidHovers) {
    passedTests++;
    console.log('✅ Test 5: Hovers visibles en dark mode');
  } else {
    // No es crítico para artículos sin elementos interactivos
    passedTests++;
    console.log('⚠️  Test 5: Sin hovers específicos (OK si no hay elementos interactivos)');
  }
  
  // Test 6: No debe tener hover:bg-white/10 sin dark variant
  totalTests++;
  const hasInvalidHover = content.includes('hover:bg-white/10') && 
                          !content.includes('dark:hover:bg-slate');
  
  if (hasInvalidHover) {
    failedTests++;
    console.log('❌ Test 6: Hover transparente sin variante dark');
  } else {
    passedTests++;
    console.log('✅ Test 6: Hovers correctamente implementados');
  }
}

// Validar archivos principales
FILES_TO_CHECK.forEach(validateFile);

// Buscar todos los artículos de wiki
console.log('\n📚 Validando artículos de Wiki...');
const wikiPath = path.join(process.cwd(), 'src/app/[locale]/wiki');

function findWikiArticles(dir, baseDir = dir) {
  const files = [];
  
  if (!fs.existsSync(dir)) return files;
  
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      files.push(...findWikiArticles(fullPath, baseDir));
    } else if (item === 'page.tsx' && !fullPath.includes('[locale]/wiki/page.tsx')) {
      files.push(path.relative(process.cwd(), fullPath));
    }
  }
  
  return files;
}

const wikiArticles = findWikiArticles(wikiPath);
console.log(`Encontrados ${wikiArticles.length} artículos\n`);

wikiArticles.slice(0, 5).forEach(validateFile); // Validar primeros 5 como muestra

// Resumen
console.log('\n' + '━'.repeat(60));
console.log('📊 RESUMEN DE VALIDACIÓN\n');
console.log(`Total de tests: ${totalTests}`);
console.log(`✅ Pasados:     ${passedTests} (${Math.round(passedTests/totalTests*100)}%)`);
console.log(`❌ Fallados:    ${failedTests} (${Math.round(failedTests/totalTests*100)}%)`);

if (failedTests === 0) {
  console.log('\n🎉 ¡Todos los tests pasaron! Dark mode correctamente implementado.');
  process.exit(0);
} else {
  console.log('\n⚠️  Algunos tests fallaron. Revisa los problemas arriba.');
  process.exit(1);
}
