/**
 * SCRIPT DE DIAGNÓSTICO COMPLETO - Dark Mode Wiki
 * 
 * USO:
 * 1. Abre la Wiki en el navegador
 * 2. Abre DevTools (F12 o Cmd+Opt+I)
 * 3. Copia y pega este script en la consola
 * 4. Revisa el reporte completo
 */

console.clear();
console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'color: #3b82f6; font-weight: bold');
console.log('%c🔍 DIAGNÓSTICO DARK MODE - WIKI FILTROS', 'color: #3b82f6; font-size: 18px; font-weight: bold');
console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'color: #3b82f6; font-weight: bold');
console.log('');

// 1. VERIFICAR CLASE DARK EN HTML
console.log('%c1️⃣ CLASE DARK EN <HTML>', 'color: #f59e0b; font-weight: bold');
const htmlElement = document.documentElement;
const hasDarkClass = htmlElement.classList.contains('dark');
console.log('   Clase "dark" presente:', hasDarkClass ? '✅ SÍ' : '❌ NO');
console.log('   Clases en <html>:', Array.from(htmlElement.classList).join(', ') || 'NINGUNA');
console.log('');

// 2. VERIFICAR THEME EN LOCALSTORAGE
console.log('%c2️⃣ THEME EN LOCALSTORAGE', 'color: #f59e0b; font-weight: bold');
const theme = localStorage.getItem('theme');
console.log('   localStorage.theme:', theme || 'NO DEFINIDO');
console.log('   Preferencia sistema:', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'DARK' : 'LIGHT');
console.log('');

// 3. ENCONTRAR BOTONES DE FILTRO
console.log('%c3️⃣ BOTONES DE FILTRO (WikiSidebar)', 'color: #f59e0b; font-weight: bold');
const filterButtons = document.querySelectorAll('button[class*="rounded-lg"]');
console.log('   Botones encontrados:', filterButtons.length);

if (filterButtons.length > 0) {
  filterButtons.forEach((btn, index) => {
    const computedStyle = window.getComputedStyle(btn);
    const bgColor = computedStyle.backgroundColor;
    const textColor = computedStyle.color;
    const borderColor = computedStyle.borderColor;
    const classes = btn.className;
    
    console.log(`\n   📌 Botón ${index + 1}: "${btn.textContent.trim()}"`);
    console.log('      Clases aplicadas:', classes);
    console.log('      🎨 Background:', bgColor);
    console.log('      📝 Text color:', textColor);
    console.log('      🔲 Border color:', borderColor);
    
    // Detectar si es blanco
    const isWhite = bgColor.includes('rgb(255, 255, 255)') || 
                     bgColor.includes('rgba(255, 255, 255');
    if (isWhite && hasDarkClass) {
      console.log('      ⚠️  PROBLEMA: Fondo BLANCO en modo DARK');
    }
  });
} else {
  console.log('   ❌ NO SE ENCONTRARON BOTONES - Asegúrate de estar en la página de Wiki');
}
console.log('');

// 4. VERIFICAR SIDEBAR
console.log('%c4️⃣ WIKI SIDEBAR', 'color: #f59e0b; font-weight: bold');
const sidebar = document.querySelector('div.w-80');
if (sidebar) {
  const sidebarStyle = window.getComputedStyle(sidebar);
  console.log('   Sidebar encontrado: ✅');
  console.log('   Background:', sidebarStyle.backgroundColor);
  console.log('   Border:', sidebarStyle.borderRightColor);
  console.log('   Clases:', sidebar.className);
  
  const isWhiteSidebar = sidebarStyle.backgroundColor.includes('rgb(255, 255, 255)');
  if (isWhiteSidebar && hasDarkClass) {
    console.log('   ⚠️  PROBLEMA: Sidebar BLANCO en modo DARK');
  }
} else {
  console.log('   ❌ Sidebar NO encontrado');
}
console.log('');

// 5. VERIFICAR INPUT DE BÚSQUEDA
console.log('%c5️⃣ INPUT DE BÚSQUEDA', 'color: #f59e0b; font-weight: bold');
const searchInput = document.querySelector('input[placeholder*="Buscar"]');
if (searchInput) {
  const inputStyle = window.getComputedStyle(searchInput);
  console.log('   Input encontrado: ✅');
  console.log('   Background:', inputStyle.backgroundColor);
  console.log('   Text color:', inputStyle.color);
  console.log('   Border:', inputStyle.borderColor);
  console.log('   Clases:', searchInput.className);
  
  const isWhiteInput = inputStyle.backgroundColor.includes('rgb(255, 255, 255)') ||
                        inputStyle.backgroundColor.includes('rgb(248, 250, 252)'); // slate-50
  if (isWhiteInput && hasDarkClass) {
    console.log('   ⚠️  PROBLEMA: Input BLANCO/CLARO en modo DARK');
  }
} else {
  console.log('   ❌ Input de búsqueda NO encontrado');
}
console.log('');

// 6. VERIFICAR CSS CUSTOM PROPERTIES
console.log('%c6️⃣ CSS VARIABLES (Design System)', 'color: #f59e0b; font-weight: bold');
const rootStyle = window.getComputedStyle(document.documentElement);
const bgPrimary = rootStyle.getPropertyValue('--color-bg-primary').trim();
const textPrimary = rootStyle.getPropertyValue('--color-text-primary').trim();
const surfaceSecondary = rootStyle.getPropertyValue('--color-surface-secondary').trim();

console.log('   --color-bg-primary:', bgPrimary || 'NO DEFINIDO');
console.log('   --color-text-primary:', textPrimary || 'NO DEFINIDO');
console.log('   --color-surface-secondary:', surfaceSecondary || 'NO DEFINIDO');

if (!bgPrimary && !textPrimary) {
  console.log('   ⚠️  CSS Variables NO cargadas - design-system.css puede no estar importado');
}
console.log('');

// 7. VERIFICAR TAILWIND CONFIG
console.log('%c7️⃣ TAILWIND CLASSES (Computed)', 'color: #f59e0b; font-weight: bold');
const testDiv = document.createElement('div');
testDiv.className = 'bg-white dark:bg-slate-900';
testDiv.style.display = 'none';
document.body.appendChild(testDiv);
const testStyle = window.getComputedStyle(testDiv);
console.log('   Test div con "bg-white dark:bg-slate-900"');
console.log('   Background computado:', testStyle.backgroundColor);
const expectedDarkBg = 'rgb(15, 23, 42)'; // slate-900
const isCorrect = testStyle.backgroundColor === expectedDarkBg;
if (hasDarkClass) {
  console.log('   ¿Aplica dark:bg-slate-900?', isCorrect ? '✅ SÍ' : '❌ NO');
  if (!isCorrect) {
    console.log('   ⚠️  PROBLEMA: Tailwind dark: classes no funcionan');
  }
}
document.body.removeChild(testDiv);
console.log('');

// 8. RECOMENDACIONES
console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'color: #10b981; font-weight: bold');
console.log('%c💡 RECOMENDACIONES', 'color: #10b981; font-size: 16px; font-weight: bold');
console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'color: #10b981; font-weight: bold');

if (!hasDarkClass) {
  console.log('%c⚡ ACCIÓN: Clase "dark" NO está en <html>', 'color: #ef4444; font-weight: bold');
  console.log('   - Verifica el script de theme en layout.tsx');
  console.log('   - Cambia manualmente con: document.documentElement.classList.add("dark")');
  console.log('');
}

if (filterButtons.length === 0) {
  console.log('%c⚡ ACCIÓN: Navega a la página de Wiki', 'color: #ef4444; font-weight: bold');
  console.log('   - Este script necesita ejecutarse en http://localhost:3000/wiki');
  console.log('');
}

const problemButtons = Array.from(filterButtons).filter(btn => {
  const bg = window.getComputedStyle(btn).backgroundColor;
  return bg.includes('rgb(255, 255, 255)') && hasDarkClass;
});

if (problemButtons.length > 0 && hasDarkClass) {
  console.log('%c⚡ ACCIÓN: Botones de filtro tienen fondo BLANCO en dark mode', 'color: #ef4444; font-weight: bold');
  console.log('   - Posibles causas:');
  console.log('     1. Cache del navegador (prueba Cmd+Shift+R o modo incógnito)');
  console.log('     2. Tailwind no compiló dark: variants (reinicia dev server)');
  console.log('     3. Estilos inline o !important sobreescribiendo');
  console.log('');
  console.log('   🔧 Debug adicional:');
  problemButtons.forEach((btn, i) => {
    console.log(`      Botón ${i + 1}:`);
    console.log('      ', btn.className);
    console.log('      Inline style:', btn.getAttribute('style') || 'NINGUNO');
  });
  console.log('');
}

if (!bgPrimary && !textPrimary) {
  console.log('%c⚡ ACCIÓN: CSS Variables NO cargadas', 'color: #ef4444; font-weight: bold');
  console.log('   - Verifica que design-system.css esté importado en layout.tsx');
  console.log('   - Reinicia el dev server: npm run dev');
  console.log('');
}

console.log('%c✅ DIAGNÓSTICO COMPLETO', 'color: #10b981; font-weight: bold');
console.log('');
console.log('%c📋 PRÓXIMOS PASOS:', 'color: #3b82f6; font-weight: bold');
console.log('1. Revisa los problemas marcados con ⚠️ arriba');
console.log('2. Si hay cache: Cmd+Shift+R (macOS) o Ctrl+Shift+R (Windows)');
console.log('3. Si persiste: Modo incógnito o limpia localStorage');
console.log('4. Si nada funciona: Reinicia dev server (npm run dev)');
console.log('');
console.log('%cCopia este reporte y compártelo si necesitas ayuda', 'color: #6b7280; font-style: italic');
console.log('%c━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'color: #3b82f6; font-weight: bold');
