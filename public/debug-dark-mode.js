console.log('🎨 Wiki Dark Mode Debug Script');
console.log('━'.repeat(60));

// 1. Check if dark class is present
const isDarkMode = document.documentElement.classList.contains('dark');
console.log(`1️⃣ Dark mode active: ${isDarkMode ? '✅ YES' : '❌ NO'}`);
console.log(`   HTML classes: ${document.documentElement.className}`);

// 2. Check localStorage theme
const storedTheme = localStorage.getItem('theme');
console.log(`2️⃣ Stored theme: ${storedTheme || '(none)'}`);

// 3. Check system preference
const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
console.log(`3️⃣ System prefers dark: ${systemPrefersDark ? 'YES' : 'NO'}`);

// 4. Check sidebar background
const sidebar = document.querySelector('[class*="w-80"]');
if (sidebar) {
  const styles = window.getComputedStyle(sidebar);
  const bgColor = styles.backgroundColor;
  console.log(`4️⃣ Sidebar background: ${bgColor}`);
  console.log(`   Expected dark: rgb(15, 23, 42) [slate-900]`);
  console.log(`   Expected light: rgb(255, 255, 255) [white]`);
} else {
  console.log(`4️⃣ Sidebar not found`);
}

// 5. Check filter buttons
const filterButton = document.querySelector('button[class*="bg-slate-100"]');
if (filterButton) {
  const styles = window.getComputedStyle(filterButton);
  const bgColor = styles.backgroundColor;
  console.log(`5️⃣ Filter button background: ${bgColor}`);
  console.log(`   Expected dark: rgb(30, 41, 59) [slate-800]`);
  console.log(`   Expected light: rgb(241, 245, 249) [slate-100]`);
} else {
  console.log(`5️⃣ Filter button not found`);
}

console.log('━'.repeat(60));
console.log('');
console.log('💡 Soluciones si dark mode no funciona:');
console.log('  1. Hard reload: Cmd+Shift+R (Mac) o Ctrl+Shift+R (Windows)');
console.log('  2. Limpia localStorage: localStorage.clear()');
console.log('  3. Cambia el tema del sistema a oscuro');
console.log('  4. Verifica que el servidor de desarrollo esté corriendo');
