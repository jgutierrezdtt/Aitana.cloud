/**
 * Root Layout - Solo para redirección a locale
 * 
 * Este layout vacío permite que el middleware maneje la redirección
 * El layout real con traducciones está en [locale]/layout.tsx
 */
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return children;
}
