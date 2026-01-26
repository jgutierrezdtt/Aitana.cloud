import type { Metadata } from "next";
import { Urbanist, DM_Sans } from "next/font/google";
// import "../design-system.css";  // ← TEMPORALMENTE DESACTIVADO - Tailwind v4 incompatibilidad con @apply
import "../globals.css";
import { ThemeProvider } from "@/contexts/ThemeContext";
import EnvironmentBadge from "@/components/EnvironmentBadge";
import DynamicFavicon from "@/components/DynamicFavicon";
import { NextIntlClientProvider } from 'next-intl';
import { notFound, redirect } from 'next/navigation';
import { locales, defaultLocale } from '@/i18n/config';

const urbanist = Urbanist({
  variable: "--font-urbanist",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800"],
  display: "swap",
});

const dmSans = DM_Sans({
  variable: "--font-dm-sans",
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Aitana Security Lab | Enterprise Vulnerability Assessment Platform",
  description: "Executive-level security training platform for CISOs and security leaders. Hands-on vulnerability assessment aligned with OWASP Top 10, PCI-DSS, ISO 27001, and GDPR compliance frameworks.",
  icons: {
    icon: [
      { url: '/logos/logo-navigator-white.png', media: '(prefers-color-scheme: dark)' },
      { url: '/logos/logo-navigator-black.png', media: '(prefers-color-scheme: light)' },
    ],
    apple: '/logos/logo-navigator-white.png',
  },
};

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export default async function LocaleLayout({
  children,
  params
}: {
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}) {
  // Await params en Next.js 15+
  const { locale } = await params;
  
  // Validar que el locale es soportado
  if (!locales.includes(locale as any)) {
    notFound();
  }

  // Cargar mensajes directamente según el locale (16 idiomas)
  let messages;
  switch (locale) {
    case 'es':
      messages = (await import('@/i18n/locales/es.json')).default;
      break;
    case 'en':
      messages = (await import('@/i18n/locales/en.json')).default;
      break;
    case 'fr':
      messages = (await import('@/i18n/locales/fr.json')).default;
      break;
    case 'de':
      messages = (await import('@/i18n/locales/de.json')).default;
      break;
    case 'eu':
      messages = (await import('@/i18n/locales/eu.json')).default;
      break;
    case 'ca':
      messages = (await import('@/i18n/locales/ca.json')).default;
      break;
    case 'gl':
      messages = (await import('@/i18n/locales/gl.json')).default;
      break;
    case 'ic':
      messages = (await import('@/i18n/locales/ic.json')).default;
      break;
    case 'zh':
      messages = (await import('@/i18n/locales/zh.json')).default;
      break;
    case 'it':
      messages = (await import('@/i18n/locales/it.json')).default;
      break;
    case 'pt':
      messages = (await import('@/i18n/locales/pt.json')).default;
      break;
    case 'hi':
      messages = (await import('@/i18n/locales/hi.json')).default;
      break;
    case 'ja':
      messages = (await import('@/i18n/locales/ja.json')).default;
      break;
    case 'ko':
      messages = (await import('@/i18n/locales/ko.json')).default;
      break;
    case 'ar':
      messages = (await import('@/i18n/locales/ar.json')).default;
      break;
    case 'ru':
      messages = (await import('@/i18n/locales/ru.json')).default;
      break;
    default:
      notFound();
  }

  return (
    <html lang={locale} suppressHydrationWarning>
      <head>
        <meta name="theme-color" content="#1B1663" />
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                const theme = localStorage.getItem('theme') || 'system';
                const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
                document.documentElement.classList.add(isDark ? 'dark' : 'light');
              })();
            `,
          }}
        />
      </head>
      <body className={`${urbanist.variable} ${dmSans.variable} antialiased`}>
        <ThemeProvider>
          <NextIntlClientProvider messages={messages}>
            <DynamicFavicon />
            {children}
            <EnvironmentBadge />
          </NextIntlClientProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
