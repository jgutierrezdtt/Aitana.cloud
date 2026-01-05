import type { Metadata } from "next";
import { Urbanist, DM_Sans } from "next/font/google";
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

  // Cargar mensajes directamente según el locale
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
