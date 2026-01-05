'use client';

import Navigation from '@/components/Navigation';
import WikiSidebar from '@/components/WikiSidebar';

export default function WikiLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Navigation />
      <div className="flex min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
        <WikiSidebar />
        <main className="flex-1">
          {children}
        </main>
      </div>
    </>
  );
}
