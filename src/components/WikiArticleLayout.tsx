'use client';

import { useState, useEffect, ReactNode } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { 
  ArrowLeft, 
  BookOpen, 
  Clock, 
  Calendar,
  User,
  Share2,
  Bookmark,
  ChevronRight,
  AlertTriangle
} from 'lucide-react';
import Navigation from '@/components/Navigation';

interface WikiArticleLayoutProps {
  category: string;
  categoryColor: 'blue' | 'red' | 'green' | 'purple' | 'orange';
  title: string;
  description?: string;
  level: 'Estudiante' | 'Junior Developer' | 'Pentester' | 'Security Expert';
  readTime: string;
  lastUpdated?: string;
  author?: string;
  cvssScore?: number;
  children: ReactNode;
  tableOfContents?: { id: string; title: string; level: number }[];
  relatedArticles?: string[];
}

export default function WikiArticleLayout({
  category,
  categoryColor,
  title,
  description,
  level,
  readTime,
  lastUpdated,
  author = 'Aitana Security Team',
  cvssScore,
  children,
  tableOfContents = []
}: WikiArticleLayoutProps) {
  const params = useParams();
  const locale = params.locale as string;
  const [scrollProgress, setScrollProgress] = useState(0);
  const [activeSection, setActiveSection] = useState('');

  // Scroll progress
  useEffect(() => {
    const handleScroll = () => {
      const totalHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = (window.scrollY / totalHeight) * 100;
      setScrollProgress(progress);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Category colors
  const categoryColors = {
    blue: {
      gradient: 'from-blue-600 via-blue-500 to-cyan-500',
      badge: 'bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-500/20',
      accent: 'text-blue-600 dark:text-blue-400'
    },
    red: {
      gradient: 'from-red-600 via-rose-500 to-pink-500',
      badge: 'bg-red-500/10 text-red-700 dark:text-red-300 border-red-500/20',
      accent: 'text-red-600 dark:text-red-400'
    },
    green: {
      gradient: 'from-green-600 via-emerald-500 to-teal-500',
      badge: 'bg-green-500/10 text-green-700 dark:text-green-300 border-green-500/20',
      accent: 'text-green-600 dark:text-green-400'
    },
    purple: {
      gradient: 'from-purple-600 via-violet-500 to-indigo-500',
      badge: 'bg-purple-500/10 text-purple-700 dark:text-purple-300 border-purple-500/20',
      accent: 'text-purple-600 dark:text-purple-400'
    },
    orange: {
      gradient: 'from-orange-600 via-red-500 to-pink-500',
      badge: 'bg-orange-500/10 text-orange-700 dark:text-orange-300 border-orange-500/20',
      accent: 'text-orange-600 dark:text-orange-400'
    }
  };

  const colors = categoryColors[categoryColor];

  // Level badge colors
  const getLevelBadge = () => {
    const badges = {
      'Estudiante': 'bg-blue-500/10 text-blue-700 dark:text-blue-300 border border-blue-500/20',
      'Junior Developer': 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border border-cyan-500/20',
      'Pentester': 'bg-purple-500/10 text-purple-700 dark:text-purple-300 border border-purple-500/20',
      'Security Expert': 'bg-red-500/10 text-red-700 dark:text-red-300 border border-red-500/20'
    };
    return badges[level] || badges['Estudiante'];
  };

  return (
    <>
      <Navigation />
      
      {/* Reading Progress Bar */}
      <div className="fixed top-0 left-0 right-0 h-1 bg-slate-200 dark:bg-slate-800 z-50">
        <div 
          className={`h-full bg-gradient-to-r ${colors.gradient} transition-all duration-300`}
          style={{ width: `${scrollProgress}%` }}
        />
      </div>

      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-100 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">
        
        {/* Breadcrumb */}
        <div className="bg-white/50 dark:bg-slate-900/50 backdrop-blur-xl border-b border-slate-200 dark:border-slate-800">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <nav className="flex items-center gap-2 text-sm">
              <Link 
                href={`/${locale}/wiki`}
                className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                Wiki
              </Link>
              <ChevronRight className="w-4 h-4 text-slate-400" />
              <span className={colors.accent}>{category}</span>
              <ChevronRight className="w-4 h-4 text-slate-400" />
              <span className="text-slate-900 dark:text-white font-medium truncate max-w-xs">{title}</span>
            </nav>
          </div>
        </div>

        {/* Article Header - More Professional */}
        <div className={`relative bg-gradient-to-br ${colors.gradient} overflow-hidden`}>
          {/* Decorative background pattern */}
          <div className="absolute inset-0 opacity-10">
            <div className="absolute inset-0" style={{
              backgroundImage: 'radial-gradient(circle at 2px 2px, white 1px, transparent 0)',
              backgroundSize: '32px 32px'
            }} />
          </div>
          
          <div className="relative max-w-7xl mx-auto px-6 py-16 md:py-24">
            <div className="max-w-4xl">
              {/* Category Badge */}
              <div className="inline-flex items-center gap-2 bg-white/20 dark:bg-white/10 backdrop-blur-sm px-4 py-2 rounded-full mb-6 border border-white/30">
                <BookOpen className="w-4 h-4 text-white" />
                <span className="text-white text-sm font-semibold tracking-wide">{category}</span>
              </div>

              {/* Title */}
              <h1 className="text-4xl md:text-6xl font-extrabold text-white mb-6 leading-tight">
                {title}
              </h1>

              {/* Description */}
              {description && (
                <p className="text-xl text-white/90 mb-8 leading-relaxed max-w-3xl">
                  {description}
                </p>
              )}

              {/* Meta Information */}
              <div className="flex flex-wrap items-center gap-4">
                {/* Level Badge */}
                <span className={`${getLevelBadge()} px-4 py-2 rounded-full text-sm font-semibold bg-white/20 backdrop-blur-sm`}>
                  {level}
                </span>

                {/* Read Time */}
                <div className="flex items-center gap-2 text-white/90 bg-white/10 backdrop-blur-sm px-4 py-2 rounded-full">
                  <Clock className="w-4 h-4" />
                  <span className="text-sm font-medium">{readTime}</span>
                </div>

                {/* CVSS Score */}
                {cvssScore && (
                  <div className="flex items-center gap-2 text-white/90 bg-white/10 backdrop-blur-sm px-4 py-2 rounded-full">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-sm font-medium">CVSS {cvssScore.toFixed(1)}</span>
                  </div>
                )}

                {/* Last Updated */}
                {lastUpdated && (
                  <div className="flex items-center gap-2 text-white/90 bg-white/10 backdrop-blur-sm px-4 py-2 rounded-full">
                    <Calendar className="w-4 h-4" />
                    <span className="text-sm font-medium">{lastUpdated}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Main Content Area with Sidebar */}
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="flex gap-12">
            
            {/* Main Article Content */}
            <article className="flex-1 min-w-0">
              <div className="bg-white dark:bg-slate-900 backdrop-blur-sm border border-slate-200 dark:border-slate-800 rounded-3xl shadow-2xl shadow-slate-200/50 dark:shadow-none overflow-hidden">
                <div className="p-8 md:p-12 lg:p-16">
                  {children}
                </div>
              </div>

              {/* Article Footer */}
              <div className="mt-8 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
                  <User className="w-4 h-4" />
                  <span>Por {author}</span>
                </div>
                
                <div className="flex items-center gap-3">
                  <button className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
                    <Share2 className="w-5 h-5 text-slate-600 dark:text-slate-400" />
                  </button>
                  <button className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
                    <Bookmark className="w-5 h-5 text-slate-600 dark:text-slate-400" />
                  </button>
                </div>
              </div>

              {/* Back Button */}
              <div className="mt-8">
                <Link 
                  href={`/${locale}/wiki`}
                  className="inline-flex items-center gap-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors group"
                >
                  <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
                  <span className="font-medium">Volver a la Wiki</span>
                </Link>
              </div>
            </article>

            {/* Table of Contents Sidebar */}
            {tableOfContents.length > 0 && (
              <aside className="hidden xl:block w-64 flex-shrink-0">
                <div className="sticky top-24">
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-lg">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-4 uppercase tracking-wider">
                      En este artículo
                    </h3>
                    <nav className="space-y-2">
                      {tableOfContents.map((item) => (
                        <a
                          key={item.id}
                          href={`#${item.id}`}
                          className={`block text-sm py-2 px-3 rounded-lg transition-colors ${
                            item.level === 2 ? 'pl-3' : 'pl-6 text-slate-600 dark:text-slate-400'
                          } ${
                            activeSection === item.id
                              ? `${colors.accent} bg-slate-100 dark:bg-slate-800 font-semibold`
                              : 'text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                          }`}
                        >
                          {item.title}
                        </a>
                      ))}
                    </nav>
                  </div>
                </div>
              </aside>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
