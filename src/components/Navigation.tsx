'use client';

import Link from "next/link";
import { useState } from "react";
import { useParams } from "next/navigation";
import { Menu, X, ChevronDown, ArrowRight, Shield, Brain } from "lucide-react";
import Logo from "./Logo";
import ThemeToggle from "./ThemeToggle";
import LanguageSelector from "./LanguageSelector";
import { getEnabledRoutes, getRoutesByCategory } from "@/config/routes";
import { isFeatureEnabled } from "@/config/features";

export default function Navigation() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const params = useParams();
  const locale = params?.locale || 'es';
  
  // Obtener rutas habilitadas por categoría
  const toolsRoutes = getRoutesByCategory('tools');
  const redTeamRoutes = getRoutesByCategory('red-team');
  const docsRoutes = getRoutesByCategory('docs');

  // Mapeo de iconos para las rutas de labs
  const getLabIcon = (path: string) => {
    if (path.includes('blue-team')) {
      return <Shield className="w-4 h-4 inline-block mr-1.5" />;
    } else if (path.includes('ai-red-team')) {
      return <Brain className="w-4 h-4 inline-block mr-1.5" />;
    }
    return null;
  };

  return (
    <>
      {/* Top Bar - CyberGuard Style */}
      <div className="bg-primary border-b border-border hidden lg:block">
        <div className="max-w-[1240px] mx-auto px-6">
          <div className="flex items-center justify-end py-3 text-sm">
            <div className="flex items-center gap-4">
              {/* Language Selector */}
              <LanguageSelector />
              
              {/* Theme Toggle */}
              <ThemeToggle />
            </div>
          </div>
        </div>
      </div>

      {/* Main Header */}
      <header className="bg-primary border-b border-border sticky top-0 z-50 backdrop-blur-lg">
        <div className="max-w-[1240px] mx-auto px-6">
          <div className="flex items-center justify-between h-20">
            {/* Logo */}
            <Logo variant="header" size="md" />

            {/* Desktop Menu */}
            <nav className="hidden lg:flex items-center gap-8">
              <Link 
                href={`/${locale}`}
                className="font-urbanist text-[17px] font-semibold text-secondary hover:text-primary transition-colors"
              >
                Inicio
              </Link>
              
              {/* Labs Dropdown - Solo si hay rutas de Red Team habilitadas */}
              {redTeamRoutes.length > 0 && (
                <div className="group relative">
                  <button className="font-urbanist text-[17px] font-semibold text-secondary hover:text-primary transition-colors flex items-center gap-1">
                    Labs
                    <ChevronDown className="w-4 h-4 transition-transform group-hover:rotate-180" />
                  </button>
                  <div className="absolute top-full left-0 mt-2 w-72 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 bg-secondary border border-border rounded-xl shadow-2xl overflow-hidden max-h-96 overflow-y-auto z-[100]">
                    {redTeamRoutes.map((route, idx) => (
                      <Link 
                        key={route.path} 
                        href={`/${locale}${route.path}`} 
                        className={`block px-5 py-3 text-secondary hover:text-primary hover:bg-hover transition-colors ${idx !== redTeamRoutes.length - 1 ? 'border-b border-border' : ''}`}
                      >
                        <div className="font-urbanist font-semibold flex items-center">
                          {getLabIcon(route.path)}
                          {route.label}
                        </div>
                        {route.description && (
                          <div className="text-xs text-muted font-dm-sans mt-1">{route.description}</div>
                        )}
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              {/* Tools Dropdown - Solo si hay rutas de Tools habilitadas */}
              {toolsRoutes.length > 0 && (
                <div className="group relative">
                  <button className="font-urbanist text-[17px] font-semibold text-secondary hover:text-primary transition-colors flex items-center gap-1">
                    Herramientas
                    <ChevronDown className="w-4 h-4 transition-transform group-hover:rotate-180" />
                  </button>
                  <div className="absolute top-full left-0 mt-2 w-64 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 bg-secondary border border-border rounded-xl shadow-2xl overflow-hidden z-[100]">
                    {toolsRoutes.map((route, idx) => (
                      <Link 
                        key={route.path} 
                        href={`/${locale}${route.path}`} 
                        className={`block px-5 py-3 text-secondary hover:text-primary hover:bg-hover transition-colors ${idx !== toolsRoutes.length - 1 ? 'border-b border-border' : ''}`}
                      >
                        <div className="font-urbanist font-semibold">{route.icon} {route.label}</div>
                        {route.description && (
                          <div className="text-xs text-muted font-dm-sans">{route.description}</div>
                        )}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
              
              {/* Guías SSDLC - Solo si está habilitado */}
              {isFeatureEnabled('SSDLC_GUIDES') && (
                <Link 
                  href={`/${locale}/guias`}
                  className="font-urbanist text-[17px] font-semibold text-secondary hover:text-primary transition-colors"
                >
                  Guías SSDLC
                </Link>
              )}
            </nav>

            {/* CTA Buttons - Desktop */}
            <div className="hidden lg:flex items-center gap-3">
              {/* API Docs - Solo si está habilitado */}
              {isFeatureEnabled('API_DOCS') && (
                <Link 
                  href={`/${locale}/docs`}
                  className="px-5 py-2.5 bg-hover hover:bg-accent border border-border hover:border-accent text-primary font-urbanist font-semibold text-[15px] rounded-lg transition-all duration-200"
                >
                  API Docs
                </Link>
              )}
              {/* CTA principal - siempre visible (apunta a Blue Team Labs) */}
              <Link 
                href={`/${locale}/labs/blue-team`}
                className="px-6 py-2.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-urbanist font-bold text-[15px] rounded-lg transition-all duration-200 shadow-lg shadow-blue-500/30 hover:shadow-blue-500/50"
              >
                Empezar Ahora
              </Link>
            </div>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="lg:hidden text-primary p-2"
              aria-label="Toggle menu"
            >
              {isMobileMenuOpen ? (
                <X className="w-6 h-6" />
              ) : (
                <Menu className="w-6 h-6" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="lg:hidden bg-secondary border-t border-border">
            <div className="px-6 py-4 space-y-3">
              <Link href={`/${locale}`} className="block py-2 text-primary font-urbanist font-semibold">
                Inicio
              </Link>
              
              {/* Red Team Labs */}
              {redTeamRoutes.length > 0 && (
                <div className="border-t border-border pt-3">
                  <div className="text-muted text-xs font-urbanist font-bold uppercase tracking-wider mb-2">Labs</div>
                  {redTeamRoutes.map(route => (
                    <Link key={route.path} href={`/${locale}${route.path}`} className="block py-2 text-secondary font-dm-sans pl-3">
                      <span className="flex items-center">
                        {getLabIcon(route.path)}
                        {route.label}
                      </span>
                    </Link>
                  ))}
                </div>
              )}
              
              {/* Tools */}
              {toolsRoutes.length > 0 && (
                <div className="border-t border-border pt-3">
                  <div className="text-muted text-xs font-urbanist font-bold uppercase tracking-wider mb-2">Herramientas</div>
                  {toolsRoutes.map(route => (
                    <Link key={route.path} href={`/${locale}${route.path}`} className="block py-2 text-secondary font-dm-sans pl-3">
                      {route.icon} {route.label}
                    </Link>
                  ))}
                </div>
              )}
              
              {/* Guías SSDLC */}
              {isFeatureEnabled('SSDLC_GUIDES') && (
                <Link href={`/${locale}/guias`} className="block py-2 text-primary font-urbanist font-semibold border-t border-border pt-3">
                  Guías SSDLC
                </Link>
              )}
              
              {/* API Docs */}
              {isFeatureEnabled('API_DOCS') && (
                <Link href={`/${locale}/docs`} className="block py-2 text-primary font-urbanist font-semibold">
                  API Docs
                </Link>
              )}
              
              <Link 
                href={`/${locale}/labs/blue-team`}
                className="block px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-urbanist font-bold text-center rounded-lg mt-4"
              >
                Empezar Ahora
              </Link>
            </div>
          </div>
        )}
      </header>
    </>
  );
}

