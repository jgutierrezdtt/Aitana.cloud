"use client";

import { useParams } from "next/navigation";
import Navigation from "@/components/Navigation";
import Link from "next/link";
import { allRegulationsData } from "@/data/allRegulations";

export default function RegulationDetailPage() {
  const params = useParams();
  const regulationId = params.id as string;
  const regulation = allRegulationsData[regulationId];

  if (!regulation) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
        <Navigation />
        <div className="max-w-7xl mx-auto px-6 py-20 text-center">
          <h1 className="text-4xl font-bold text-white mb-4">Normativa no encontrada</h1>
          <Link href="/normativas" className="text-blue-400 hover:text-blue-300">
            Volver a normativas
          </Link>
        </div>
      </div>
    );
  }

  const categoryColors: Record<string, string> = {
    privacy: 'from-blue-600 to-cyan-600',
    security: 'from-purple-600 to-pink-600',
    financial: 'from-green-600 to-emerald-600',
    healthcare: 'from-red-600 to-orange-600',
    european: 'from-blue-700 to-indigo-600',
    spanish: 'from-yellow-600 to-orange-600',
    industrial: 'from-orange-600 to-red-600',
    automotive: 'from-cyan-600 to-blue-600',
    ai: 'from-pink-600 to-purple-600',
    general: 'from-gray-600 to-slate-600'
  };

  const categoryIcons: Record<string, string> = {
    privacy: '🔒',
    security: '🛡️',
    financial: '💳',
    healthcare: '🏥',
    european: '🇪🇺',
    spanish: '🇪🇸',
    industrial: '🏭',
    automotive: '🚗',
    ai: '🤖',
    general: '📋'
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <Navigation />

      {/* Hero Section */}
      <div className={`relative overflow-hidden border-b border-slate-800 bg-gradient-to-r ${categoryColors[regulation.category]}`}>
        <div className="absolute inset-0 opacity-10 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmYiIGZpbGwtb3BhY2l0eT0iMSI+PHBhdGggZD0iTTM2IDM0djItMnptMC0xMHYyLTJ6bTEwIDEwdjItMnptMC0xMHYyLTJ6TTI2IDM0djItMnptMC0xMHYyLTJ6bTEwIDIwdjItMnptMTAgMHYyLTJ6bS0yMCAwdjItMnoiLz48L2c+PC9nPjwvc3ZnPg==')]" />
        
        <div className="relative max-w-7xl mx-auto px-6 py-16">
          <Link href="/normativas" className="inline-flex items-center gap-2 text-white/80 hover:text-white mb-6 transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Volver a Normativas
          </Link>

          <div className="flex items-start gap-6">
            <div className="text-7xl">{categoryIcons[regulation.category]}</div>
            <div className="flex-1">
              <div className="inline-block px-3 py-1 bg-white/20 rounded-full text-white text-sm font-semibold mb-3">
                {regulation.jurisdiction.join(' • ')}
              </div>
              <h1 className="text-5xl font-bold text-white mb-3">{regulation.name}</h1>
              <p className="text-2xl text-white/90 mb-4">{regulation.fullName}</p>
              <p className="text-lg text-white/80 max-w-4xl">{regulation.description}</p>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
            <div className="bg-white/10 backdrop-blur rounded-xl p-4">
              <div className="text-sm text-white/70">Artículos</div>
              <div className="text-2xl font-bold text-white">{regulation.keyRequirements.length}</div>
            </div>
            <div className="bg-white/10 backdrop-blur rounded-xl p-4">
              <div className="text-sm text-white/70">Categoría</div>
              <div className="text-2xl font-bold text-white capitalize">{regulation.category}</div>
            </div>
            <div className="bg-white/10 backdrop-blur rounded-xl p-4">
              <div className="text-sm text-white/70">Certificación</div>
              <div className="text-2xl font-bold text-white">{regulation.certificationRequired ? 'Requerida' : 'Opcional'}</div>
            </div>
            <div className="bg-white/10 backdrop-blur rounded-xl p-4">
              <div className="text-sm text-white/70">Estándares</div>
              <div className="text-2xl font-bold text-white">{regulation.relatedStandards.length}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Main Column */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Purpose */}
            <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-8">
              <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                <span>🎯</span> Propósito
              </h2>
              <p className="text-slate-300 text-lg leading-relaxed">{regulation.purpose}</p>
            </div>

            {/* Applicability */}
            <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-8">
              <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                <span>🏢</span> Aplicabilidad
              </h2>
              <ul className="space-y-3">
                {regulation.applicability.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-3 text-slate-300">
                    <span className="text-blue-400 mt-1">▹</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Key Requirements - Artículos Literales */}
            <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-8">
              <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                <span>📜</span> Artículos y Requisitos Clave
              </h2>
              
              <div className="space-y-6">
                {regulation.keyRequirements.map((req, idx) => (
                  <div key={idx} className="border border-slate-700 rounded-xl overflow-hidden">
                    <div className={`bg-gradient-to-r ${categoryColors[regulation.category]} p-4`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-sm text-white/70 mb-1">{req.article}</div>
                          <h3 className="text-xl font-bold text-white">{req.title}</h3>
                        </div>
                        <div className="flex gap-2">
                          {req.ssdlcPhases.map((phase, pidx) => (
                            <span key={pidx} className="px-2 py-1 bg-white/20 rounded text-xs text-white">
                              {phase}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-slate-900/50 p-6 space-y-4">
                      <div>
                        <div className="text-sm text-slate-400 mb-2">Descripción</div>
                        <p className="text-slate-300">{req.description}</p>
                      </div>
                      
                      <div className="border-t border-slate-700 pt-4">
                        <div className="text-sm text-slate-400 mb-2">Texto Literal</div>
                        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                          <p className="text-slate-300 italic leading-relaxed">"{req.literal}"</p>
                        </div>
                      </div>

                      <div className="border-t border-slate-700 pt-4">
                        <div className="text-sm text-slate-400 mb-2">Fases SSDLC Aplicables</div>
                        <div className="flex flex-wrap gap-2">
                          {req.ssdlcPhases.map((phase, pidx) => (
                            <Link
                              key={pidx}
                              href={`/matriz-normativas?phase=${phase}`}
                              className="px-3 py-1.5 bg-blue-500/10 border border-blue-500/30 text-blue-300 rounded-lg text-sm hover:bg-blue-500/20 transition-colors"
                            >
                              {phase}
                            </Link>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Penalties */}
            <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-8">
              <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                <span>⚠️</span> Penalizaciones
              </h2>
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                <p className="text-red-300">{regulation.penalties}</p>
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            
            {/* References */}
            <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-6 sticky top-6">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <span>🔗</span> Referencias Oficiales
              </h3>
              
              <div className="space-y-4">
                <div>
                  <div className="text-sm text-slate-400 mb-2">Sitio Oficial</div>
                  <a
                    href={regulation.references.official}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 text-sm underline break-all"
                  >
                    {regulation.references.official}
                  </a>
                </div>

                {regulation.references.guidelines.length > 0 && (
                  <div>
                    <div className="text-sm text-slate-400 mb-2">Guías y Documentación</div>
                    <ul className="space-y-2">
                      {regulation.references.guidelines.map((guide, idx) => (
                        <li key={idx}>
                          <a
                            href={guide}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 text-sm underline break-all"
                          >
                            Guía {idx + 1}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {regulation.references.tools.length > 0 && (
                  <div>
                    <div className="text-sm text-slate-400 mb-2">Herramientas Recomendadas</div>
                    <ul className="space-y-2">
                      {regulation.references.tools.map((tool, idx) => (
                        <li key={idx} className="flex items-center gap-2 text-slate-300 text-sm">
                          <span className="text-green-400">✓</span>
                          <span>{tool}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            {/* Related Standards */}
            <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-6">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                <span>🔄</span> Estándares Relacionados
              </h3>
              <div className="space-y-2">
                {regulation.relatedStandards.map((standard, idx) => (
                  <div key={idx} className="bg-slate-900/50 border border-slate-700 rounded-lg p-3 text-sm text-slate-300">
                    {standard}
                  </div>
                ))}
              </div>
            </div>

            {/* CTA */}
            <Link
              href="/matriz-normativas"
              className="block bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-xl p-6 text-center transition-all shadow-xl"
            >
              <div className="text-2xl mb-2">📊</div>
              <div className="font-bold mb-1">Ver Matriz de Normativas</div>
              <div className="text-sm text-white/80">Mapeo completo con SSDLC</div>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
