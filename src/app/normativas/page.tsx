"use client";

import { useState } from "react";
import Navigation from "@/components/Navigation";
import Link from "next/link";
import VulnerableChatbot from "@/components/VulnerableChatbot";
import { allRegulationsData, regulationCategories, getRegulationsStats } from "@/data/allRegulations";

export default function NormativasPage() {
  const regulations = Object.values(allRegulationsData);
  const stats = getRegulationsStats();
  
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMode, setChatMode] = useState<'normal' | 'vulnerable'>('normal');

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

  const getCategoryIcon = (category: string) => {
    const cat = regulationCategories.find(c => c.id === category);
    return cat?.icon || '📋';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <Navigation />

      {/* Hero */}
      <div className="relative overflow-hidden border-b border-slate-800">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 via-purple-600/10 to-pink-600/10" />
        
        <div className="relative max-w-7xl mx-auto px-6 py-16">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-4 py-1.5 rounded-full bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30">
              <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
                Compliance Framework
              </span>
            </div>
          </div>
          
          <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-white via-blue-100 to-purple-200 bg-clip-text text-transparent">
            Base de Datos de Normativas
          </h1>
          
          <p className="text-xl text-slate-300 max-w-4xl leading-relaxed">
            Catálogo completo de regulaciones, estándares y frameworks de seguridad con artículos literales, 
            requisitos específicos y mapeo a fases del SSDLC
          </p>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
              <div className="text-2xl font-bold text-white">{regulations.length}</div>
              <div className="text-sm text-slate-400">Normativas</div>
            </div>
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
              <div className="text-2xl font-bold text-white">
                {regulations.reduce((sum, r) => sum + r.keyRequirements.length, 0)}
              </div>
              <div className="text-sm text-slate-400">Artículos Documentados</div>
            </div>
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
              <div className="text-2xl font-bold text-white">7</div>
              <div className="text-sm text-slate-400">Fases SSDLC</div>
            </div>
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
              <div className="text-2xl font-bold text-white">5</div>
              <div className="text-sm text-slate-400">Categorías</div>
            </div>
          </div>
        </div>
      </div>

      {/* Regulations Grid */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {regulations.map((regulation) => (
            <Link
              key={regulation.id}
              href={`/normativas/${regulation.id}`}
              className="group bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl overflow-hidden hover:border-blue-500/50 transition-all hover:shadow-2xl hover:shadow-blue-500/20"
            >
              <div className={`bg-gradient-to-r ${categoryColors[regulation.category]} p-6`}>
                <div className="flex items-start justify-between mb-3">
                  <div className="text-5xl">{getCategoryIcon(regulation.category)}</div>
                  {regulation.certificationRequired && (
                    <div className="px-2 py-1 bg-white/20 rounded text-xs text-white font-semibold">
                      Certificación
                    </div>
                  )}
                </div>
                <h3 className="text-2xl font-bold text-white mb-2">{regulation.name}</h3>
                <p className="text-white/80 text-sm">{regulation.fullName}</p>
              </div>

              <div className="p-6 space-y-4">
                <p className="text-slate-300 text-sm line-clamp-3">{regulation.description}</p>

                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-400">Jurisdicción:</span>
                  <span className="text-slate-300">{regulation.jurisdiction.join(', ')}</span>
                </div>

                <div className="border-t border-slate-700 pt-4">
                  <div className="text-xs text-slate-400 mb-2">Artículos Documentados</div>
                  <div className="text-2xl font-bold text-white">{regulation.keyRequirements.length}</div>
                </div>

                <div className="flex flex-wrap gap-2">
                  {regulation.relatedStandards.slice(0, 3).map((standard, idx) => (
                    <span key={idx} className="px-2 py-1 bg-slate-700/50 text-slate-300 rounded text-xs">
                      {standard}
                    </span>
                  ))}
                  {regulation.relatedStandards.length > 3 && (
                    <span className="px-2 py-1 bg-slate-700/50 text-slate-400 rounded text-xs">
                      +{regulation.relatedStandards.length - 3}
                    </span>
                  )}
                </div>

                <div className="flex items-center justify-between pt-4 border-t border-slate-700">
                  <span className="text-sm text-blue-400 group-hover:text-blue-300">Ver detalles</span>
                  <svg className="w-5 h-5 text-blue-400 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                </div>
              </div>
            </Link>
          ))}
        </div>

        {/* CTA to Matrix */}
        <div className="mt-12 bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-2xl p-8 text-center">
          <div className="text-4xl mb-4">📊</div>
          <h2 className="text-2xl font-bold text-white mb-3">Matriz de Normativas y SSDLC</h2>
          <p className="text-slate-300 mb-6 max-w-2xl mx-auto">
            Explora el mapeo completo de todas las normativas a través de las 7 fases del ciclo de vida de desarrollo seguro
          </p>
          <Link
            href="/matriz-normativas"
            className="inline-block px-8 py-4 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-xl font-semibold transition-all shadow-xl"
          >
            Ver Matriz Completa
          </Link>
        </div>
      </div>

      {/* Floating Chat Button */}
      <div className="fixed bottom-6 right-6 z-40 flex flex-col gap-3">
        {/* Vulnerable Mode Toggle */}
        {chatOpen && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-3 shadow-2xl animate-fade-in">
            <div className="text-xs text-slate-400 mb-2 text-center">Modo del chatbot</div>
            <div className="flex gap-2">
              <button
                onClick={() => setChatMode('normal')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  chatMode === 'normal' 
                    ? 'bg-green-600 text-white' 
                    : 'bg-slate-700 text-slate-400 hover:text-white'
                }`}
              >
                🛡️ Normal
              </button>
              <button
                onClick={() => setChatMode('vulnerable')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  chatMode === 'vulnerable' 
                    ? 'bg-red-600 text-white' 
                    : 'bg-slate-700 text-slate-400 hover:text-white'
                }`}
              >
                ⚠️ Vulnerable
              </button>
            </div>
          </div>
        )}

        {/* Main Chat Button */}
        <button
          onClick={() => setChatOpen(!chatOpen)}
          className="group relative bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white p-5 rounded-full shadow-2xl transition-all hover:scale-110"
        >
          {chatOpen ? (
            <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
          )}
          
          {/* Pulse animation */}
          {!chatOpen && (
            <span className="absolute inset-0 rounded-full bg-blue-400 animate-ping opacity-75"></span>
          )}
        </button>

        {/* Tooltip */}
        {!chatOpen && (
          <div className="absolute bottom-0 right-full mr-4 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg shadow-xl whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
            <div className="text-sm text-white font-semibold">🤖 Asistente de Normativas</div>
            <div className="text-xs text-slate-400">Click para chatear (Modo normal o vulnerable)</div>
          </div>
        )}
      </div>

      {/* Chatbot Modal */}
      <VulnerableChatbot
        isOpen={chatOpen}
        onClose={() => setChatOpen(false)}
        mode={chatMode}
        onModeChange={setChatMode}
      />
    </div>
  );
}
