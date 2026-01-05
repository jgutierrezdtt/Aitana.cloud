"use client";

import Navigation from "@/components/Navigation";
import Link from "next/link";
import { useState } from "react";
import { allRegulationsData } from "@/data/allRegulations";
import { ssdlcPhasesData } from "@/data/ssdlcActivities";

export default function MatrizNormativasPage() {
  const regulations = Object.values(allRegulationsData);
  const phases = ssdlcPhasesData;
  
  const [selectedCell, setSelectedCell] = useState<{reg: string, phase: string} | null>(null);

  // Calculate requirements count for each cell
  const getRequirementsCount = (regulationId: string, phaseId: string): number => {
    const regulation = allRegulationsData[regulationId];
    if (!regulation) return 0;
    
    return regulation.keyRequirements.filter(req => 
      req.ssdlcPhases.includes(phaseId)
    ).length;
  };

  // Get requirements for a specific cell
  const getCellRequirements = (regulationId: string, phaseId: string) => {
    const regulation = allRegulationsData[regulationId];
    if (!regulation) return [];
    
    return regulation.keyRequirements.filter(req => 
      req.ssdlcPhases.includes(phaseId)
    );
  };

  // Color intensity based on count
  const getColorIntensity = (count: number): string => {
    if (count === 0) return 'bg-slate-800/30 border-slate-700/50';
    if (count === 1) return 'bg-blue-500/20 border-blue-500/30';
    if (count === 2) return 'bg-blue-500/40 border-blue-500/50';
    if (count >= 3) return 'bg-blue-500/60 border-blue-500/70';
    return 'bg-slate-800/30';
  };

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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <Navigation />

      {/* Hero */}
      <div className="relative overflow-hidden border-b border-slate-800">
        <div className="absolute inset-0 bg-gradient-to-r from-purple-600/10 via-blue-600/10 to-cyan-600/10" />
        
        <div className="relative max-w-7xl mx-auto px-6 py-16">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-4 py-1.5 rounded-full bg-gradient-to-r from-purple-500/20 to-blue-500/20 border border-purple-500/30">
              <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">
                Compliance Matrix
              </span>
            </div>
          </div>
          
          <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-white via-purple-100 to-blue-200 bg-clip-text text-transparent">
            Matriz de Normativas y SSDLC
          </h1>
          
          <p className="text-xl text-slate-300 max-w-4xl leading-relaxed">
            Mapeo completo de requisitos normativos a través de las 7 fases del ciclo de vida de desarrollo seguro. 
            Haz clic en cualquier celda para ver los artículos aplicables.
          </p>

          {/* Legend */}
          <div className="flex flex-wrap items-center gap-4 mt-8">
            <span className="text-sm text-slate-400">Intensidad:</span>
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-slate-800/30 border border-slate-700/50 rounded" />
              <span className="text-xs text-slate-400">0</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-blue-500/20 border border-blue-500/30 rounded" />
              <span className="text-xs text-slate-400">1</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-blue-500/40 border border-blue-500/50 rounded" />
              <span className="text-xs text-slate-400">2</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-blue-500/60 border border-blue-500/70 rounded" />
              <span className="text-xs text-slate-400">3+</span>
            </div>
          </div>
        </div>
      </div>

      {/* Matrix */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="sticky left-0 bg-slate-900 p-4 text-left text-slate-400 font-semibold w-48">
                    Normativa
                  </th>
                  {phases.map((phase) => (
                    <th 
                      key={phase.id} 
                      className="p-4 text-center text-slate-400 font-semibold min-w-32 border-l border-slate-700"
                    >
                      <div className="flex flex-col items-center gap-1">
                        <div className={`w-3 h-3 rounded-full ${phase.color}`} />
                        <span className="text-xs">{phase.name}</span>
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {regulations.map((regulation) => (
                  <tr key={regulation.id} className="border-b border-slate-700/50 hover:bg-slate-800/50">
                    <td className="sticky left-0 bg-slate-900 p-4">
                      <Link 
                        href={`/normativas/${regulation.id}`}
                        className="flex items-center gap-3 hover:opacity-80 transition-opacity"
                      >
                        <div className={`w-10 h-10 rounded-lg bg-gradient-to-r ${categoryColors[regulation.category]} flex items-center justify-center text-white font-bold text-sm`}>
                          {regulation.name.substring(0, 2)}
                        </div>
                        <div>
                          <div className="text-white font-semibold text-sm">{regulation.name}</div>
                          <div className="text-slate-400 text-xs">{regulation.category}</div>
                        </div>
                      </Link>
                    </td>
                    {phases.map((phase) => {
                      const count = getRequirementsCount(regulation.id, phase.id);
                      return (
                        <td 
                          key={phase.id}
                          className="p-2 border-l border-slate-700/50"
                        >
                          <button
                            onClick={() => setSelectedCell({reg: regulation.id, phase: phase.id})}
                            className={`w-full h-16 ${getColorIntensity(count)} rounded-lg border transition-all hover:scale-105 hover:shadow-lg flex items-center justify-center cursor-pointer`}
                          >
                            {count > 0 && (
                              <span className="text-white font-bold text-lg">{count}</span>
                            )}
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Total Statistics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
            <div className="text-2xl font-bold text-white">{regulations.length}</div>
            <div className="text-sm text-slate-400">Normativas</div>
          </div>
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
            <div className="text-2xl font-bold text-white">{phases.length}</div>
            <div className="text-sm text-slate-400">Fases SSDLC</div>
          </div>
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
            <div className="text-2xl font-bold text-white">
              {regulations.reduce((sum, r) => sum + r.keyRequirements.length, 0)}
            </div>
            <div className="text-sm text-slate-400">Total Artículos</div>
          </div>
          <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-4">
            <div className="text-2xl font-bold text-white">
              {(() => {
                let total = 0;
                regulations.forEach(reg => {
                  phases.forEach(phase => {
                    total += getRequirementsCount(reg.id, phase.id);
                  });
                });
                return total;
              })()}
            </div>
            <div className="text-sm text-slate-400">Mapeos Totales</div>
          </div>
        </div>
      </div>

      {/* Cell Detail Modal */}
      {selectedCell && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div 
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            onClick={() => setSelectedCell(null)}
          />
          
          <div className="relative bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full max-h-[85vh] overflow-hidden shadow-2xl">
            {(() => {
              const regulation = allRegulationsData[selectedCell.reg];
              const phase = phases.find(p => p.id === selectedCell.phase);
              const requirements = getCellRequirements(selectedCell.reg, selectedCell.phase);

              return (
                <>
                  <div className={`bg-gradient-to-r ${categoryColors[regulation.category]} p-6`}>
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="text-sm text-white/80 mb-2">
                          {regulation.name} × {phase?.name}
                        </div>
                        <h2 className="text-2xl font-bold text-white">
                          Requisitos Aplicables
                        </h2>
                      </div>
                      <button
                        onClick={() => setSelectedCell(null)}
                        className="text-white/80 hover:text-white transition-colors"
                      >
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  <div className="p-6 overflow-y-auto max-h-[calc(85vh-120px)]">
                    {requirements.length === 0 ? (
                      <div className="text-center text-slate-400 py-8">
                        <div className="text-4xl mb-3">📋</div>
                        <p>No hay requisitos específicos para esta fase</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {requirements.map((req, idx) => (
                          <div key={idx} className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
                            <div className="flex items-start justify-between mb-3">
                              <div>
                                <div className="text-blue-400 font-mono text-sm mb-1">{req.article}</div>
                                <h3 className="text-white font-semibold">{req.title}</h3>
                              </div>
                            </div>
                            
                            <p className="text-slate-300 text-sm mb-4">{req.description}</p>
                            
                            {req.literal && (
                              <div className="bg-slate-900/50 border-l-4 border-blue-500 p-4 rounded">
                                <div className="text-xs text-slate-400 mb-2">Texto Literal</div>
                                <p className="text-slate-300 text-sm italic">"{req.literal}"</p>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="mt-6 pt-6 border-t border-slate-700 flex gap-3">
                      <Link
                        href={`/normativas/${selectedCell.reg}`}
                        className="flex-1 px-4 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold text-center transition-all"
                      >
                        Ver Normativa Completa
                      </Link>
                      <button
                        onClick={() => setSelectedCell(null)}
                        className="px-4 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-xl font-semibold transition-all"
                      >
                        Cerrar
                      </button>
                    </div>
                  </div>
                </>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
}
