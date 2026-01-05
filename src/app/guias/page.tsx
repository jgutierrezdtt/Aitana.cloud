"use client";

import { useState } from "react";
import Navigation from "@/components/Navigation";
import ActivityModal from "@/components/ActivityModal";
import { cisoAreasData, type CISOArea } from "@/data/cisoAreas";
import { ssdlcPhasesData, ssdlcActivitiesData, type SSDLCPhase } from "@/data/ssdlcActivities";
import { activityDetailsMap } from "@/data/activityDetails";

export default function GuiasPage() {
  const [selectedArea, setSelectedArea] = useState<CISOArea>('governance');
  const [selectedPhase, setSelectedPhase] = useState<SSDLCPhase>('requirements');
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedActivity, setSelectedActivity] = useState<any>(null);

  const currentArea = cisoAreasData[selectedArea];
  const currentPhaseData = ssdlcActivitiesData[selectedPhase];

  const handleActivityClick = (activity: string, areaKey: string, phaseKey: string, activityIndex: number) => {
    const detailKey = `${phaseKey}_${areaKey}_${activityIndex}`;
    const detail = activityDetailsMap[detailKey];
    
    if (detail) {
      setSelectedActivity(detail);
      setModalOpen(true);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <Navigation />
      
      {/* Hero Section */}
      <div className="relative overflow-hidden border-b border-slate-800">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 via-purple-600/10 to-pink-600/10" />
        
        <div className="relative max-w-7xl mx-auto px-6 py-16">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-4 py-1.5 rounded-full bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30">
              <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
                CISO Security Framework
              </span>
            </div>
          </div>
          
          <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-white via-blue-100 to-purple-200 bg-clip-text text-transparent">
            Guías de Seguridad Empresarial
          </h1>
          
          <p className="text-xl text-slate-300 max-w-4xl leading-relaxed">
            Framework completo de gobierno, diseño, automatización y controles de seguridad 
            integrados en todo el ciclo de vida del desarrollo seguro (SSDLC)
          </p>
          
          {/* Stats */}
          <div className="grid grid-cols-4 gap-6 mt-12">
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
              <div className="text-3xl font-bold text-blue-400">4</div>
              <div className="text-sm text-slate-400 mt-1">Pilares CISO</div>
            </div>
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
              <div className="text-3xl font-bold text-purple-400">7</div>
              <div className="text-sm text-slate-400 mt-1">Fases SSDLC</div>
            </div>
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
              <div className="text-3xl font-bold text-green-400">100+</div>
              <div className="text-sm text-slate-400 mt-1">Controles</div>
            </div>
            <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
              <div className="text-3xl font-bold text-orange-400">15+</div>
              <div className="text-sm text-slate-400 mt-1">Frameworks</div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        
        {/* CISO Areas Selection */}
        <div className="mb-12">
          <h2 className="text-2xl font-bold text-white mb-6">Pilares de Seguridad Empresarial</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {(Object.keys(cisoAreasData) as CISOArea[]).map((areaKey) => {
              const area = cisoAreasData[areaKey];
              const isSelected = selectedArea === areaKey;
              
              return (
                <button
                  key={areaKey}
                  onClick={() => setSelectedArea(areaKey)}
                  className={`relative group p-6 rounded-xl border transition-all duration-300 text-left ${
                    isSelected
                      ? 'bg-gradient-to-br ' + area.gradient + ' border-white/20 shadow-2xl scale-105'
                      : 'bg-slate-800/50 border-slate-700 hover:border-slate-600 hover:bg-slate-800/70'
                  }`}
                >
                  <div className="text-4xl mb-3">{area.icon}</div>
                  <h3 className="text-lg font-bold text-white mb-2">{area.title}</h3>
                  <p className={`text-sm ${isSelected ? 'text-white/90' : 'text-slate-400'}`}>
                    {area.description}
                  </p>
                  
                  {isSelected && (
                    <div className="absolute top-4 right-4">
                      <div className="w-3 h-3 bg-white rounded-full animate-pulse" />
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Interactive SSDLC Lifecycle */}
        <div className="mb-16">
          <h2 className="text-2xl font-bold text-white mb-6">Ciclo de Vida del Desarrollo Seguro (SSDLC)</h2>
          
          <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-8">
            {/* SVG Interactive Lifecycle */}
            <div className="relative">
              <svg viewBox="0 0 1000 300" className="w-full h-auto">
                <path
                  d="M 70 150 Q 250 150 250 150 Q 400 150 400 150 Q 550 150 550 150 Q 700 150 700 150 Q 850 150 850 150 Q 930 150 930 150"
                  stroke="url(#lineGradient)"
                  strokeWidth="3"
                  fill="none"
                  strokeDasharray="5,5"
                  className="animate-pulse"
                />
                
                <defs>
                  <linearGradient id="lineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#3b82f6" />
                    <stop offset="20%" stopColor="#8b5cf6" />
                    <stop offset="40%" stopColor="#ec4899" />
                    <stop offset="60%" stopColor="#f59e0b" />
                    <stop offset="80%" stopColor="#10b981" />
                    <stop offset="100%" stopColor="#6366f1" />
                  </linearGradient>
                </defs>
                
                {ssdlcPhasesData.map((phase, index) => {
                  const x = 70 + index * 140;
                  const y = 150;
                  const isSelected = selectedPhase === phase.id;
                  
                  return (
                    <g key={phase.id} className="cursor-pointer" onClick={() => setSelectedPhase(phase.id)}>
                      {isSelected && (
                        <circle cx={x} cy={y} r="35" fill={phase.color} opacity="0.3" className="animate-ping" />
                      )}
                      
                      <circle
                        cx={x} cy={y} r="28"
                        fill={isSelected ? phase.color : '#1e293b'}
                        stroke={phase.color}
                        strokeWidth={isSelected ? '4' : '2'}
                        className="transition-all duration-300"
                      />
                      
                      <text x={x} y={y + 5} textAnchor="middle" fill="white" fontSize="16" fontWeight="bold">
                        {index + 1}
                      </text>
                      
                      <text x={x} y={y + 60} textAnchor="middle" fill={isSelected ? phase.color : '#94a3b8'} fontSize="13" fontWeight={isSelected ? 'bold' : 'normal'}>
                        {phase.name}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>

            {/* Selected Phase Activities - CLICKABLE */}
            <div className="mt-12 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {(Object.keys(cisoAreasData) as CISOArea[]).map((areaKey) => {
                const area = cisoAreasData[areaKey];
                const activities = currentPhaseData[areaKey];
                
                return (
                  <div key={areaKey} className="bg-slate-900/50 border border-slate-700 rounded-xl p-5">
                    <div className="flex items-center gap-2 mb-4">
                      <span className="text-2xl">{area.icon}</span>
                      <h4 className="text-sm font-bold text-white">{area.title}</h4>
                    </div>
                    
                    <ul className="space-y-2">
                      {activities.map((activity, idx) => (
                        <li key={idx}>
                          <button
                            onClick={() => handleActivityClick(activity, areaKey, selectedPhase, idx)}
                            className="flex items-start gap-2 text-xs text-slate-300 hover:text-blue-400 transition-colors w-full text-left group"
                          >
                            <span className="text-blue-400 mt-1 group-hover:scale-125 transition-transform">▹</span>
                            <span className="group-hover:underline">{activity}</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Detailed Content for Selected Area */}
        <div className="mb-12">
          <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl overflow-hidden">
            <div className={`bg-gradient-to-r ${currentArea.gradient} p-8`}>
              <div className="flex items-center gap-4">
                <div className="text-6xl">{currentArea.icon}</div>
                <div>
                  <h2 className="text-3xl font-bold text-white mb-2">{currentArea.title}</h2>
                  <p className="text-white/90 text-lg">{currentArea.description}</p>
                </div>
              </div>
            </div>

            <div className="p-8">
              <div className="space-y-6">
                {currentArea.pillars.map((pillar, index) => {
                  const isExpanded = expandedSection === `${selectedArea}-${index}`;
                  
                  return (
                    <div key={index} className="border border-slate-700 rounded-xl overflow-hidden bg-slate-900/50">
                      <button
                        onClick={() => setExpandedSection(isExpanded ? null : `${selectedArea}-${index}`)}
                        className="w-full p-6 flex items-center justify-between hover:bg-slate-800/50 transition-colors"
                      >
                        <div className="flex items-center gap-4">
                          <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${currentArea.gradient} flex items-center justify-center text-white font-bold`}>
                            {index + 1}
                          </div>
                          <h3 className="text-xl font-bold text-white text-left">{pillar.title}</h3>
                        </div>
                        <svg className={`w-6 h-6 text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>

                      {isExpanded && (
                        <div className="px-6 pb-6 border-t border-slate-700">
                          <ul className="space-y-3 mt-6">
                            {pillar.items.map((item, idx) => (
                              <li key={idx} className="flex items-start gap-3 text-slate-300">
                                <span className="text-blue-400 mt-1 flex-shrink-0">✓</span>
                                <span className="leading-relaxed">{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Compliance & Standards Footer */}
        <div className="bg-slate-800/30 backdrop-blur border border-slate-700 rounded-2xl p-8">
          <h3 className="text-xl font-bold text-white mb-6">Frameworks y Estándares Integrados</h3>
          
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            {[
              { name: 'OWASP', subtitle: 'Top 10 & SAMM' },
              { name: 'NIST', subtitle: '800-53 & CSF' },
              { name: 'ISO 27001', subtitle: 'ISMS' },
              { name: 'PCI-DSS', subtitle: 'v4.0' },
              { name: 'GDPR', subtitle: 'Privacy' },
              { name: 'SOC 2', subtitle: 'Trust Services' },
              { name: 'HIPAA', subtitle: 'Healthcare' },
              { name: 'CIS', subtitle: 'Benchmarks' },
              { name: 'MITRE', subtitle: 'ATT&CK' },
              { name: 'BSIMM', subtitle: 'Maturity' },
              { name: 'SANS', subtitle: 'Top 25 CWE' },
              { name: 'CSA', subtitle: 'Cloud Security' }
            ].map((framework, idx) => (
              <div key={idx} className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 text-center hover:border-blue-500/50 transition-colors">
                <div className="text-sm font-bold text-white">{framework.name}</div>
                <div className="text-xs text-slate-400 mt-1">{framework.subtitle}</div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Activity Modal */}
      <ActivityModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        activity={selectedActivity}
      />
    </div>
  );
}
