"use client";

import Link from "next/link";

interface ActivityModalProps {
  isOpen: boolean;
  onClose: () => void;
  activity: {
    title: string;
    area: string;
    phase: string;
    description: string;
    regulations: string[];
    tools: string[];
    bestPractices: string[];
    metrics: string[];
  } | null;
}

// Helper to convert regulation name to URL slug
function getRegulationSlug(regulation: string): string {
  const mapping: { [key: string]: string } = {
    'GDPR': 'gdpr',
    'ISO 27001': 'iso27001',
    'PCI-DSS': 'pci-dss',
    'NIST 800-53': 'nist-800-53',
    'SOC 2': 'soc2',
    'HIPAA': 'hipaa'
  };
  
  for (const [name, slug] of Object.entries(mapping)) {
    if (regulation.includes(name)) {
      return slug;
    }
  }
  
  return regulation.toLowerCase().replace(/\s+/g, '-');
}

export default function ActivityModal({ isOpen, onClose, activity }: ActivityModalProps) {
  if (!isOpen || !activity) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />
      
      {/* Modal */}
      <div className="relative bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 border border-slate-700 rounded-2xl max-w-4xl w-full max-h-[85vh] overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-purple-600 p-6">
          <div className="flex items-start justify-between">
            <div>
              <div className="text-sm text-blue-100 mb-2">
                {activity.area} → {activity.phase}
              </div>
              <h2 className="text-2xl font-bold text-white">
                {activity.title}
              </h2>
            </div>
            <button
              onClick={onClose}
              className="text-white/80 hover:text-white transition-colors"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(85vh-120px)]">
          {/* Description */}
          <div className="mb-6">
            <h3 className="text-lg font-bold text-white mb-3">📋 Descripción</h3>
            <p className="text-slate-300 leading-relaxed">{activity.description}</p>
          </div>

          {/* Regulations */}
          <div className="mb-6">
            <h3 className="text-lg font-bold text-white mb-3">⚖️ Normativas Aplicables</h3>
            <div className="flex flex-wrap gap-2">
              {activity.regulations.map((reg, idx) => {
                const slug = getRegulationSlug(reg);
                return (
                  <Link
                    key={idx}
                    href={`/normativas/${slug}`}
                    className="px-3 py-1.5 bg-green-500/10 border border-green-500/30 text-green-300 rounded-lg text-sm font-medium hover:bg-green-500/20 hover:border-green-500/50 transition-all hover:shadow-lg hover:shadow-green-500/20 hover:scale-105"
                  >
                    {reg} →
                  </Link>
                );
              })}
            </div>
          </div>

          {/* Tools */}
          <div className="mb-6">
            <h3 className="text-lg font-bold text-white mb-3">🛠️ Herramientas Recomendadas</h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {activity.tools.map((tool, idx) => (
                <div
                  key={idx}
                  className="px-4 py-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-300 text-sm text-center"
                >
                  {tool}
                </div>
              ))}
            </div>
          </div>

          {/* Best Practices */}
          <div className="mb-6">
            <h3 className="text-lg font-bold text-white mb-3">✨ Mejores Prácticas</h3>
            <ul className="space-y-2">
              {activity.bestPractices.map((practice, idx) => (
                <li key={idx} className="flex items-start gap-3 text-slate-300">
                  <span className="text-purple-400 mt-1">▸</span>
                  <span>{practice}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Metrics */}
          <div>
            <h3 className="text-lg font-bold text-white mb-3">📊 Métricas de Éxito</h3>
            <div className="space-y-2">
              {activity.metrics.map((metric, idx) => (
                <div
                  key={idx}
                  className="px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-slate-300 text-sm"
                >
                  {metric}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
