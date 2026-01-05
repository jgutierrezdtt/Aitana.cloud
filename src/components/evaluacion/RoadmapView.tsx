"use client";

interface RoadmapViewProps {
  sector: string;
  sectorActions: {
    short: string[];
    medium: string[];
    long: string[];
  };
}

export default function RoadmapView({ sector, sectorActions }: RoadmapViewProps) {
  return (
    <div>
      <h3 className="text-lg font-bold text-white mb-4">
        Roadmap de Mejora Recomendado (12 meses) - Sector: {sector}
      </h3>

      <div className="space-y-4">
        <div className="bg-indigo-900/20 border border-indigo-800 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="font-semibold text-indigo-200">Corto plazo (0-3 meses)</span>
          </div>
          <ul className="text-sm text-slate-300 ml-4">
            {sectorActions.short.map((s, i) => (
              <li key={i}>• {s}</li>
            ))}
          </ul>
        </div>

        <div className="bg-indigo-900/15 border border-indigo-800 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-indigo-400 rounded-full"></div>
            <span className="font-semibold text-indigo-200">Medio plazo (3-9 meses)</span>
          </div>
          <ul className="text-sm text-slate-300 ml-4">
            {sectorActions.medium.map((s, i) => (
              <li key={i}>• {s}</li>
            ))}
          </ul>
        </div>

        <div className="bg-indigo-900/10 border border-indigo-800 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-indigo-300 rounded-full"></div>
            <span className="font-semibold text-indigo-200">Largo plazo (9-12+ meses)</span>
          </div>
          <ul className="text-sm text-slate-300 ml-4">
            {sectorActions.long.map((s, i) => (
              <li key={i}>• {s}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
