"use client";

interface MaturityChartProps {
  icon: string;
  name: string;
  currentScore: number;
  projectedScores: number[];
  color: string;
  shortActions: string[];
}

export default function MaturityChart({ 
  icon, 
  name, 
  currentScore, 
  projectedScores, 
  color,
  shortActions 
}: MaturityChartProps) {
  return (
    <div className="bg-slate-900/40 rounded-lg p-4 border border-slate-700">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <div className="text-2xl">{icon}</div>
          <div>
            <div className="font-semibold text-white">{name}</div>
            <div className="text-xs text-slate-400">Actual: {currentScore}/5</div>
          </div>
        </div>
        <div className="text-xs text-slate-400">Proyección trimestral</div>
      </div>

      <svg width="100%" height="48" viewBox="0 0 200 48" className="mb-2">
        {projectedScores.map((p, i) => {
          const x = i * 40 + 10;
          const h = (p / 5) * 36;
          return (
            <g key={i}>
              <rect 
                x={x} 
                y={40 - h} 
                width={28} 
                height={h} 
                rx={3} 
                fill="#7c3aed" 
                opacity={i === 0 ? 0.9 : 0.7} 
              />
              <text x={x + 14} y={44} fontSize="8" fill="#cbd5e1" textAnchor="middle">
                Q{i}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="text-xs text-slate-300">
        Acciones cortas: {shortActions.slice(0, 2).join(', ')}
      </div>
    </div>
  );
}
