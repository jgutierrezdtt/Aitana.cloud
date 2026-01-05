"use client";

interface SectorSelectorProps {
  sector: string;
  onChange: (sector: string) => void;
}

export default function SectorSelector({ sector, onChange }: SectorSelectorProps) {
  return (
    <div className="mb-6" role="group" aria-labelledby="sector-label">
      <label 
        id="sector-label"
        htmlFor="sector-select"
        className="text-sm text-slate-300 mr-3 font-medium"
      >
        Sector:
      </label>
      <select
        id="sector-select"
        value={sector}
        onChange={(e) => onChange(e.target.value)}
        className="bg-slate-800 text-slate-200 px-3 py-2 rounded-md border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
        aria-describedby="sector-description"
      >
        <option value="general">General / Multisector</option>
        <option value="financiero">Financiero</option>
        <option value="salud">Salud</option>
        <option value="industrial">Industrial / OT</option>
        <option value="tecnologia">Tecnología / SaaS</option>
      </select>
      <span id="sector-description" className="text-xs text-slate-400 ml-3">
        Selecciona el sector para adaptar recomendaciones y roadmap
      </span>
    </div>
  );
}
