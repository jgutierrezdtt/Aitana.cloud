import Link from "next/link";
import { usePathname } from "next/navigation";

interface UnifiedNavLink {
  href: string;
  label: string;
  icon: string;
  description: string;
  badge?: string;
}

const navLinks: UnifiedNavLink[] = [
  {
    href: "/guias",
    label: "Guías SSDLC",
    icon: "📚",
    description: "Framework CISO y ciclo de vida seguro"
  },
  {
    href: "/normativas",
    label: "Normativas",
    icon: "📋",
    description: "18 regulaciones y estándares"
  },
  {
    href: "/matriz-normativas",
    label: "Matriz de Cumplimiento",
    icon: "🎯",
    description: "Mapeo normativas × SSDLC"
  },
  {
    href: "/evaluacion-madurez",
    label: "Evaluador de Madurez",
    icon: "📊",
    description: "Assessment por sectores industriales",
    badge: "Nuevo"
  }
];

export default function UnifiedNavigation() {
  const pathname = usePathname();

  return (
    <div className="bg-slate-900/50 border-b border-slate-800 mb-8">
      <div className="max-w-7xl mx-auto px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 py-6">
          {navLinks.map((link) => {
            const isActive = pathname === link.href || pathname?.startsWith(link.href + '/');
            
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`group relative p-4 rounded-xl border transition-all duration-300 ${
                  isActive
                    ? 'bg-gradient-to-br from-blue-600/20 to-purple-600/20 border-blue-500/50 shadow-lg shadow-blue-500/20'
                    : 'bg-slate-800/50 border-slate-700 hover:border-slate-600 hover:bg-slate-800/80'
                }`}
              >
                {link.badge && (
                  <div className="absolute -top-2 -right-2 px-2 py-0.5 bg-gradient-to-r from-green-500 to-emerald-500 text-white text-xs font-bold rounded-full shadow-lg">
                    {link.badge}
                  </div>
                )}
                
                <div className="flex items-start gap-3">
                  <div className={`text-3xl transition-transform duration-300 ${
                    isActive ? 'scale-110' : 'group-hover:scale-110'
                  }`}>
                    {link.icon}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className={`font-semibold mb-1 transition-colors ${
                      isActive ? 'text-white' : 'text-slate-200 group-hover:text-white'
                    }`}>
                      {link.label}
                    </div>
                    <div className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors">
                      {link.description}
                    </div>
                  </div>
                </div>

                {isActive && (
                  <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-500 to-purple-500 rounded-b-xl" />
                )}
              </Link>
            );
          })}
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-3 gap-4 pb-6 text-center">
          <div className="bg-slate-800/30 rounded-lg p-3">
            <div className="text-2xl font-bold text-blue-400">18</div>
            <div className="text-xs text-slate-400">Normativas</div>
          </div>
          <div className="bg-slate-800/30 rounded-lg p-3">
            <div className="text-2xl font-bold text-purple-400">68</div>
            <div className="text-xs text-slate-400">Controles</div>
          </div>
          <div className="bg-slate-800/30 rounded-lg p-3">
            <div className="text-2xl font-bold text-green-400">10</div>
            <div className="text-xs text-slate-400">Sectores</div>
          </div>
        </div>
      </div>
    </div>
  );
}
