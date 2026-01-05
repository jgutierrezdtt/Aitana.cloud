'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import { useParams, usePathname } from 'next/navigation';
import { Search, BookOpen, AlertTriangle, Shield, Terminal, ChevronDown, ChevronRight, X } from 'lucide-react';

interface Article {
  slug: string;
  title: string;
  category: string;
  roles: ('Estudiante' | 'Junior Developer' | 'Mid-Level Developer' | 'Senior Developer' | 'Tech Lead' | 'DevSecOps' | 'Security Champion' | 'Pentester' | 'Security Expert' | 'CISO' | 'Security Manager' | 'Bug Bounty')[];
  tags: string[];
  time: string;
}

const allArticles: Article[] = [
  // Fundamentos - Conceptos base para estudiantes
  { slug: 'http-basico', title: 'HTTP: El Protocolo de la Web', category: 'fundamentos', roles: ['Estudiante'], tags: ['protocolos', 'web', 'basics'], time: '10 min' },
  { slug: 'cookies-sesiones', title: 'Cookies y Sesiones', category: 'fundamentos', roles: ['Estudiante'], tags: ['autenticación', 'sesiones', 'cookies'], time: '15 min' },
  { slug: 'autenticacion-autorizacion', title: 'Autenticación y Autorización', category: 'fundamentos', roles: ['Estudiante'], tags: ['autenticación', 'autorización', 'seguridad'], time: '18 min' },
  { slug: 'arquitectura-cliente-servidor', title: 'Arquitectura Cliente-Servidor', category: 'fundamentos', roles: ['Estudiante'], tags: ['arquitectura', 'web', 'basics'], time: '15 min' },
  { slug: 'apis-rest-seguridad', title: 'APIs REST y Seguridad', category: 'fundamentos', roles: ['Estudiante'], tags: ['api', 'rest', 'seguridad'], time: '20 min' },
  { slug: 'cors-same-origin', title: 'CORS y Same-Origin Policy', category: 'fundamentos', roles: ['Estudiante'], tags: ['cors', 'seguridad', 'navegador'], time: '16 min' },
  
  // Vulnerabilidades - Conocimiento base esencial
  { slug: 'sql-injection', title: 'SQL Injection (SQLi)', category: 'vulnerabilidades', roles: ['Estudiante'], tags: ['sql', 'inyección', 'crítico'], time: '20 min' },
  { slug: 'xss', title: 'Cross-Site Scripting (XSS)', category: 'vulnerabilidades', roles: ['Estudiante'], tags: ['xss', 'javascript', 'crítico'], time: '22 min' },
  { slug: 'csrf', title: 'Cross-Site Request Forgery (CSRF)', category: 'vulnerabilidades', roles: ['Estudiante'], tags: ['csrf', 'sesiones', 'alto'], time: '18 min' },
  { slug: 'idor', title: 'Insecure Direct Object References (IDOR)', category: 'vulnerabilidades', roles: ['Estudiante'], tags: ['idor', 'autorización', 'medio'], time: '15 min' },
  { slug: 'broken-authentication', title: 'Broken Authentication', category: 'vulnerabilidades', roles: ['Junior Developer'], tags: ['autenticación', 'sesiones', 'crítico'], time: '19 min' },
  { slug: 'command-injection', title: 'Command Injection', category: 'vulnerabilidades', roles: ['Junior Developer'], tags: ['inyección', 'comandos', 'crítico'], time: '20 min' },
  { slug: 'xxe', title: 'XML External Entity (XXE)', category: 'vulnerabilidades', roles: ['Junior Developer'], tags: ['xxe', 'xml', 'alto'], time: '25 min' },
  { slug: 'ssti', title: 'Server-Side Template Injection (SSTI)', category: 'vulnerabilidades', roles: ['Junior Developer'], tags: ['ssti', 'templates', 'crítico'], time: '24 min' },
  
  // Defensas - Prácticas básicas de seguridad
  { slug: 'input-validation', title: 'Validación de Entrada', category: 'defensas', roles: ['Estudiante'], tags: ['validación', 'sanitización', 'defensa'], time: '15 min' },
  { slug: 'output-encoding', title: 'Output Encoding', category: 'defensas', roles: ['Estudiante'], tags: ['encoding', 'xss', 'defensa'], time: '14 min' },
  { slug: 'parameterized-queries', title: 'Parameterized Queries', category: 'defensas', roles: ['Estudiante'], tags: ['sql', 'queries', 'defensa'], time: '16 min' },
  { slug: 'password-hashing', title: 'Password Hashing', category: 'defensas', roles: ['Junior Developer'], tags: ['passwords', 'hashing', 'criptografía'], time: '17 min' },
  { slug: 'csp', title: 'Content Security Policy (CSP)', category: 'defensas', roles: ['Junior Developer'], tags: ['csp', 'headers', 'xss'], time: '22 min' },
  { slug: 'security-headers', title: 'Security Headers', category: 'defensas', roles: ['Junior Developer'], tags: ['headers', 'configuración', 'defensa'], time: '18 min' },
  { slug: 'secure-sessions', title: 'Secure Session Management', category: 'defensas', roles: ['Junior Developer'], tags: ['sesiones', 'seguridad', 'jwt'], time: '20 min' },
  
  // Herramientas - Introducción para estudiantes
  { slug: 'nikto', title: 'Nikto', category: 'herramientas', roles: ['Estudiante'], tags: ['nikto', 'scanner', 'web'], time: '15 min' },
  { slug: 'owasp-zap', title: 'OWASP ZAP', category: 'herramientas', roles: ['Estudiante'], tags: ['zap', 'scanner', 'testing'], time: '22 min' },
  { slug: 'burp-suite', title: 'Burp Suite', category: 'herramientas', roles: ['Junior Developer'], tags: ['burp', 'proxy', 'testing'], time: '25 min' },
  { slug: 'sqlmap', title: 'SQLMap', category: 'herramientas', roles: ['Junior Developer'], tags: ['sqlmap', 'sql', 'automation'], time: '20 min' },
];

const categories = [
  { id: 'fundamentos', title: 'Fundamentos', icon: BookOpen, color: 'blue' },
  { id: 'vulnerabilidades', title: 'Vulnerabilidades', icon: AlertTriangle, color: 'red' },
  { id: 'defensas', title: 'Defensas', icon: Shield, color: 'green' },
  { id: 'herramientas', title: 'Herramientas', icon: Terminal, color: 'purple' },
];

export default function WikiSidebar() {
  const params = useParams();
  const pathname = usePathname();
  const locale = params.locale as string;

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<string[]>(['fundamentos', 'vulnerabilidades', 'defensas', 'herramientas']);

  const filteredArticles = useMemo(() => {
    return allArticles.filter(article => {
      const matchesSearch = 
        article.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        article.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
      
      const matchesCategory = !selectedCategory || article.category === selectedCategory;
      const matchesRole = !selectedRole || article.roles.includes(selectedRole as any);

      return matchesSearch && matchesCategory && matchesRole;
    });
  }, [searchQuery, selectedCategory, selectedRole]);

  const toggleCategory = (categoryId: string) => {
    setExpandedCategories(prev =>
      prev.includes(categoryId)
        ? prev.filter(id => id !== categoryId)
        : [...prev, categoryId]
    );
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'Estudiante': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'Junior Developer': return 'bg-green-400/20 text-green-300 border-green-400/30';
      case 'Mid-Level Developer': return 'bg-green-500/20 text-green-300 border-green-500/30';
      case 'Senior Developer': return 'bg-green-600/20 text-green-300 border-green-600/30';
      case 'Tech Lead': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
      case 'DevSecOps': return 'bg-teal-500/20 text-teal-300 border-teal-500/30';
      case 'Security Champion': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30';
      case 'Pentester': return 'bg-red-500/20 text-red-300 border-red-500/30';
      case 'Security Expert': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      case 'CISO': return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'Security Manager': return 'bg-pink-500/20 text-pink-300 border-pink-500/30';
      case 'Bug Bounty': return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      default: return 'bg-gray-500/20 text-gray-300 border-gray-500/30';
    }
  };

  const getCategoryColor = (categoryId: string) => {
    const category = categories.find(c => c.id === categoryId);
    return category?.color || 'gray';
  };

  return (
    <div className="w-80 bg-white dark:bg-slate-900 backdrop-blur-sm border-r border-slate-200 dark:border-slate-700 sticky top-16 h-[calc(100vh-4rem)] overflow-y-auto">
      <div className="p-6 space-y-6">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400 dark:text-slate-400" />
          <input
            type="text"
            placeholder="Buscar artículos..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-10 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Filters */}
        <div className="space-y-3">
          <div className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">Filtros</div>
          
          {/* Role Filter */}
          <div className="space-y-2">
            <div className="text-sm text-slate-700 dark:text-slate-300 font-medium">Nivel / Rol</div>
            <div className="flex flex-wrap gap-2">
              {['Estudiante', 'Junior Developer', 'Mid-Level Developer', 'Senior Developer', 'Tech Lead', 'DevSecOps', 'Security Champion', 'Pentester', 'Security Expert', 'CISO', 'Security Manager', 'Bug Bounty'].map(role => (
                <button
                  key={role}
                  onClick={() => setSelectedRole(selectedRole === role ? null : role)}
                  className={`px-3 py-1 rounded-lg text-xs font-medium border transition-all ${
                    selectedRole === role
                      ? getRoleColor(role)
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700'
                  }`}
                >
                  {role}
                </button>
              ))}
            </div>
          </div>

          {/* Category Filter */}
          <div className="space-y-2">
            <div className="text-sm text-slate-700 dark:text-slate-300 font-medium">Categoría</div>
            <div className="space-y-1">
              {categories.map(category => {
                const Icon = category.icon;
                const isSelected = selectedCategory === category.id;
                return (
                  <button
                    key={category.id}
                    onClick={() => setSelectedCategory(isSelected ? null : category.id)}
                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${
                      isSelected
                        ? `bg-${category.color}-500/20 text-${category.color}-600 dark:text-${category.color}-300 border border-${category.color}-500/30`
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-transparent hover:bg-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span className="flex-1 text-left">{category.title}</span>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      {allArticles.filter(a => a.category === category.id).length}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Clear Filters */}
          {(selectedCategory || selectedRole || searchQuery) && (
            <button
              onClick={() => {
                setSelectedCategory(null);
                setSelectedRole(null);
                setSearchQuery('');
              }}
              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-all border border-slate-200 dark:border-slate-700"
            >
              Limpiar filtros
            </button>
          )}
        </div>

        {/* Articles by Category */}
        <div className="space-y-4">
          <div className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
            Artículos ({filteredArticles.length})
          </div>
          
          {categories.map(category => {
            const Icon = category.icon;
            const categoryArticles = filteredArticles.filter(a => a.category === category.id);
            const isExpanded = expandedCategories.includes(category.id);

            if (categoryArticles.length === 0) return null;

            return (
              <div key={category.id} className="space-y-2">
                <button
                  onClick={() => toggleCategory(category.id)}
                  className="w-full flex items-center gap-2 px-3 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg text-sm font-medium text-slate-900 dark:text-white transition-all group"
                >
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-slate-500 dark:text-slate-400 group-hover:text-slate-900 dark:group-hover:text-white transition-colors" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-slate-500 dark:text-slate-400 group-hover:text-slate-900 dark:group-hover:text-white transition-colors" />
                  )}
                  <Icon className={`w-4 h-4 text-${category.color}-500 dark:text-${category.color}-400`} />
                  <span className="flex-1 text-left">{category.title}</span>
                  <span className="text-xs text-slate-500 dark:text-slate-400">{categoryArticles.length}</span>
                </button>

                {isExpanded && (
                  <div className="ml-6 space-y-1">
                    {categoryArticles.map(article => {
                      const isActive = pathname.includes(article.slug);
                      return (
                        <Link
                          key={article.slug}
                          href={`/${locale}/wiki/${article.category}/${article.slug}`}
                          className={`block px-3 py-2 rounded-lg text-sm transition-all ${
                            isActive
                              ? `bg-${category.color}-500/20 text-${category.color}-600 dark:text-${category.color}-300 border-l-2 border-${category.color}-500`
                              : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white border-l-2 border-transparent'
                          }`}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <span className="flex-1 leading-tight">{article.title}</span>
                            <span className="text-xs text-slate-500 dark:text-slate-500 whitespace-nowrap">{article.time}</span>
                          </div>
                          <div className="flex flex-wrap items-center gap-1 mt-1.5">
                            {article.roles.map(role => (
                              <span key={role} className={`text-xs px-1.5 py-0.5 rounded border ${getRoleColor(role)}`}>
                                {role}
                              </span>
                            ))}
                          </div>
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}

          {filteredArticles.length === 0 && (
            <div className="text-center py-8 text-slate-500 dark:text-slate-400">
              <Search className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p className="text-sm">No se encontraron artículos</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
