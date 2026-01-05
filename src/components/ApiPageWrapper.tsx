import Navigation from "./Navigation";

interface ApiPageWrapperProps {
  title: string;
  description: string;
  severity?: "critical" | "high" | "medium" | "low";
  children: React.ReactNode;
  color?: string;
}

export default function ApiPageWrapper({ 
  title, 
  description, 
  severity = "medium",
  children,
  color = "from-blue-500 to-cyan-500"
}: ApiPageWrapperProps) {
  const severityColors = {
    critical: "bg-red-100 dark:bg-red-500/20 border-red-300 dark:border-red-400/30 text-red-700 dark:text-red-300",
    high: "bg-orange-100 dark:bg-orange-500/20 border-orange-300 dark:border-orange-400/30 text-orange-700 dark:text-orange-300",
    medium: "bg-yellow-100 dark:bg-yellow-500/20 border-yellow-300 dark:border-yellow-400/30 text-yellow-700 dark:text-yellow-300",
    low: "bg-blue-100 dark:bg-blue-500/20 border-blue-300 dark:border-blue-400/30 text-blue-700 dark:text-blue-300",
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gradient-to-br dark:from-slate-900 dark:via-blue-900 dark:to-slate-900">
      <div className="absolute inset-0 z-0 pointer-events-none">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiMzYjgyZjYiIGZpbGwtb3BhY2l0eT0iMC4xIj48cGF0aCBkPSJNMzYgMzRjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0wLTEwYzAtMi4yMS0xLjc5LTQtNC00cy00IDEuNzktNCA0IDEuNzkgNCA0IDQgNC0xLjc5IDQtNHptMTAgMTBjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0wLTEwYzAtMi4yMS0xLjcktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00ek0yNiAzNGMwLTIuMjEtMS43OS00LTQtNHMtNCAxLjc5LTQgNCAxLjc5IDQgNCA0IDQtMS43OSA0LTR6bTAtMTBjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0xMCAyMGMwLTIuMjEtMS43OS00LTQtNHMtNCAxLjc5LTQgNCAxLjc5IDQgNCA0IDQtMS43OSA0LTR6bTEwIDBjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0tMjAgMGMwLTIuMjEtMS43OS00LTQtNHMtNCAxLjc5LTQgNCAxLjc5IDQgNCA0IDQtMS43OSA0LTR6Ii8+PC9nPjwvZz48L3N2Zz4=')] opacity-5 dark:opacity-20"></div>
      </div>

      <div className="relative z-20">
        <Navigation />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-6 py-12">
        <div className="mb-8">
          <div className="flex items-center gap-4 mb-4">
            <div className={`inline-block px-4 py-2 rounded-full border ${severityColors[severity]} text-sm font-medium`}>
              {severity.toUpperCase()}
            </div>
          </div>
          <h1 className={`text-5xl md:text-6xl font-black mb-4 bg-gradient-to-r ${color} bg-clip-text text-transparent`}>
            {title}
          </h1>
          <p className="text-xl text-gray-600 dark:text-blue-200/80 max-w-3xl">
            {description}
          </p>
        </div>

        <div className="bg-white dark:bg-white/5 backdrop-blur-sm border border-gray-200 dark:border-white/10 rounded-3xl p-8 shadow-lg dark:shadow-none">
          {children}
        </div>
      </div>

      <div className="relative z-10 border-t border-gray-200 dark:border-white/10 backdrop-blur-sm bg-white/80 dark:bg-white/5 mt-12">
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="text-center text-gray-500 dark:text-blue-200/40 text-sm">
            <p>Esta aplicación es vulnerable por diseño - Solo para propósitos educativos</p>
            <p className="mt-2">© 2025 Aitana Security Lab</p>
          </div>
        </div>
      </div>
    </div>
  );
}
