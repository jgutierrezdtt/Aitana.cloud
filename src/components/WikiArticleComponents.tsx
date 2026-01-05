'use client';

import { ReactNode } from 'react';
import { 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  XCircle,
  Lightbulb,
  Code2,
  Terminal,
  Copy,
  Check
} from 'lucide-react';
import { useState } from 'react';

// Section Component
interface SectionProps {
  id?: string;
  title: string;
  children: ReactNode;
  className?: string;
}

export function Section({ id, title, children, className = '' }: SectionProps) {
  return (
    <section id={id} className={`scroll-mt-24 ${className}`}>
      <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 pb-3 border-b border-slate-200 dark:border-slate-800">
        {title}
      </h2>
      <div className="space-y-6">
        {children}
      </div>
    </section>
  );
}

// Subsection Component
interface SubsectionProps {
  id?: string;
  title: string;
  children: ReactNode;
  className?: string;
}

export function Subsection({ id, title, children, className = '' }: SubsectionProps) {
  return (
    <div id={id} className={`scroll-mt-24 ${className}`}>
      <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">
        {title}
      </h3>
      {children}
    </div>
  );
}

// Alert Components
interface AlertProps {
  children: ReactNode;
  title?: string;
}

export function AlertInfo({ children, title }: AlertProps) {
  return (
    <div className="bg-blue-50 dark:bg-blue-950/30 border-l-4 border-blue-500 rounded-r-xl p-6">
      <div className="flex gap-4">
        <Info className="w-6 h-6 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          {title && (
            <h4 className="text-lg font-bold text-blue-900 dark:text-blue-300 mb-2">
              {title}
            </h4>
          )}
          <div className="text-blue-900 dark:text-blue-300 leading-relaxed">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

export function AlertWarning({ children, title }: AlertProps) {
  return (
    <div className="bg-yellow-50 dark:bg-yellow-950/30 border-l-4 border-yellow-500 rounded-r-xl p-6">
      <div className="flex gap-4">
        <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          {title && (
            <h4 className="text-lg font-bold text-yellow-900 dark:text-yellow-300 mb-2">
              {title}
            </h4>
          )}
          <div className="text-yellow-900 dark:text-yellow-300 leading-relaxed">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

export function AlertDanger({ children, title }: AlertProps) {
  return (
    <div className="bg-red-50 dark:bg-red-950/30 border-l-4 border-red-500 rounded-r-xl p-6">
      <div className="flex gap-4">
        <XCircle className="w-6 h-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          {title && (
            <h4 className="text-lg font-bold text-red-900 dark:text-red-300 mb-2">
              {title}
            </h4>
          )}
          <div className="text-red-900 dark:text-red-300 leading-relaxed">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

export function AlertSuccess({ children, title }: AlertProps) {
  return (
    <div className="bg-green-50 dark:bg-green-950/30 border-l-4 border-green-500 rounded-r-xl p-6">
      <div className="flex gap-4">
        <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          {title && (
            <h4 className="text-lg font-bold text-green-900 dark:text-green-300 mb-2">
              {title}
            </h4>
          )}
          <div className="text-green-900 dark:text-green-300 leading-relaxed">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

export function AlertTip({ children, title }: AlertProps) {
  return (
    <div className="bg-purple-50 dark:bg-purple-950/30 border-l-4 border-purple-500 rounded-r-xl p-6">
      <div className="flex gap-4">
        <Lightbulb className="w-6 h-6 text-purple-600 dark:text-purple-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          {title && (
            <h4 className="text-lg font-bold text-purple-900 dark:text-purple-300 mb-2">
              {title}
            </h4>
          )}
          <div className="text-purple-900 dark:text-purple-300 leading-relaxed">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

// Code Block Component with Copy
interface CodeBlockProps {
  code: string;
  language?: string;
  title?: string;
  showLineNumbers?: boolean;
}

export function CodeBlock({ code, language = 'text', title, showLineNumbers = false }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="group relative">
      {title && (
        <div className="flex items-center justify-between bg-slate-800 dark:bg-slate-950 px-4 py-2 rounded-t-xl border-b border-slate-700">
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-mono text-slate-300">{title}</span>
          </div>
          <span className="text-xs text-slate-500 uppercase">{language}</span>
        </div>
      )}
      
      <div className="relative">
        <pre className={`bg-slate-900 dark:bg-slate-950 text-slate-100 p-6 ${title ? 'rounded-b-xl' : 'rounded-xl'} overflow-x-auto border border-slate-800 dark:border-slate-800`}>
          <code className={`language-${language} text-sm font-mono leading-relaxed`}>
            {code}
          </code>
        </pre>
        
        <button
          onClick={handleCopy}
          className="absolute top-4 right-4 p-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-all opacity-0 group-hover:opacity-100 border border-slate-700"
          title="Copiar código"
        >
          {copied ? (
            <Check className="w-4 h-4 text-green-400" />
          ) : (
            <Copy className="w-4 h-4 text-slate-400" />
          )}
        </button>
      </div>
    </div>
  );
}

// Terminal Output Component
interface TerminalProps {
  children: ReactNode;
  title?: string;
}

export function TerminalOutput({ children, title = 'Terminal' }: TerminalProps) {
  return (
    <div className="rounded-xl overflow-hidden border border-slate-800 shadow-2xl">
      <div className="bg-slate-800 px-4 py-3 flex items-center gap-2 border-b border-slate-700">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-red-500" />
          <div className="w-3 h-3 rounded-full bg-yellow-500" />
          <div className="w-3 h-3 rounded-full bg-green-500" />
        </div>
        <div className="flex items-center gap-2 ml-3">
          <Terminal className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-300 font-mono">{title}</span>
        </div>
      </div>
      <div className="bg-slate-950 p-6 font-mono text-sm text-green-400 overflow-x-auto">
        {children}
      </div>
    </div>
  );
}

// Highlight Box
interface HighlightBoxProps {
  children: ReactNode;
  color?: 'blue' | 'purple' | 'green' | 'red';
  title?: string;
  icon?: ReactNode;
}

export function HighlightBox({ children, color = 'blue', title, icon }: HighlightBoxProps) {
  const colors = {
    blue: 'bg-blue-500/10 border-blue-500/20 dark:bg-blue-950/30 dark:border-blue-500/30',
    purple: 'bg-purple-500/10 border-purple-500/20 dark:bg-purple-950/30 dark:border-purple-500/30',
    green: 'bg-green-500/10 border-green-500/20 dark:bg-green-950/30 dark:border-green-500/30',
    red: 'bg-red-500/10 border-red-500/20 dark:bg-red-950/30 dark:border-red-500/30'
  };

  const titleColors = {
    blue: 'text-blue-700 dark:text-blue-300',
    purple: 'text-purple-700 dark:text-purple-300',
    green: 'text-green-700 dark:text-green-300',
    red: 'text-red-700 dark:text-red-300'
  };

  return (
    <div className={`${colors[color]} border rounded-xl p-6`}>
      {(title || icon) && (
        <div className="flex items-center gap-3 mb-4">
          {icon}
          {title && (
            <h4 className={`text-xl font-bold ${titleColors[color]}`}>
              {title}
            </h4>
          )}
        </div>
      )}
      <div className="text-slate-700 dark:text-slate-300 leading-relaxed">
        {children}
      </div>
    </div>
  );
}

// List Component with Icons
interface ListItemProps {
  icon?: ReactNode;
  children: ReactNode;
}

export function ListItem({ icon, children }: ListItemProps) {
  return (
    <li className="flex items-start gap-3">
      {icon || <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />}
      <span className="text-slate-700 dark:text-slate-300 leading-relaxed">{children}</span>
    </li>
  );
}

// Paragraph Component
interface ParagraphProps {
  children: ReactNode;
  className?: string;
}

export function Paragraph({ children, className = '' }: ParagraphProps) {
  return (
    <p className={`text-lg text-slate-700 dark:text-slate-300 leading-relaxed ${className}`}>
      {children}
    </p>
  );
}

// Strong text component
interface StrongProps {
  children: ReactNode;
}

export function Strong({ children }: StrongProps) {
  return (
    <strong className="text-slate-900 dark:text-white font-semibold">
      {children}
    </strong>
  );
}

// Inline Code
interface InlineCodeProps {
  children: ReactNode;
}

export function InlineCode({ children }: InlineCodeProps) {
  return (
    <code className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-blue-600 dark:text-blue-400 rounded font-mono text-sm border border-slate-200 dark:border-slate-700">
      {children}
    </code>
  );
}
