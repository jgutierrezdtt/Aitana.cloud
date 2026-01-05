import LabTemplate from "@/components/LabTemplate";

export default function CommandInjectionLab() {
  return (
    <LabTemplate
      title="Command Injection"
      description="Ejecución de comandos del sistema operativo a través de entrada no sanitizada"
      severity="critical"
      color="from-red-600 to-rose-700"
      apiEndpoint="/api/lab/command-injection?cmd=ls"
      examples={[
        {
          name: "Listar archivos",
          description: "Comando básico para listar archivos del directorio actual",
          url: "/api/lab/command-injection?cmd=ls"
        },
        {
          name: "Ver contenido de archivos",
          description: "Concatenar comandos para leer archivos sensibles",
          url: "/api/lab/command-injection?cmd=ls;cat /etc/passwd"
        },
        {
          name: "Información del sistema",
          description: "Ejecutar múltiples comandos para obtener información del sistema",
          url: "/api/lab/command-injection?cmd=whoami && uname -a"
        }
      ]}
      vulnerabilityInfo="Este endpoint ejecuta comandos del sistema operativo sin validación. Un atacante puede inyectar comandos maliciosos usando separadores como ';', '&&', '||' o '|' para ejecutar código arbitrario en el servidor."
    />
  );
}
