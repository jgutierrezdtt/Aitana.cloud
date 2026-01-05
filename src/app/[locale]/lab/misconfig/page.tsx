import LabTemplate from "@/components/LabTemplate";

export default function SecurityMisconfigLab() {
  return (
    <LabTemplate
      title="Security Misconfiguration"
      description="Configuraciones de seguridad incorrectas que exponen el sistema a ataques"
      severity="medium"
      color="from-cyan-500 to-blue-500"
      apiEndpoint="/api/system-info"
      examples={[
        {
          name: "Información del sistema",
          description: "Endpoint que revela versiones de software y configuración",
          url: "/api/system-info"
        },
        {
          name: "Variables de entorno",
          description: "Exposición de variables de entorno del servidor",
          url: "/api/env-status"
        }
      ]}
      vulnerabilityInfo="El sistema tiene múltiples problemas de configuración: headers de seguridad débiles, CORS permisivo, información de debugging habilitada en producción, versiones de software expuestas, CSP débil con 'unsafe-inline' y 'unsafe-eval', y variables de entorno accesibles públicamente."
    />
  );
}
