import LabTemplate from "@/components/LabTemplate";

export default function SensitiveDataLab() {
  return (
    <LabTemplate
      title="Sensitive Data Exposure"
      description="Exposición inadecuada de información sensible sin controles de acceso apropiados"
      severity="high"
      color="from-indigo-500 to-purple-500"
      apiEndpoint="/api/users"
      examples={[
        {
          name: "Listar todos los usuarios",
          description: "Endpoint que expone datos sensibles de todos los usuarios",
          url: "/api/users"
        },
        {
          name: "Ver usuario específico",
          description: "Acceder a información detallada incluyendo contraseñas",
          url: "/api/users/1"
        },
        {
          name: "Información del sistema",
          description: "Endpoint que revela configuración interna del servidor",
          url: "/api/system-info"
        },
        {
          name: "Estado de variables de entorno",
          description: "Expone variables de entorno con información sensible",
          url: "/api/env-status"
        }
      ]}
      vulnerabilityInfo="Estos endpoints exponen información sensible sin autenticación ni autorización adecuada. Se revelan contraseñas en texto plano, tokens de sesión, configuración del servidor, variables de entorno y datos personales de usuarios sin cifrado ni protección."
    />
  );
}
