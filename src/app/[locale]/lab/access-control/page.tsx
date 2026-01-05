import LabTemplate from "@/components/LabTemplate";

export default function BrokenAccessControlLab() {
  return (
    <LabTemplate
      title="Broken Access Control"
      description="Fallos en controles de acceso y autorización que permiten acceso no autorizado a recursos"
      severity="critical"
      color="from-pink-500 to-rose-600"
      apiEndpoint="/api/notes"
      examples={[
        {
          name: "Ver todas las notas",
          description: "Acceder a notas de todos los usuarios sin autenticación",
          url: "/api/notes"
        },
        {
          name: "Ver nota específica",
          description: "Acceder a notas privadas de otros usuarios (IDOR)",
          url: "/api/notes/1"
        },
        {
          name: "Modificar nota ajena",
          description: "Cambiar o eliminar notas de otros usuarios sin verificación",
          url: "/api/notes/2"
        }
      ]}
      vulnerabilityInfo="Estos endpoints no implementan controles de acceso adecuados. Cualquier usuario (incluso sin autenticar) puede ver, modificar o eliminar recursos de otros usuarios. No hay validación de permisos ni verificación de propiedad de recursos (IDOR - Insecure Direct Object Reference)."
    />
  );
}
