import LabTemplate from "@/components/LabTemplate";

export default function FileUploadLab() {
  return (
    <LabTemplate
      title="File Upload Vulnerabilities"
      description="Subida de archivos sin validación adecuada que permite ejecutar código malicioso"
      severity="high"
      color="from-emerald-500 to-teal-600"
      apiEndpoint="/api/upload"
      examples={[
        {
          name: "Verificar endpoint",
          description: "Comprobar configuración del endpoint de subida",
          url: "/api/upload"
        }
      ]}
      vulnerabilityInfo="Este endpoint acepta archivos sin validar el tipo, tamaño o contenido. Un atacante puede subir archivos ejecutables (.php, .jsp, .aspx), scripts maliciosos, o archivos diseñados para explotar vulnerabilidades del servidor. No hay sanitización de nombres de archivo ni restricciones de ubicación de almacenamiento."
    />
  );
}
