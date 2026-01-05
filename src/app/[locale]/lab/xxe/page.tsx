import LabTemplate from "@/components/LabTemplate";

export default function XXELab() {
  return (
    <LabTemplate
      title="XML External Entity (XXE)"
      description="Vulnerabilidades de procesamiento XML inseguro que permiten leer archivos del sistema"
      severity="high"
      color="from-amber-500 to-orange-500"
      apiEndpoint="/api/lab/xxe"
      examples={[
        {
          name: "XXE básico - Leer archivo local",
          description: "Payload XXE que intenta leer /etc/passwd",
          url: "/api/lab/xxe"
        },
        {
          name: "XXE con entidad externa",
          description: "Inyección de entidades externas para acceder a archivos del sistema",
          url: "/api/lab/xxe"
        }
      ]}
      vulnerabilityInfo="Este endpoint procesa XML sin deshabilitar entidades externas. Un atacante puede usar XXE para leer archivos del sistema, realizar SSRF, o causar ataques de denegación de servicio (Billion Laughs)."
    />
  );
}
