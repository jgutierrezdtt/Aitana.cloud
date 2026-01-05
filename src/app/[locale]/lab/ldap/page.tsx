import LabTemplate from "@/components/LabTemplate";

export default function LDAPLab() {
  return (
    <LabTemplate
      title="LDAP Injection"
      description="Inyección en consultas LDAP para bypass de autenticación y acceso no autorizado"
      severity="high"
      color="from-yellow-500 to-amber-500"
      apiEndpoint="/api/lab/ldap?filter=admin"
      examples={[
        {
          name: "Búsqueda normal",
          description: "Consulta LDAP legítima",
          url: "/api/lab/ldap?filter=admin"
        },
        {
          name: "LDAP Injection - Bypass",
          description: "Inyección para obtener todos los usuarios",
          url: "/api/lab/ldap?filter=*"
        },
        {
          name: "LDAP Injection - OR",
          description: "Bypass de autenticación usando OR lógico",
          url: "/api/lab/ldap?filter=*)(|(cn=*"
        }
      ]}
      vulnerabilityInfo="Este endpoint construye consultas LDAP concatenando entrada del usuario directamente. Un atacante puede manipular la consulta usando caracteres especiales como *, (, ), | para acceder a datos no autorizados o bypass de autenticación."
    />
  );
}
