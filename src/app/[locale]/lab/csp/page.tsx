import LabTemplate from "@/components/LabTemplate";

export default function CSPLab() {
  return (
    <LabTemplate
      title="Content Security Policy Bypass"
      description="Bypass de políticas de seguridad de contenido y evasión de restricciones CSP"
      severity="medium"
      color="from-teal-500 to-emerald-500"
      apiEndpoint="/api/lab/csp"
      examples={[
        {
          name: "Verificar CSP",
          description: "Obtener la política CSP actual del sitio",
          url: "/api/lab/csp"
        },
        {
          name: "Script inline permitido",
          description: "Prueba si los scripts inline están permitidos",
          url: "/api/lab/csp?test=inline"
        },
        {
          name: "Eval permitido",
          description: "Verificar si eval() está permitido (unsafe-eval)",
          url: "/api/lab/csp?test=eval"
        }
      ]}
      vulnerabilityInfo="Este endpoint tiene una política CSP débil o incorrectamente configurada. Las directivas 'unsafe-inline' y 'unsafe-eval' están habilitadas, permitiendo la ejecución de scripts inline y eval(), lo que facilita ataques XSS."
    />
  );
}
