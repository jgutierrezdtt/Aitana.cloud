import LabTemplate from "@/components/LabTemplate";

export default function SessionFixationLab() {
  return (
    <LabTemplate
      title="Session Fixation"
      description="Vulnerabilidades de fijación de sesión que permiten secuestro de sesiones de usuario"
      severity="medium"
      color="from-blue-500 to-cyan-500"
      apiEndpoint="/api/lab/session-fixation"
      examples={[
        {
          name: "Obtener sesión",
          description: "Crear una nueva sesión sin autenticación",
          url: "/api/lab/session-fixation"
        },
        {
          name: "Fijar sesión",
          description: "Usar un ID de sesión específico antes de autenticarse",
          url: "/api/lab/session-fixation?sessionId=attacker-controlled-session"
        }
      ]}
      vulnerabilityInfo="Este endpoint no regenera el ID de sesión después de la autenticación. Un atacante puede crear una sesión, engañar a la víctima para que se autentique con esa sesión, y luego usar el mismo ID de sesión para acceder a la cuenta de la víctima."
    />
  );
}
