// Scripts de soporte para la interfaz de seguridad-web
document.addEventListener("DOMContentLoaded", () => {
    // Auto-ocultar alertas tras 5 segundos
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 5000);
    });
});
