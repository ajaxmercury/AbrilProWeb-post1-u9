package com.universidad.seguridad.security;

import com.universidad.seguridad.repository.TareaRepository;
import org.springframework.stereotype.Component;

/**
 * Validador de seguridad en SpEL para comprobar la propiedad de recursos en @PreAuthorize.
 */
@Component("tareaSecurityValidator")
public class TareaSecurityValidator {

    private final TareaRepository tareaRepository;

    public TareaSecurityValidator(TareaRepository tareaRepository) {
        this.tareaRepository = tareaRepository;
    }

    /**
     * Comprueba si el usuario autenticado es el dueno de la tarea con el ID indicado.
     * @param tareaId ID de la tarea.
     * @param username Email o nombre de usuario autenticado en Spring Security.
     * @return true si es dueno, false si no.
     */
    public boolean esPropietario(Long tareaId, String username) {
        if (tareaId == null || username == null) {
            return false;
        }
        return tareaRepository.findById(tareaId)
                .map(tarea -> tarea.getPropietario() != null && username.equalsIgnoreCase(tarea.getPropietario().getEmail()))
                .orElse(false);
    }
}
