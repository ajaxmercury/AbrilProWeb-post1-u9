package com.universidad.seguridad.service;

import com.universidad.seguridad.dto.TareaDTO;
import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementacion del servicio de tareas.
 */
@Service
public class TareaServiceImpl implements TareaService {

    private final TareaRepository tareaRepository;
    private final UsuarioRepository usuarioRepository;

    public TareaServiceImpl(TareaRepository tareaRepository, UsuarioRepository usuarioRepository) {
        this.tareaRepository = tareaRepository;
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN') or #email == authentication.name")
    public List<TareaDTO> listarDe(String email) {
        return tareaRepository.findByPropietarioEmail(email)
                .stream()
                .map(TareaDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<TareaDTO> buscarPorTitulo(String texto) {
        return tareaRepository.buscarPorTitulo(texto)
                .stream()
                .map(TareaDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN') or #email == authentication.name")
    public List<TareaDTO> buscarPorPropietarioYTitulo(String email, String texto) {
        return tareaRepository.buscarPorPropietarioYTitulo(email, texto)
                .stream()
                .map(TareaDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public TareaDTO crearTarea(String titulo, String descripcion, String emailPropietario) {
        Usuario propietario = usuarioRepository.findByEmail(emailPropietario)
                .orElseThrow(() -> new IllegalArgumentException("No se encontro el usuario propietario: " + emailPropietario));

        Tarea nuevaTarea = new Tarea();
        nuevaTarea.setTitulo(titulo.trim());
        nuevaTarea.setDescripcion(descripcion != null ? descripcion.trim() : "");
        nuevaTarea.setPropietario(propietario);
        nuevaTarea.setCompletada(false);

        Tarea guardada = tareaRepository.save(nuevaTarea);
        return TareaDTO.fromEntity(guardada);
    }

    @Override
    @Transactional
    @PreAuthorize("hasRole('ADMIN') or @tareaSecurityValidator.esPropietario(#id, authentication.name)")
    public TareaDTO alternarCompletada(Long id, String emailSolicitante) {
        Tarea tarea = tareaRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Tarea no encontrada con ID: " + id));

        tarea.setCompletada(!tarea.isCompletada());
        Tarea actualizada = tareaRepository.save(tarea);
        return TareaDTO.fromEntity(actualizada);
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public List<TareaDTO> listarTodas() {
        return tareaRepository.findAll()
                .stream()
                .map(TareaDTO::fromEntity)
                .collect(Collectors.toList());
    }
}
