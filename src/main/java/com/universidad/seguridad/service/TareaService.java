package com.universidad.seguridad.service;

import com.universidad.seguridad.dto.TareaDTO;
import com.universidad.seguridad.model.Tarea;
import java.util.List;

/**
 * Contrato de servicio para la gestion de tareas y control de autorizaciones a nivel de metodo.
 */
public interface TareaService {

    /**
     * Lista las tareas de un usuario en particular.
     * Solo accesible por un ADMIN o por el propio usuario autenticado duenho de la cuenta.
     * @param email correo del propietario.
     * @return lista de tareas en formato DTO.
     */
    List<TareaDTO> listarDe(String email);

    /**
     * Busca tareas cuyo titulo contenga el texto indicado (busqueda parametrizada segura).
     * @param texto patron de texto a buscar.
     * @return lista de tareas encontradas.
     */
    List<TareaDTO> buscarPorTitulo(String texto);

    /**
     * Busca tareas por propietario y coincidencia parcial en el titulo.
     */
    List<TareaDTO> buscarPorPropietarioYTitulo(String email, String texto);

    /**
     * Crea una nueva tarea asignada al usuario dueno.
     * @param titulo titulo de la tarea.
     * @param descripcion descripcion opcional.
     * @param emailPropietario correo del usuario autenticado.
     * @return DTO de la tarea creada.
     */
    TareaDTO crearTarea(String titulo, String descripcion, String emailPropietario);

    /**
     * Alterna el estado de completada de una tarea, validando pertenencia o rol de admin.
     * @param id identificador de la tarea.
     * @param emailSolicitante usuario autenticado que solicita la modificacion.
     * @return DTO actualizado.
     */
    TareaDTO alternarCompletada(Long id, String emailSolicitante);

    /**
     * Lista absolutamente todas las tareas del sistema (solo rol ADMIN).
     */
    List<TareaDTO> listarTodas();
}
