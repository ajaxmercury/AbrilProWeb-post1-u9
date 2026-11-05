package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.RegistroDTO;
import com.universidad.seguridad.dto.TareaDTO;
import com.universidad.seguridad.dto.UsuarioDTO;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.service.TareaService;
import com.universidad.seguridad.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

/**
 * Controlador Spring MVC para la gestion de vistas web renderizadas con Thymeleaf.
 * Maneja login con sesion, registro de usuarios, dashboard personal y panel administrativo.
 */
@Controller
public class AuthController {

    private final UsuarioService usuarioService;
    private final TareaService tareaService;

    public AuthController(UsuarioService usuarioService, TareaService tareaService) {
        this.usuarioService = usuarioService;
        this.tareaService = tareaService;
    }

    /**
     * Ruta raiz: redirige al dashboard si ya existe una sesion autenticada,
     * o a la pagina de login en caso contrario.
     */
    @GetMapping("/")
    public String index(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getName())) {
            return "redirect:/dashboard";
        }
        return "redirect:/login";
    }

    /**
     * Muestra la pagina de inicio de sesion (login con formulario tradicional).
     */
    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            @RequestParam(value = "registrado", required = false) String registrado,
            Model model) {

        if (error != null) {
            model.addAttribute("errorMensaje", "Credenciales invalidas. Verifique su correo y contrasena.");
        }
        if (logout != null) {
            model.addAttribute("infoMensaje", "Ha cerrado sesion correctamente. La sesion y cookies han sido destruidas.");
        }
        if (registrado != null) {
            model.addAttribute("exitoMensaje", "Registro completado con exito. Ahora puede iniciar sesion.");
        }
        return "login";
    }

    /**
     * Muestra el formulario de registro de nuevos usuarios.
     */
    @GetMapping("/registro")
    public String mostrarFormularioRegistro(Model model) {
        model.addAttribute("usuario", new RegistroDTO());
        return "registro";
    }

    /**
     * Procesa el envio del formulario de registro aplicando validaciones Jakarta y hashing BCrypt.
     */
    @PostMapping("/registro")
    public String procesarRegistro(
            @Valid @ModelAttribute("usuario") RegistroDTO registroDTO,
            BindingResult bindingResult,
            Model model,
            RedirectAttributes redirectAttributes) {

        // Validacion de contrasenas identicas
        if (!registroDTO.getContrasenia().equals(registroDTO.getConfirmarContrasenia())) {
            bindingResult.rejectValue("confirmarContrasenia", "error.usuario", "Las contrasenas no coinciden.");
        }

        // Validacion de correo unico
        if (usuarioService.existePorEmail(registroDTO.getEmail())) {
            bindingResult.rejectValue("email", "error.usuario", "El correo electronico ya esta registrado.");
        }

        if (bindingResult.hasErrors()) {
            return "registro";
        }

        try {
            usuarioService.registrarUsuario(registroDTO);
            redirectAttributes.addFlashAttribute("exitoMensaje", "Cuenta creada exitosamente con rol ROLE_USER.");
            return "redirect:/login?registrado=true";
        } catch (Exception ex) {
            model.addAttribute("errorGlobal", "Ocurrio un error al registrar la cuenta: " + ex.getMessage());
            return "registro";
        }
    }

    /**
     * Muestra el Dashboard del usuario autenticado, sus tareas asociadas
     * y la demostracion de contraste de seguridad XSS.
     */
    @GetMapping("/dashboard")
    public String dashboard(
            Authentication authentication,
            @RequestParam(name = "q", required = false) String q,
            Model model) {

        String email = authentication.getName();
        Usuario usuario = usuarioService.buscarPorEmail(email)
                .orElseThrow(() -> new IllegalStateException("Usuario no encontrado en base de datos: " + email));

        boolean esAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        List<TareaDTO> tareas;
        if (q != null && !q.trim().isEmpty()) {
            tareas = tareaService.buscarPorPropietarioYTitulo(email, q.trim());
            model.addAttribute("terminoBusqueda", q);
        } else {
            tareas = tareaService.listarDe(email);
        }

        model.addAttribute("usuario", usuario);
        model.addAttribute("tareas", tareas);
        model.addAttribute("esAdmin", esAdmin);

        return "dashboard";
    }

    /**
     * Agrega una nueva tarea desde la interfaz web (con proteccion CSRF activa).
     */
    @PostMapping("/dashboard/tareas")
    public String agregarTarea(
            Authentication authentication,
            @RequestParam("titulo") String titulo,
            @RequestParam(value = "descripcion", required = false) String descripcion,
            RedirectAttributes redirectAttributes) {

        if (titulo == null || titulo.trim().isEmpty()) {
            redirectAttributes.addFlashAttribute("errorTarea", "El titulo de la tarea no puede estar vacio.");
            return "redirect:/dashboard";
        }

        tareaService.crearTarea(titulo, descripcion, authentication.getName());
        redirectAttributes.addFlashAttribute("exitoTarea", "Tarea creada satisfactoriamente.");
        return "redirect:/dashboard";
    }

    /**
     * Alterna el estado de completada de una tarea desde la interfaz web.
     */
    @PostMapping("/dashboard/tareas/{id}/toggle")
    public String toggleTarea(
            Authentication authentication,
            @PathVariable("id") Long id) {

        tareaService.alternarCompletada(id, authentication.getName());
        return "redirect:/dashboard";
    }

    /**
     * Panel administrativo exclusivo para usuarios con ROLE_ADMIN.
     * Protegido mediante @PreAuthorize a nivel de controlador y filtro de seguridad.
     */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String panelAdmin(Authentication authentication, Model model) {
        List<UsuarioDTO> usuarios = usuarioService.listarTodos();
        List<TareaDTO> tareas = tareaService.listarTodas();

        model.addAttribute("usuarios", usuarios);
        model.addAttribute("tareas", tareas);
        model.addAttribute("adminEmail", authentication.getName());

        return "admin/panel";
    }
}
