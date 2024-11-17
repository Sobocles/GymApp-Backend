package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAssignmentRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;

import jakarta.validation.Valid;



@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService service;

    @GetMapping
    public List<UserDto> list() {
        System.out.println("ENTRO AL LIST");
        return service.findAll();
    }

    @GetMapping("/page/{page}")
    public ResponseEntity<Page<UserDto>> list(
        @PathVariable Integer page,
        @RequestParam(value = "search", required = false) String search
    ) {
        Pageable pageable = PageRequest.of(page, 6);
        Page<UserDto> usersPage;

        if (search != null && !search.isEmpty()) {
            usersPage = service.findByUsernameContaining(search, pageable);
        } else {
            usersPage = service.findAll(pageable);
            System.out.println("AQUI ESTA EL "+usersPage);
        }
        return ResponseEntity.ok(usersPage);
    }


    @GetMapping("/{id}")
    public ResponseEntity<?> show(@PathVariable Long id) {
        Optional<UserDto> userOption1 = service.findById(id);

        if (userOption1.isPresent()) {
            return ResponseEntity.ok(userOption1.orElseThrow());
        }
        return ResponseEntity.notFound().build();
    }
    
    @PutMapping("/profile")
    @PreAuthorize("hasAnyRole('ADMIN','TRAINER','USER')")
    public ResponseEntity<?> updateProfile(
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "file", required = false) MultipartFile file) {
        try {
            UserRequest userRequest = new UserRequest();
            userRequest.setUsername(username);
            userRequest.setEmail(email);
            userRequest.setPassword(password);

            // Obtener el email actual del usuario autenticado
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String currentEmail = authentication.getName();

            UserDto updatedUser = service.updateProfile(userRequest, file, currentEmail);
            return ResponseEntity.ok(updatedUser);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al actualizar el perfil");
        }
    }


    
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody User user, BindingResult result) {
        System.out.println(user);
        if(result.hasErrors()){
            return validation(result);
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(service.save(user));
    }

    @PostMapping("/{id}/create-trainer")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createTrainer(
            @PathVariable Long id,
            @RequestBody TrainerAssignmentRequest request) {
        service.assignTrainerRole(id, request.getSpecialization(), request.getExperienceYears(), request.getAvailability());
        return ResponseEntity.ok("Role de Trainer asignado correctamente y especialización añadida");
    }


    
    @PutMapping("/{id}")
    public ResponseEntity<?> update(@Valid @RequestBody UserRequest user, BindingResult result, @PathVariable Long id) {
        if(result.hasErrors()){
            return validation(result);
        }
        Optional<UserDto> o = service.update(user, id);
        
        if (o.isPresent()) {
            return ResponseEntity.status(HttpStatus.CREATED).body(o.orElseThrow());
        }
        return ResponseEntity.notFound().build();
    }
    
    

@DeleteMapping("/{id}")
public ResponseEntity<?> remove(@PathVariable Long id) {
    Optional<UserDto> o = service.findById(id);

    if (o.isPresent()) {
        service.remove(id);
        return ResponseEntity.noContent().build(); // 204
    }

    return ResponseEntity.notFound().build();
}

    private ResponseEntity<?> validation(BindingResult result) {
        Map<String, String> errors = new HashMap<>();

        result.getFieldErrors().forEach(err -> {
            errors.put(err.getField(), "El campo " + err.getField() + " " + err.getDefaultMessage());
        });
        return ResponseEntity.badRequest().body(errors);
    }

    // UserController.java

@PostMapping("/register")
public ResponseEntity<?> registerUser(@Valid @RequestBody User user, BindingResult result) {
    if (result.hasErrors()) {
        return validation(result);
    }

    if (service.existsByEmail(user.getEmail())) {
        return ResponseEntity.badRequest().body(Map.of("message", "El correo electrónico ya está en uso"));
    }
    if (service.existsByUsername(user.getUsername())) {
        return ResponseEntity.badRequest().body(Map.of("message", "El nombre de usuario ya está en uso"));
    }

    user.setAdmin(false); // Asegurarse de que no pueda registrarse como admin
    user.setTrainer(false); // Asegurarse de que no pueda registrarse como entrenador

    service.save(user);
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("message", "Usuario registrado con éxito"));
}





}

