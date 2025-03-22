package com.sebastian.backend.gymapp.backend_gestorgympro.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Role;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.RoleRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;

@Component
public class DatabaseInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    @Transactional
    public void run(String... args) throws Exception {
        // Inicializar roles si no existen
        createRoleIfNotFound("ROLE_USER");
        createRoleIfNotFound("ROLE_ADMIN");
        createRoleIfNotFound("ROLE_TRAINER");
        
        // Crear usuario administrador si no existe
        createAdminUserIfNotFound();
        
        System.out.println("Base de datos inicializada con roles y usuario administrador.");
    }
    
    /**
     * Crear un rol si no existe en la base de datos
     */
    private void createRoleIfNotFound(String name) {
        if (!roleRepository.findByName(name).isPresent()) {
            Role role = new Role(name);
            roleRepository.save(role);
            System.out.println("Rol creado: " + name);
        }
    }
    
    /**
     * Crear un usuario administrador si no existe en la base de datos
     */
    private void createAdminUserIfNotFound() {
        // Método 1: Verificar si existe un usuario con el email del admin
        if (userRepository.existsByEmail("admin@gymnasium.com")) {
            System.out.println("Usuario administrador ya existe. No es necesario crearlo.");
            return;
        }
        
        // Método 2: Verificar si hay algún usuario con rol ADMIN
        Role adminRole = roleRepository.findByName("ROLE_ADMIN").orElse(null);
        if (adminRole != null) {
            boolean adminExists = false;
            for (User user : userRepository.findAll()) {
                // Solo verificamos si el campo admin está establecido a true
                if (user.isAdmin()) {
                    adminExists = true;
                    System.out.println("Usuario administrador encontrado con ID: " + user.getId());
                    break;
                }
            }
            
            if (adminExists) {
                System.out.println("Ya existe un usuario con rol de administrador.");
                return;
            }
        }
        
        // Si no existe un administrador, crear uno nuevo
        User admin = new User();
        admin.setUsername("admin");
        admin.setEmail("admin@gymnasium.com");
        
        // Contraseña por defecto: admin123
        String defaultPassword = "admin123";
        admin.setPassword(passwordEncoder.encode(defaultPassword));
        admin.setActive(true);
        admin.setAdmin(true); // Marcar como admin
        
        // Asignar roles de administrador y usuario
        List<Role> roles = new ArrayList<>();
        roleRepository.findByName("ROLE_ADMIN").ifPresent(roles::add);
        roleRepository.findByName("ROLE_USER").ifPresent(roles::add);
        admin.setRoles(roles);
        
        userRepository.save(admin);
        System.out.println("Usuario administrador creado con éxito.");
        System.out.println("Usuario: admin@gymnasium.com");
        System.out.println("Contraseña: " + defaultPassword);
    }
}