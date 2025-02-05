package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.IUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Role;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.RoleRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.EmailService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;



import org.springframework.transaction.annotation.Transactional;



    @Service
    public class UserServiceImpl implements UserService{

        @Autowired
        private UserRepository repository;

        
        @Autowired
        private CloudinaryService cloudinaryService;

        @Autowired
        private RoleRepository roleRepository;

        @Autowired
        private PersonalTrainerRepository personalTrainerRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private EmailService emailService;

        @Override
        @Transactional(readOnly = true)
        public List<UserDto> findAll() {
            // En vez de findAll(), usamos findAllActive sin paginación.
            // Si realmente necesitas un Page en la interfaz, omite este y 
            // usa la versión paginada. Si no, haz una versión List en el repositorio.
            // Por ejemplo:
            Page<User> page = repository.findAllActive(Pageable.unpaged());
            List<User> users = page.getContent();
        
            return users.stream()
                        .map(u -> DtoMapperUser.builder().setUser(u).build())
                        .collect(Collectors.toList());
        }

/* 
        @Override
        @Transactional(readOnly = true)
        public Optional<UserDto> findById(Long id) {
            Optional<User> o = repository.findById(id);
            if (o.isPresent()) {
                return Optional.of(
                    DtoMapperUser
                        .builder()
                        .setUser(o.orElseThrow())
                        .build()
                );
            }
            return Optional.empty();
        }
*/


        @Override
        @Transactional(readOnly = true)
        public Page<UserDto> findAll(Pageable pageable) {
            // Aquí usamos findAllActive(pageable)
            Page<User> usersPage = repository.findAllActive(pageable);
            return usersPage.map(u -> DtoMapperUser.builder().setUser(u).build());
        }

        @Override
        @Transactional(readOnly = true)
        public Page<UserDto> findByUsernameContaining(String search, Pageable pageable) {
            // Reemplazamos por la versión que filtra activos:
            Page<User> usersPage = repository.findByUsernameContainingIgnoreCaseAndActiveTrue(search, pageable);
            return usersPage.map(u -> DtoMapperUser.builder().setUser(u).build());
        }


        
        @Override
        @Transactional(readOnly = true)
        public Optional<UserDto> findById(Long id) {
            return repository.findById(id).map(u -> DtoMapperUser
                .builder()
                .setUser(u)
                .build());
        }


        @Override
        @Transactional
        public UserDto save(User user) {
        
            // 1) Generar/encriptar contraseña (si no lo hiciste antes). 
            //    OJO: Aquí se asume que 'user.getPassword()' viene con la contraseña generada.
            String rawPassword = user.getPassword();          // Contraseña generada sin encriptar
            String encrypted = passwordEncoder.encode(rawPassword);
            user.setPassword(encrypted);
        
            // 2) Roles, etc. (código que ya tienes)
            List<Role> roles = getRoles(user);
            user.setRoles(roles);
        
            // 3) Guardar en base de datos
            User saved = repository.save(user);
        
            // 4) Enviar email con la contraseña en texto plano
            try {
                String subject = "¡Te han creado una cuenta en GymApp!";
                String body = "Hola " + saved.getUsername() + 
                              ", tu cuenta ha sido creada. " +
                              "Tu contraseña temporal es: " + rawPassword + 
                              "\n\nPor favor, inicia sesión y cámbiala lo antes posible.";
                emailService.sendEmail(saved.getEmail(), subject, body);
            } catch(Exception e) {
                // Manejo de errores si falla el envío de correo
                e.printStackTrace();
            }
        
            // 5) Retornar el DTO
            return DtoMapperUser.builder().setUser(saved).build();
        }
        
        
        
        

        @Transactional
        @Override
        public void remove(Long id) {
            User user = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado con ID: " + id));
            
            // Marcar como inactivo en lugar de borrarlo
            user.setActive(false);
            repository.save(user);
        
            // (Opcional) si el usuario es trainer, podrías marcar su disponibilidad en false
            // para que no aparezca en “Entrenadores disponibles”:
            Optional<PersonalTrainer> ptOpt = personalTrainerRepository.findByUserId(id);
            ptOpt.ifPresent(pt -> {
                pt.setAvailability(false);
                personalTrainerRepository.save(pt);
            });
            
   
        }
        

        @Override
        @Transactional
        public Optional<UserDto> update(UserRequest user, Long id) {
            Optional<User> o = repository.findById(id);
            User userOptional = null;
            if (o.isPresent()){
                User userDb = o.orElseThrow();
                List<Role> roles = getRoles(user);
                userDb.setRoles(roles);
                userDb.setUsername(user.getUsername());
                userDb.setEmail(user.getEmail());
                userOptional = repository.save(userDb);
            }
            return Optional.ofNullable(DtoMapperUser.builder().setUser(userOptional).build());
        }
        



private List<Role> getRoles(IUser user) {
    
    Optional<Role> ou = roleRepository.findByName("ROLE_USER");

    List<Role> roles = new ArrayList<>();
    if (ou.isPresent()) {
        roles.add(ou.orElseThrow());
    }

    if (user.isAdmin()) {
        Optional<Role> oa = roleRepository.findByName("ROLE_ADMIN");
        if (oa.isPresent()) {
            roles.add(oa.orElseThrow());
        }
    }
    System.out.println("Valor de trainer: " + user.isTrainer());
    if (user.isTrainer()) {
        Optional<Role> ot = roleRepository.findByName("ROLE_TRAINER");
        if (ot.isPresent()) {
            roles.add(ot.orElseThrow());
        }
    }

    return roles;
}

        @Override
        public boolean existsByEmail(String email) {
            return repository.existsByEmail(email);
        }

        @Override
        public boolean existsByUsername(String username) {
            return repository.existsByUsername(username);
}


        @Override
        @Transactional(readOnly = true)
        public Optional<User> findByEmail(String email) {
            // También llamamos la nueva versión "only active"
            return repository.findByEmailAndActiveTrue(email);
        }


        
    }


