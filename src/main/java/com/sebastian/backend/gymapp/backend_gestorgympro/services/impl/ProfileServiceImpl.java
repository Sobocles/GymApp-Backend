package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProfileService;


import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
public class ProfileServiceImpl implements ProfileService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CloudinaryService cloudinaryService;

    @Autowired
    private PasswordEncoder passwordEncoder;



      @Override
    public UserDto updateProfile(UserRequest userRequest, MultipartFile file, String currentEmail) {
        Optional<User> optionalUser = userRepository.findByEmail(currentEmail);
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Usuario no encontrado");
        }

        User user = optionalUser.get();

        // Actualizar datos básicos
        if (userRequest.getUsername() != null) {
            user.setUsername(userRequest.getUsername());
        }
        if (userRequest.getEmail() != null) {
            user.setEmail(userRequest.getEmail());
        }
        if (userRequest.getPassword() != null && !userRequest.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        }

        // Subir imagen (si viene)
        if (file != null && !file.isEmpty()) {
            try {
                String imageUrl = cloudinaryService.uploadImage(file);
                user.setProfileImageUrl(imageUrl);
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException("Error al subir la imagen de perfil");
            }
        }

        // Guardar
        userRepository.save(user);

        // Convertir a DTO
        UserDto dto = DtoMapperUser.builder().setUser(user).build();

        // 1) Extraer roles de la entidad `user`
        List<String> rolesList = user.getRoles()
            .stream()
            .map(role -> role.getName())  // "ROLE_ADMIN", "ROLE_TRAINER", etc
            .collect(Collectors.toList());

        // 2) Asignarlos al DTO
        dto.setRoles(rolesList);

        // Retornar
        return dto;
    }
}
