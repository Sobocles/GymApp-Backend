package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

public class DtoMapperUser {

    private User user;

    
    private DtoMapperUser() {
    }

    public static DtoMapperUser builder() {
        return new DtoMapperUser();
    }

    public DtoMapperUser setUser(User user) {
        this.user = user;
        return this;
    }

    public UserDto build() {
        if (user == null) {
            throw new RuntimeException("Debe pasar el entity user!");
        }
        boolean isAdmin = user.getRoles().stream().anyMatch(r -> "ROLE_ADMIN".equals(r.getName()));
        boolean isTrainer = user.getRoles().stream().anyMatch(r -> "ROLE_TRAINER".equals(r.getName()));
        return new UserDto(
            this.user.getId(),
            user.getUsername(),
            user.getEmail(),
            isAdmin,
            isTrainer,
            user.getProfileImageUrl() // Asignar la URL de la imagen
        );
    }
    

}

