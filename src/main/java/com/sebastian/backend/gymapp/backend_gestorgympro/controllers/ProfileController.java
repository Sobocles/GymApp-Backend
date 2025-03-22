package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProfileService;

@RestController
@RequestMapping("/profile")
public class ProfileController {

        @Autowired
        private ProfileService profileService;

    @PutMapping("/update")
    @PreAuthorize("hasAnyRole('ADMIN','TRAINER','USER')")
    public ResponseEntity<?> updateProfile(
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "file", required = false) MultipartFile file,
            @RequestParam(value = "instagramUrl", required = false) String instagramUrl,
            @RequestParam(value = "whatsappNumber", required = false) String whatsappNumber) {
        try {
            UserRequest userRequest = new UserRequest();
            userRequest.setUsername(username);
            userRequest.setEmail(email);
            userRequest.setPassword(password);
            userRequest.setInstagramUrl(instagramUrl);
            userRequest.setWhatsappNumber(whatsappNumber);
            System.out.println("userRequest"+userRequest);
            // Obtener el email actual del usuario autenticado
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String currentEmail = authentication.getName();
        
            UserDto updatedUser = profileService.updateProfile(userRequest, file, currentEmail);
            System.out.println("Aqui el usuario actualizado"+updatedUser);
            return ResponseEntity.ok(updatedUser);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al actualizar el perfil");
        }
    }

}
