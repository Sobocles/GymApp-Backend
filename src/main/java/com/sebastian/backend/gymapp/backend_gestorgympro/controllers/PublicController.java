// src/main/java/com/sebastian/backend/gymapp/backend_gestorgympro/controllers/PublicController.java

package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {

    @GetMapping("/info")
    public ResponseEntity<?> getPublicInfo() {
        // Retorna la información pública necesaria
        return ResponseEntity.ok("Información pública del gimnasio");
    }
    

}
