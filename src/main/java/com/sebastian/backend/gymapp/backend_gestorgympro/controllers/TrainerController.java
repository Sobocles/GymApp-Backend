package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.bind.annotation.RestController;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ActiveClientInfoDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.BodyMeasurementDto;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAssignmentRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;



@RestController
@RequestMapping("/trainers")
public class TrainerController {

    @Autowired
    private UserService userService;

    @Autowired
    private TrainerService trainerService;


// TrainerController.java

@PostMapping("/{id}/assign")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> assignTrainerRole(@PathVariable Long id, @RequestBody TrainerAssignmentRequest request) {

    
    trainerService.assignTrainerRole(
        id,
        request.getSpecialization(),
        request.getExperienceYears(),
        request.getAvailability(),
        request.getMonthlyFee(),
        request.getTitle(),          
        request.getStudies(),
        request.getCertifications(),
        request.getDescription(),
        request.getInstagramUrl(),
        request.getWhatsappNumber()
    );
    return ResponseEntity.ok("Rol de Trainer asignado correctamente y especialización añadida");
}


    

@PostMapping("/clients/{clientId}/measurements")
@PreAuthorize("hasRole('TRAINER')")
public ResponseEntity<?> addBodyMeasurement(
        @PathVariable Long clientId,
        @RequestBody BodyMeasurementDto measurementDto,
        Authentication authentication) {

    String email = authentication.getName();
    Optional<User> trainerOpt = userService.findByEmail(email);
    if (trainerOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    User trainer = trainerOpt.get();
    trainerService.addBodyMeasurement(trainer.getId(), clientId, measurementDto);
    return ResponseEntity.ok("Medición corporal añadida exitosamente");
}



    @PostMapping("/clients/{clientId}")
    @PreAuthorize("hasRole('TRAINER')")
    public ResponseEntity<?> addClientToTrainer(
            @PathVariable Long clientId,
            Authentication authentication) {

        String email = authentication.getName();
        Optional<User> trainerOpt = userService.findByEmail(email);
        if (!trainerOpt.isPresent()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User trainer = trainerOpt.get();

        trainerService.addClientToTrainer(trainer.getId(), clientId);
        return ResponseEntity.ok("Cliente asignado al entrenador exitosamente");
    }
    

@GetMapping("/clients")
@PreAuthorize("hasRole('TRAINER')")
public ResponseEntity<List<UserDto>> getAssignedClients(Authentication authentication) {
    String email = authentication.getName();
    Optional<User> trainerOpt = userService.findByEmail(email);
    if (trainerOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    User trainer = trainerOpt.get();
    
    // Obtener el PersonalTrainer asociado al User
    Optional<PersonalTrainer> personalTrainerOpt = trainerService.findByUserId(trainer.getId());
    if (personalTrainerOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
    }
    PersonalTrainer personalTrainer = personalTrainerOpt.get();
    
    // Ahora usa el ID de PersonalTrainer
    List<UserDto> clients = trainerService.getAssignedClients(personalTrainer.getId());
    return ResponseEntity.ok(clients);
}




    @PutMapping("/update_details")
@PreAuthorize("hasRole('TRAINER')")
public ResponseEntity<?> updateTrainerDetails(@RequestBody TrainerUpdateRequest request, Authentication authentication) {
    String email = authentication.getName();
    trainerService.updateTrainerDetails(email, request);
    return ResponseEntity.ok("Datos del entrenador actualizados con éxito");
}

        @GetMapping("/active-clients-info")
        @PreAuthorize("hasRole('TRAINER')")
        public ResponseEntity<List<ActiveClientInfoDTO>> getActiveClientsInfo(Authentication authentication) {
            // 1. Encontrar al User entrenador
            String email = authentication.getName();
            Optional<User> trainerUserOpt = userService.findByEmail(email);
            if (trainerUserOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            User trainerUser = trainerUserOpt.get();

            // 2. Encontrar su PersonalTrainer
            Optional<PersonalTrainer> ptOpt = trainerService.findByUserId(trainerUser.getId());

            if (ptOpt.isEmpty()) {
                // Si no está registrado como trainer
                return ResponseEntity.badRequest().body(Collections.emptyList());
            }
            Long personalTrainerId = ptOpt.get().getId();

            // 3. Delegar toda la lógica al servicio
            List<ActiveClientInfoDTO> infoList = trainerService.getActiveClientsInfoForTrainer(personalTrainerId);

            return ResponseEntity.ok(infoList);
        }

        @GetMapping("/findByUserId/{userId}")
    @PreAuthorize("hasRole('TRAINER')") 
    // ^ OJO: Ajusta según quieras quién puede consultar.
    public ResponseEntity<Map<String, Object>> getTrainerByUserId(@PathVariable Long userId) {
        return trainerService.findByUserId(userId)
            .map(pt -> {
                // Devolvemos un JSON con { id: xx, ... } o lo que necesites
                Map<String, Object> response = new HashMap<>();
                response.put("id", pt.getId()); 
                response.put("username", pt.getUser().getUsername());
                response.put("specialization", pt.getSpecialization());
                return ResponseEntity.ok(response);
            })
            .orElseGet(() -> ResponseEntity.notFound().build());
    }
        
}
