package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAssignmentRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Routine;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerClientRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;

import org.springframework.transaction.annotation.Transactional;


@RestController
@RequestMapping("/trainers")
public class TrainerController {

    @Autowired
    private UserService userService;

    @Autowired
    private TrainerService trainerService;

    @Autowired
private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private SubscriptionService subscriptionService;

        @Autowired
    private TrainerClientRepository trainerClientRepository;

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
            request.getDescription()
        );
        return ResponseEntity.ok("Rol de Trainer asignado correctamente y especialización añadida");
    }
    

    @PostMapping("/clients/{clientId}/measurements")
    @PreAuthorize("hasRole('TRAINER')")
    public ResponseEntity<?> addBodyMeasurement(
            @PathVariable Long clientId,
            @RequestBody BodyMeasurement measurement,
            Authentication authentication) {
    
        String email = authentication.getName();
        Optional<User> trainerOpt = userService.findByEmail(email);
        if (!trainerOpt.isPresent()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User trainer = trainerOpt.get();
    
        trainerService.addBodyMeasurement(trainer.getId(), clientId, measurement);
        return ResponseEntity.ok("Medición corporal añadida exitosamente");
    }
    

    @PostMapping("/clients/{clientId}/routines")
    @PreAuthorize("hasRole('TRAINER')")
    public ResponseEntity<?> addRoutine(
            @PathVariable Long clientId,
            @RequestBody Routine routine,
            Authentication authentication) {
    
        String email = authentication.getName();
        Optional<User> trainerOpt = userService.findByEmail(email);
        if (!trainerOpt.isPresent()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User trainer = trainerOpt.get();
    
        trainerService.addRoutine(trainer.getId(), clientId, routine);
        return ResponseEntity.ok("Rutina añadida exitosamente");
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
    
/* 
        @GetMapping("/clients")
    @PreAuthorize("hasRole('TRAINER')")
    public ResponseEntity<List<UserDto>> getAssignedClients(Authentication authentication) {
        String email = authentication.getName();
        Optional<User> trainerOpt = userService.findByEmail(email);
        if (trainerOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User trainer = trainerOpt.get();
        List<UserDto> clients = trainerService.getAssignedClients(trainer.getId());
        return ResponseEntity.ok(clients);
    }
    */
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





    
    


        // Nuevo endpoint para obtener entrenadores disponibles
    @GetMapping("/available")
    public ResponseEntity<List<PersonalTrainerDto>> getAvailableTrainers() {
        
        List<PersonalTrainerDto> trainers = trainerService.getAvailableTrainers();
        return ResponseEntity.ok(trainers);
    }

    @PutMapping("/update_details")
@PreAuthorize("hasRole('TRAINER')")
public ResponseEntity<?> updateTrainerDetails(@RequestBody TrainerUpdateRequest request, Authentication authentication) {
    String email = authentication.getName();
    trainerService.updateTrainerDetails(email, request);
    return ResponseEntity.ok("Datos del entrenador actualizados con éxito");
}


}
