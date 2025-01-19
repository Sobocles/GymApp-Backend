package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import java.util.List;
import java.util.Optional;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerScheduleService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;


import org.springframework.security.core.Authentication;




import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;


import org.springframework.http.HttpStatus;
import java.util.Collections;


@RestController
@RequestMapping("/clients")
public class ClientController {

    @Autowired
    private TrainerService trainerService;

    @Autowired
    private UserService userService;

    @Autowired
    private TrainerScheduleService trainerScheduleService;
    

    @GetMapping("/{clientId}/measurements")
    @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
    public ResponseEntity<List<BodyMeasurement>> getBodyMeasurements(@PathVariable Long clientId) {
        List<BodyMeasurement> measurements = trainerService.getClientBodyMeasurements(clientId);
        return ResponseEntity.ok(measurements);
    }
/* 
    @GetMapping("/{clientId}/routines")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<Routine>> getRoutines(@PathVariable Long clientId) {
        List<Routine> routines = trainerService.getClientRoutines(clientId);
        return ResponseEntity.ok(routines);
    } */

    @GetMapping("/{clientId}/sessions")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<CalendarEventDTO>> getClientSessions(
            @PathVariable Long clientId,
            Authentication authentication) {
    
        String email = authentication.getName();
        Optional<User> userOpt = userService.findByEmail(email);
        
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    
        User user = userOpt.get();
    
        if (!user.getId().equals(clientId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body(Collections.emptyList());
        }
    
        List<CalendarEventDTO> events = trainerScheduleService.getClientSessions(clientId);
    
        return ResponseEntity.ok(events);
    }
    

}

