package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Routine;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;

@RestController
@RequestMapping("/clients")
public class ClientController {

    @Autowired
    private TrainerService trainerService;

    @GetMapping("/{clientId}/measurements")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<BodyMeasurement>> getBodyMeasurements(@PathVariable Long clientId) {
        List<BodyMeasurement> measurements = trainerService.getClientBodyMeasurements(clientId);
        return ResponseEntity.ok(measurements);
    }

    @GetMapping("/{clientId}/routines")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<Routine>> getRoutines(@PathVariable Long clientId) {
        List<Routine> routines = trainerService.getClientRoutines(clientId);
        return ResponseEntity.ok(routines);
    }
}

