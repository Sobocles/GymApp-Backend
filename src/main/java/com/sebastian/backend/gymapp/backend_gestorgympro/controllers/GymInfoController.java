package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GymInfo;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.GymInfoService;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/gym-info")
public class GymInfoController {

    private final GymInfoService gymInfoService;
    
    @Autowired
    public GymInfoController(GymInfoService gymInfoService) {
        this.gymInfoService = gymInfoService;
    }
    
    @PostMapping
    public ResponseEntity<GymInfo> createGymInfo(@RequestBody GymInfo gymInfo) {
        GymInfo savedGymInfo = gymInfoService.saveGymInfo(gymInfo);
        return ResponseEntity.ok(savedGymInfo);
    }

    @GetMapping
    public ResponseEntity<GymInfo> getGymInfo() {
        List<GymInfo> gymInfos = gymInfoService.getAllGymInfos();
        return gymInfos.isEmpty() 
            ? ResponseEntity.notFound().build()
            : ResponseEntity.ok(gymInfos.get(0));
    }

    @PutMapping("/{id}")
    public ResponseEntity<GymInfo> updateGymInfo(
        @PathVariable Long id, 
        @RequestBody GymInfo gymInfo
    ) {
        return ResponseEntity.ok(gymInfoService.updateGymInfo(id, gymInfo));
    }
}
