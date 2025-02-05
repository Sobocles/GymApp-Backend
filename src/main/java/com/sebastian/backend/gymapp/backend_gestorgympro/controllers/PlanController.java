package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/plans")
public class PlanController {
    @Autowired
    private PlanService planService;

    
    @GetMapping
    public ResponseEntity<List<Plan>> getAllPlans() {
        // Si quieres SOLO los activos:
        // List<Plan> plans = planService.getAllActivePlans();
        // Si quieres TODOS (activos + inactivos):
        // List<Plan> plans = planService.getAllPlans();
        List<Plan> plans = planService.getAllActivePlans();
        return ResponseEntity.ok(plans);
    }

   
    @GetMapping("/{id}")
    public ResponseEntity<Plan> getPlan(@PathVariable Long id) {
        Plan plan = planService.getPlanById(id);
        if (plan == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(plan);
    }


    @PostMapping
    public ResponseEntity<Plan> createPlan(@RequestBody Plan plan) {
        Plan newPlan = planService.createPlan(plan);
        return ResponseEntity.status(HttpStatus.CREATED).body(newPlan);
    }

    // 4. Actualizar (con versión nueva)
    @PutMapping("/{id}")
    public ResponseEntity<Plan> updatePlan(@PathVariable Long id, @RequestBody Plan planDetails) {
        Plan updated = planService.updatePlan(id, planDetails);
        if (updated == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(updated);
    }

    // 5. “Eliminar” (soft delete)
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> archivePlan(@PathVariable Long id) {
        planService.archivePlan(id);
        return ResponseEntity.noContent().build();
    }
}
