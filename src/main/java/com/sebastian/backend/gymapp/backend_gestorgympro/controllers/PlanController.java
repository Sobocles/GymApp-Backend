package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/plans")
public class PlanController {

    @Autowired
    private PlanService planService;

    @GetMapping
    public List<Plan> getAllPlans() {
        return planService.getAllPlans();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Plan> getPlanById(@PathVariable Long id) {
        Plan plan = planService.getPlanById(id);
        if (plan != null) {
            return ResponseEntity.ok(plan);
        }
        return ResponseEntity.notFound().build();
    }

    @PostMapping
    public Plan createPlan(@RequestBody Plan plan) {
        return planService.createPlan(plan);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Plan> updatePlan(@PathVariable Long id, @RequestBody Plan planDetails) {
        Plan updatedPlan = planService.updatePlan(id, planDetails);
        if (updatedPlan != null) {
            return ResponseEntity.ok(updatedPlan);
        }
        return ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePlan(@PathVariable Long id) {
        planService.deletePlan(id);
        return ResponseEntity.noContent().build();
    }
}
