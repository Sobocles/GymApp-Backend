package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PlanRepository;

@Service
public class PlanService {

    @Autowired
    private PlanRepository planRepository;

    public List<Plan> getAllPlans() {
        return planRepository.findAll();
    }

    public Plan getPlanById(Long id) {
        return planRepository.findById(id).orElse(null);
    }

    public Plan createPlan(Plan plan) {
        return planRepository.save(plan);
    }

    public Plan updatePlan(Long id, Plan planDetails) {
        Plan plan = planRepository.findById(id).orElse(null);
        if (plan != null) {
            plan.setName(planDetails.getName());
            plan.setPrice(planDetails.getPrice());
            return planRepository.save(plan);
        }
        return null;
    }

    public void deletePlan(Long id) {
        planRepository.deleteById(id);
    }
}
