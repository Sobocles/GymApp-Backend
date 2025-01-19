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

    public List<Plan> getAllActivePlans() {
        // Retorna solo planes activos
        return planRepository.findByActiveTrue();
    }

    public Plan getPlanById(Long id) {
        // Podrías buscar sin filtrar "active"
        return planRepository.findById(id).orElse(null);
    }

    public Plan createPlan(Plan plan) {
        // Al crear un plan nuevo, version=1, active=true
        plan.setVersionNumber(1);
        plan.setActive(true);
        return planRepository.save(plan);
    }

    /**
     * “Actualiza” un plan con versionado: 
     * 1. Inactiva el plan viejo
     * 2. Crea un clon con versión + 1 y los nuevos datos
     */
    public Plan updatePlan(Long planId, Plan planDetails) {
        Plan oldPlan = planRepository.findById(planId).orElse(null);
        if (oldPlan == null) {
            return null;
        }
    
        // Inactiva el plan anterior
        oldPlan.setActive(false);
        planRepository.save(oldPlan);
    
        // Crear uno nuevo con version + 1
        Plan newPlanVersion = new Plan();
        newPlanVersion.setName(planDetails.getName());
        newPlanVersion.setPrice(planDetails.getPrice());
        newPlanVersion.setDescription(planDetails.getDescription());
        
        // Copiar también discount y discountReason
        newPlanVersion.setDiscount(planDetails.getDiscount());
        newPlanVersion.setDiscountReason(planDetails.getDiscountReason());
        
        newPlanVersion.setVersionNumber(oldPlan.getVersionNumber() + 1);
        newPlanVersion.setActive(true);
    
        return planRepository.save(newPlanVersion);
    }
    

    /**
     * Soft-delete: inactiva el plan, sin borrarlo físicamente
     */
    public void archivePlan(Long id) {
        Plan plan = planRepository.findById(id).orElse(null);
        if (plan != null) {
            plan.setActive(false);
            planRepository.save(plan);
        }
    }
}
