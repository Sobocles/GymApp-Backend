package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDate;
import java.util.List;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PlanRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.SubscriptionRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;

import jakarta.persistence.EntityNotFoundException;

@Service
public class SubscriptionServiceImpl implements SubscriptionService{

    @Autowired
    private SubscriptionRepository subscriptionRepository;

    @Autowired
    private PlanService planService;
    

    @Autowired
    private PlanRepository planRepository;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    public Subscription createSubscription(Subscription subscription) {
        return subscriptionRepository.save(subscription);
    }

    public List<Subscription> getSubscriptionsByUserId(Long userId) {
        return subscriptionRepository.findByUserId(userId);
    }

    @Override
    @Transactional
    public Subscription createSubscriptionForPayment(Payment payment) {
        Subscription subscription = new Subscription();
    
        subscription.setUser(payment.getUser());
        subscription.setPlan(payment.getPlan());
        subscription.setStartDate(LocalDate.now());
    
        // Obtenemos el plan del Payment
        Plan paymentPlan = payment.getPlan();
        if (paymentPlan != null && paymentPlan.getDurationMonths() != null && paymentPlan.getDurationMonths() > 0) {
            subscription.setEndDate(LocalDate.now().plusMonths(paymentPlan.getDurationMonths()));
        } else {
            // Valor por defecto: 1 año
            subscription.setEndDate(LocalDate.now().plusYears(1));
        }
        
        subscription.setActive(true);
        subscription.setPayment(payment);
    
        if (paymentPlan != null) {
            subscription.setPlanNameSnapshot(paymentPlan.getName());
            subscription.setPlanPriceSnapshot(paymentPlan.getPrice());
            subscription.setPlanVersionSnapshot(paymentPlan.getVersionNumber());
        }
    
        return subscriptionRepository.save(subscription);
    }
    

    
    @Override
    public boolean hasActivePlanWithTrainer(Long userId, Long trainerId) {
        System.out.println("Verificando suscripciones activas para el usuario " + userId + " con el entrenador " + trainerId);
    
        List<Subscription> activeSubscriptions = subscriptionRepository.findByUserId(userId).stream()
                .filter(Subscription::getActive)
                .toList();
    
        System.out.println("Suscripciones activas encontradas: " + activeSubscriptions);
    
        for (Subscription sub : activeSubscriptions) {
            Plan plan = sub.getPlan();
            if (plan != null && plan.getIncludedTrainers() != null) {
                for (PersonalTrainer trainer : plan.getIncludedTrainers()) {
                    System.out.println("Entrenador en el plan: " + trainer.getId());
                    if (trainer.getId().equals(trainerId)) {
                        System.out.println("Suscripción válida encontrada.");
                        return true;
                    }
                }
            }
        }
        System.out.println("No se encontraron suscripciones válidas.");
        return false;
    }
    
    @Override
public boolean hasAnyActiveSubscription(Long userId) {
    List<Subscription> subscriptions = subscriptionRepository.findByUserId(userId);
    // Verificar si existe al menos una suscripción activa
    return subscriptions.stream().anyMatch(Subscription::getActive);
}

    @Override
    @Transactional
    public void reassignPlanTrainers(Long oldTrainerId, Long newTrainerId) {
        PersonalTrainer newTrainer = personalTrainerRepository.findById(newTrainerId)
            .orElseThrow(() -> new EntityNotFoundException("Entrenador no encontrado"));
        
        List<Plan> plans = planRepository.findAllByIncludedTrainersId(oldTrainerId);
        
        plans.forEach(plan -> {
            plan.getIncludedTrainers().removeIf(pt -> pt.getId().equals(oldTrainerId));
            plan.getIncludedTrainers().add(newTrainer);
            planRepository.save(plan);
        });
    }

}
