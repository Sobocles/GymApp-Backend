package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.time.LocalDate;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.SubscriptionRepository;

@Service
public class SubscriptionStatusUpdaterService {

    @Autowired
    private SubscriptionRepository subscriptionRepository;

    // Se ejecuta todos los días a medianoche
    @Scheduled(cron = "0 0 0 * * ?")
    public void updateExpiredSubscriptions() {
        LocalDate today = LocalDate.now();
        
        // Suponiendo que tienes un método en el repositorio que devuelva todas las suscripciones activas
        List<Subscription> activeSubscriptions = subscriptionRepository.findByActiveTrue();
        
        activeSubscriptions.forEach(subscription -> {
            if (subscription.getEndDate() != null && subscription.getEndDate().isBefore(today)) {
                subscription.setActive(false);
            }
        });
        
        subscriptionRepository.saveAll(activeSubscriptions);
    }
}