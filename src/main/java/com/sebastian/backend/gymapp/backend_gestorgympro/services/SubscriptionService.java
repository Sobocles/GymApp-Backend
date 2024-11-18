package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.SubscriptionRepository;

@Service
public class SubscriptionService {

    @Autowired
    private SubscriptionRepository subscriptionRepository;

    public Subscription createSubscription(Subscription subscription) {
        return subscriptionRepository.save(subscription);
    }

    public List<Subscription> getSubscriptionsByUserId(Long userId) {
        return subscriptionRepository.findByUserId(userId);
    }


}
