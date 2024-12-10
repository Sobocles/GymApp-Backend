package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerSubscriptionRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;

import java.time.LocalDate;
import java.util.List;

@Service
public class PersonalTrainerSubscriptionServiceImpl implements PersonalTrainerSubscriptionService {

    @Autowired
    private PersonalTrainerSubscriptionRepository personalTrainerSubscriptionRepository;

        @Autowired
    private PersonalTrainerRepository personalTrainerRepository; // Inyectamos el repositorio



    @Override
    public boolean hasActiveTrainerSubscription(Long userId, Long trainerId) {
        List<PersonalTrainerSubscription> subscriptions = personalTrainerSubscriptionRepository.findByUserId(userId);
        return subscriptions.stream().anyMatch(sub -> 
            sub.getPersonalTrainer().getId().equals(trainerId) && sub.getActive()
        );
    }

    @Override
    @Transactional
    public void createSubscriptionForTrainerOnly(Payment payment, PersonalTrainer trainer) {
        // Crear la suscripción para el entrenador
        PersonalTrainerSubscription subscription = new PersonalTrainerSubscription();
        subscription.setUser(payment.getUser());
        subscription.setPersonalTrainer(trainer);
        subscription.setPayment(payment);
        subscription.setStartDate(LocalDate.now());
        subscription.setEndDate(LocalDate.now().plusMonths(1)); // Duración estándar de 1 mes (ejemplo)
        subscription.setActive(true);

        personalTrainerSubscriptionRepository.save(subscription);
    }

@Override
public List<PersonalTrainerSubscription> getSubscriptionsByUserId(Long userId) {
    return personalTrainerSubscriptionRepository.findByUserId(userId);
}

}
