package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;

public interface SubscriptionService {
    
    /**
     * Crea una nueva suscripción.
     *
     * @param subscription La suscripción a crear.
     * @return La suscripción creada.
     */
    Subscription createSubscription(Subscription subscription);

    /**
     * Obtiene todas las suscripciones de un usuario por su ID.
     *
     * @param userId El ID del usuario.
     * @return Lista de suscripciones del usuario.
     */
    List<Subscription> getSubscriptionsByUserId(Long userId);

    /**
     * Crea una suscripción a partir de un pago.
     *
     * @param payment El pago asociado a la suscripción.
     * @return La suscripción creada.
     */
    Subscription createSubscriptionForPayment(Payment payment);
    
    /**
     * Verifica si el usuario tiene una suscripción activa que incluye al entrenador especificado.
     *
     * @param userId     ID del usuario.
     * @param trainerId  ID del entrenador.
     * @return true si tiene una suscripción activa con el entrenador, false en caso contrario.
     */
    boolean hasActivePlanWithTrainer(Long userId, Long trainerId);

    boolean hasAnyActiveSubscription(Long userId);
}   
