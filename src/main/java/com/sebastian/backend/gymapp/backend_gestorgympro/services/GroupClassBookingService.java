package com.sebastian.backend.gymapp.backend_gestorgympro.services;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClassBooking;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassBookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.impl.SubscriptionServiceImpl;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class GroupClassBookingService {

    @Autowired
    private GroupClassRepository groupClassRepository;

    @Autowired
    private GroupClassBookingRepository groupClassBookingRepository;

    @Autowired
    private SubscriptionServiceImpl subscriptionService;

    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    /**
     * Lógica de reserva:
     * - El cliente debe tener un plan activo (gimnasio o gimnasio+entrenador)
     * - Puede reservar desde 12 horas antes hasta 1 hora antes de la clase
     * - Verificar que no haya alcanzado el cupo máximo
     * - Verificar que la clase no haya comenzado
     * - Verificar que el usuario no haya reservado ya esa clase
     */
    @Transactional
    public boolean bookClass(User user, Long classId) {
        GroupClass gc = groupClassRepository.findById(classId)
            .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada"));

        LocalDateTime now = LocalDateTime.now();

        // Verificar que tenga algún plan activo
        // Para simplificar, asumamos que si el usuario tiene cualquier suscripción activa (plan o entrenador), puede reservar
        boolean hasActivePlan = subscriptionService.hasAnyActiveSubscription(user.getId()) ||
                                !personalTrainerSubscriptionService.getSubscriptionsByUserId(user.getId()).isEmpty();
        if(!hasActivePlan) {
            throw new IllegalArgumentException("No tienes plan activo para reservar esta clase");
        }

        // Verificar ventana de tiempo: desde 12h antes hasta 1h antes
        LocalDateTime classStart = gc.getStartTime();
        LocalDateTime earliestBooking = classStart.minusHours(12);
        LocalDateTime latestBooking = classStart.minusHours(1);

        if (now.isBefore(earliestBooking) || now.isAfter(latestBooking)) {
            throw new IllegalArgumentException("No puedes reservar fuera del rango permitido");
        }

        // Verificar que no haya comenzado la clase
        if (now.isAfter(classStart)) {
            throw new IllegalArgumentException("La clase ya ha comenzado, no puedes reservar");
        }

        // Verificar cupo
        long currentBookings = groupClassBookingRepository.countByGroupClassId(classId);
        if (currentBookings >= gc.getMaxParticipants()) {
            throw new IllegalArgumentException("La clase ya alcanzó el cupo máximo");
        }

        // Verificar que el usuario no haya reservado ya esta clase
        if (groupClassBookingRepository.existsByUserIdAndGroupClassId(user.getId(), classId)) {
            throw new IllegalArgumentException("Ya tienes una reserva en esta clase");
        }

        // Crear reserva
        GroupClassBooking booking = new GroupClassBooking();
        booking.setUser(user);
        booking.setGroupClass(gc);
        booking.setBookingTime(now);
        groupClassBookingRepository.save(booking);

        return true;
    }
}
