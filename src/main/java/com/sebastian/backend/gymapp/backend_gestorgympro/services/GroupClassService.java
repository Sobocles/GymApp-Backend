package com.sebastian.backend.gymapp.backend_gestorgympro.services;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class GroupClassService {

    @Autowired
    private GroupClassRepository groupClassRepository;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

        @Autowired
    private BookingRepository bookingRepository;

    /**
     * Crea una nueva clase grupal sin asignar entrenador todavía.
     */
    @Transactional
    public GroupClass createGroupClass(String className, LocalDateTime startTime, LocalDateTime endTime, int maxParticipants) {
        GroupClass gc = new GroupClass();
        gc.setClassName(className);
        gc.setStartTime(startTime);
        gc.setEndTime(endTime);
        gc.setMaxParticipants(maxParticipants);
        return groupClassRepository.save(gc);
    }

    /**
     * Asigna un entrenador a la clase grupal, verificando su disponibilidad.
     */
    @Transactional
    public void assignTrainerToClass(Long classId, Long trainerId) {
        GroupClass gc = groupClassRepository.findById(classId)
            .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada"));

        PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
            .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado"));

        // Verificar disponibilidad del entrenador en ese horario:
        // Si el entrenador tiene entrenos personales agendados que se solapen con la clase, no se puede asignar.
        boolean hasOverlap = bookingRepository.hasOverlappingBookings(trainerId, gc.getStartTime(), gc.getEndTime());
        if (hasOverlap) {
            throw new IllegalArgumentException("El entrenador no está disponible en el horario de esta clase");
        }

        gc.setAssignedTrainer(trainer);
        groupClassRepository.save(gc);
    }

    public Optional<GroupClass> findById(Long id){
        return groupClassRepository.findById(id);
    }

    public List<GroupClass> findFutureClasses() {
        return groupClassRepository.findByStartTimeAfter(LocalDateTime.now());
    }

}
