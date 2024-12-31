package com.sebastian.backend.gymapp.backend_gestorgympro.services;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.GroupClassDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassBookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;

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

    @Autowired
    private GroupClassBookingRepository GroupbookingRepository;

    @Autowired
    private TrainerAvailabilityRepository trainerAvailabilityRepository;

    

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
        boolean hasOverlap = bookingRepository.hasOverlappingBookings(trainerId, gc.getStartTime(), gc.getEndTime());
        boolean isAvailableForClass = trainerAvailabilityRepository.isTrainerAvailable(
            trainerId,
            gc.getStartTime().toLocalDate(),
            gc.getStartTime().toLocalTime(),
            gc.getEndTime().toLocalTime()
        );
    
        if (hasOverlap || !isAvailableForClass) {
            throw new IllegalArgumentException("El entrenador no está disponible en el horario de esta clase");
        }
    
        gc.setAssignedTrainer(trainer);
        groupClassRepository.save(gc);
    }

    public Optional<GroupClass> findById(Long id){
        return groupClassRepository.findById(id);
    }

    public List<GroupClassDto> findFutureClasses() {
        List<GroupClass> futureClasses = groupClassRepository.findByStartTimeAfter(LocalDateTime.now());
        
        return futureClasses.stream()
            .map(gc -> {
                long currentBookings = GroupbookingRepository.countByGroupClassId(gc.getId());
                return new GroupClassDto(gc, currentBookings);
            })
            .toList();
    }
    

     public GroupClassDto getClassDetails(Long classId) {
        GroupClass groupClass = groupClassRepository.findById(classId)
            .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada"));

        long currentBookings = GroupbookingRepository.countByGroupClassId(classId);
        return new GroupClassDto(groupClass, currentBookings);
    }

    public GroupClass save(GroupClass groupClass) {
        return groupClassRepository.save(groupClass);
    }

}
