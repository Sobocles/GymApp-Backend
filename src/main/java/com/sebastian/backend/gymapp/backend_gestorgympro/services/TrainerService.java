package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Routine;

public interface TrainerService {

    void assignTrainerRole(Long userId, String specialization, Integer experienceYears, Boolean availability, 
                       BigDecimal monthlyFee, String title, String studies, String certifications, String description);

    void updateTrainerDetails(String email, TrainerUpdateRequest request);


    void addClientToTrainer(Long trainerId, Long clientId);

    void removeClientFromTrainer(Long trainerId, Long clientId);

       void addBodyMeasurement(Long trainerId, Long clientId, BodyMeasurement measurement);

    void addRoutine(Long trainerId, Long clientId, Routine routine);

    List<BodyMeasurement> getClientBodyMeasurements(Long clientId);

    List<Routine> getClientRoutines(Long clientId);

    List<UserDto> getAssignedClients(Long trainerId);

    List<PersonalTrainerDto> getAvailableTrainers();

    Optional<PersonalTrainer> findByUserId(Long userId);

    // En TrainerService
Optional<PersonalTrainer> findPersonalTrainerById(Long trainerId);



}

