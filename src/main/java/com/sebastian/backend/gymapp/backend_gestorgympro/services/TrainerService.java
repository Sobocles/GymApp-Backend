package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

import org.springframework.web.multipart.MultipartFile;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ActiveClientInfoDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.BodyMeasurementDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAssignmentRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.BodyMeasurement;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;


public interface TrainerService {

    //void assignTrainerRole(Long userId, String specialization, Integer experienceYears, Boolean availability, 
                      // BigDecimal monthlyFee, String title, String studies, String certifications, String description, String instagramUrl, String whatsappNumber );

    void updateTrainerDetails(String email, TrainerUpdateRequest request);


    void addClientToTrainer(Long trainerId, Long clientId);

    //void removeClientFromTrainer(Long trainerId, Long clientId);

       void addBodyMeasurement(Long trainerId, Long clientId, BodyMeasurementDto measurementDto);


    //void addRoutine(Long trainerId, Long clientId, Routine routine);

    List<BodyMeasurement> getClientBodyMeasurements(Long clientId);

    //List<Routine> getClientRoutines(Long clientId);

    List<UserDto> getAssignedClients(Long trainerId);

    List<PersonalTrainerDto> getAvailableTrainers();

    Optional<PersonalTrainer> findByUserId(Long userId);

    // En TrainerService
Optional<PersonalTrainer> findPersonalTrainerById(Long trainerId);

    /**
     * Retorna la lista de clientes que tienen un plan o sub personal con este entrenador,
     * con la información de las fechas de suscripción.
     */
    List<ActiveClientInfoDTO> getActiveClientsInfoForTrainer(Long personalTrainerId);

    List<PersonalTrainerDto> getAvailableTrainersForSlot(LocalDate day, LocalTime startTime, LocalTime endTime);

       void assignTrainerRoleWithFile(Long userId,
                                   TrainerAssignmentRequest request,
                                   MultipartFile certificationFile) throws IOException;

}

