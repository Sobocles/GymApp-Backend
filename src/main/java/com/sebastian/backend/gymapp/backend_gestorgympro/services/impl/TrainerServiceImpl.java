package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerUpdateRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperUser;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Role;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.RoleRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerClientRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;

import jakarta.persistence.EntityNotFoundException;

@Service
public class TrainerServiceImpl implements TrainerService{
   @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    @Autowired
    private TrainerClientRepository trainerClientRepository;

    // Agrega estas líneas para inyectar los servicios faltantes
    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private SubscriptionService subscriptionService;

        @Transactional
        public void assignTrainerRole(Long userId, String specialization, Integer experienceYears, Boolean availability, BigDecimal monthlyFee, String title, String studies, String certifications, String description) {
            Optional<User> userOptional = userRepository.findById(userId);
            if (userOptional.isEmpty()) {
                throw new EntityNotFoundException("Usuario no encontrado con ID: " + userId);
            }
        
            User user = userOptional.get();
        
            // Verificar si el rol de ROLE_TRAINER existe
            Role trainerRole = roleRepository.findByName("ROLE_TRAINER")
                    .orElseThrow(() -> new EntityNotFoundException("Rol 'ROLE_TRAINER' no encontrado"));
        
            // Asignar el rol si no lo tiene
            if (!user.getRoles().contains(trainerRole)) {
                user.getRoles().add(trainerRole);
            }
        
            // Verificar si ya existe un registro de PersonalTrainer
            if (personalTrainerRepository.existsByUserId(userId)) {
                throw new IllegalArgumentException("Este usuario ya está registrado como personal trainer.");
            }
        
            PersonalTrainer personalTrainer = new PersonalTrainer();
            personalTrainer.setUser(user);
            personalTrainer.setSpecialization(specialization);
            personalTrainer.setExperienceYears(experienceYears);
            personalTrainer.setAvailability(availability);
            personalTrainer.setMonthlyFee(monthlyFee);
        
            // Asignar los nuevos campos
            personalTrainer.setTitle(title);
            personalTrainer.setStudies(studies);
            personalTrainer.setCertifications(certifications);
            personalTrainer.setDescription(description);
        
            personalTrainerRepository.save(personalTrainer);
            userRepository.save(user);
        }
        



        @Override
        @Transactional
        public void addClientToTrainer(Long trainerId, Long clientId) {
            // Recuperar el PersonalTrainer por su ID
            PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
                .orElseThrow(() -> new EntityNotFoundException("Entrenador no encontrado con ID: " + trainerId));
        
            // Recuperar el cliente por su ID
            User client = userRepository.findById(clientId)
                .orElseThrow(() -> new EntityNotFoundException("Cliente no encontrado con ID: " + clientId));
        
            // Verificar que el entrenador tiene el rol 'ROLE_TRAINER'
            boolean isTrainer = trainer.getUser().getRoles().stream()
                    .anyMatch(role -> role.getName().equals("ROLE_TRAINER"));
        
            if (!isTrainer) {
                throw new IllegalArgumentException("El usuario no es un entrenador");
            }
        
            // Verificar si ya existe la relación
            if (trainerClientRepository.existsByTrainerIdAndClientId(trainerId, clientId)) {
                throw new IllegalArgumentException("El cliente ya está asignado a este entrenador");
            }
        
            // Crear y guardar la relación
            TrainerClient trainerClient = new TrainerClient();
            trainerClient.setTrainer(trainer); // Ahora 'trainer' es un PersonalTrainer
            trainerClient.setClient(client);
        
            trainerClientRepository.save(trainerClient);
        }
        
        
        

    @Override
    @Transactional
    public void removeClientFromTrainer(Long trainerId, Long clientId) {
        // Implementación del método
    }
/* 
        @Override
    @Transactional(readOnly = true)
    public List<UserDto> getAssignedClients(Long trainerId) {
        List<TrainerClient> trainerClients = trainerClientRepository.findByTrainerId(trainerId);
        List<UserDto> clients = trainerClients.stream()
                .map(tc -> DtoMapperUser.builder().setUser(tc.getClient()).build())
                .collect(Collectors.toList());
        return clients;
    }
*/
@Override
@Transactional(readOnly = true)
public List<UserDto> getAssignedClients(Long trainerId) {
    List<TrainerClient> trainerClients = trainerClientRepository.findByTrainerId(trainerId);
    List<UserDto> clients = trainerClients.stream()
        .map(tc -> DtoMapperUser.builder().setUser(tc.getClient()).build())
        .filter(clientDto -> {
            Long clientId = clientDto.getId();
            // Verificar si el cliente tiene suscripción activa con este entrenador
            boolean hasTrainerOnly = personalTrainerSubscriptionService.hasActiveTrainerSubscription(clientId, trainerId);
            // Verificar si el cliente tiene un plan activo que incluya al entrenador
            boolean hasPlanWithTrainer = subscriptionService.hasActivePlanWithTrainer(clientId, trainerId);
            return hasTrainerOnly || hasPlanWithTrainer;
        })
        .collect(Collectors.toList());
    return clients;
}



    @Override
    @Transactional(readOnly = true)
    public List<PersonalTrainerDto> getAvailableTrainers() {
        List<PersonalTrainer> trainers = personalTrainerRepository.findByAvailability(true);
        return trainers.stream()
            .map(trainer -> {
                User user = trainer.getUser();
                return new PersonalTrainerDto(
                    trainer.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    trainer.getSpecialization(),
                    trainer.getExperienceYears(),
                    trainer.getAvailability(),
                    user.getProfileImageUrl(),
                    trainer.getTitle(),
                    trainer.getStudies(),
                    trainer.getCertifications(),
                    trainer.getDescription()
                );
            })
            .collect(Collectors.toList());
    }

    @Override
@Transactional
public void updateTrainerDetails(String email, TrainerUpdateRequest request) {
    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

    // Verificar si existe un registro de PersonalTrainer para este usuario
    PersonalTrainer pt = personalTrainerRepository.findByUserId(user.getId())
        .orElseThrow(() -> new IllegalArgumentException("Este usuario no está registrado como entrenador"));

    // Actualizar campos del entrenador
    if (request.getTitle() != null) pt.setTitle(request.getTitle());
    if (request.getStudies() != null) pt.setStudies(request.getStudies());
    if (request.getCertifications() != null) pt.setCertifications(request.getCertifications());
    if (request.getDescription() != null) pt.setDescription(request.getDescription());
    if (request.getMonthlyFee() != null) pt.setMonthlyFee(request.getMonthlyFee());

    personalTrainerRepository.save(pt);
}

@Override
public Optional<PersonalTrainer> findByUserId(Long userId) {
    return personalTrainerRepository.findByUserId(userId);
}

@Override
@Transactional(readOnly = true)
public Optional<PersonalTrainer> findPersonalTrainerById(Long trainerId) {
    return personalTrainerRepository.findById(trainerId);
}



}
