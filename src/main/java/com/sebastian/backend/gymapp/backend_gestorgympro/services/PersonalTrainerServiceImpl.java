package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear.DtoMapperPersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class PersonalTrainerServiceImpl implements PersonalTrainerService {

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    @Override
    @Transactional(readOnly = true)
    public List<PersonalTrainerDto> findAll() {
        List<PersonalTrainer> trainers = personalTrainerRepository.findAll();
        return trainers.stream()
                .map(t -> DtoMapperPersonalTrainer.builder().setPersonalTrainer(t).build())
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<PersonalTrainerDto> findById(Long id) {
        return personalTrainerRepository.findById(id)
                .map(t -> DtoMapperPersonalTrainer.builder().setPersonalTrainer(t).build());
    }

    @Override
    @Transactional
    public PersonalTrainerDto save(PersonalTrainer personalTrainer) {
        PersonalTrainer savedTrainer = personalTrainerRepository.save(personalTrainer);
        return DtoMapperPersonalTrainer.builder().setPersonalTrainer(savedTrainer).build();
    }

    @Override
    @Transactional
    public Optional<PersonalTrainerDto> update(PersonalTrainer personalTrainer, Long id) {
        return personalTrainerRepository.findById(id).map(existingTrainer -> {
            existingTrainer.setSpecialization(personalTrainer.getSpecialization());
            existingTrainer.setExperienceYears(personalTrainer.getExperienceYears());
            existingTrainer.setAvailability(personalTrainer.getAvailability());
            personalTrainerRepository.save(existingTrainer);
            return DtoMapperPersonalTrainer.builder().setPersonalTrainer(existingTrainer).build();
        });
    }

    @Override
    @Transactional
    public void remove(Long id) {
        personalTrainerRepository.deleteById(id);
    }
}
