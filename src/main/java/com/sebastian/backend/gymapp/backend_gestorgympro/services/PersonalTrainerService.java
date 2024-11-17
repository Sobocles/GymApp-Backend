package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

import java.util.List;
import java.util.Optional;

public interface PersonalTrainerService {

    List<PersonalTrainerDto> findAll();

    Optional<PersonalTrainerDto> findById(Long id);

    PersonalTrainerDto save(PersonalTrainer personalTrainer);

    Optional<PersonalTrainerDto> update(PersonalTrainer personalTrainer, Long id);

    void remove(Long id);
}
