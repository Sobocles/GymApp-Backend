package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.mappear;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

public class DtoMapperPersonalTrainer {

    private PersonalTrainer personalTrainer;

    private DtoMapperPersonalTrainer() {}

    public static DtoMapperPersonalTrainer builder() {
        return new DtoMapperPersonalTrainer();
    }

    public DtoMapperPersonalTrainer setPersonalTrainer(PersonalTrainer personalTrainer) {
        this.personalTrainer = personalTrainer;
        return this;
    }

    public PersonalTrainerDto build() {
        if (personalTrainer == null) {
            throw new RuntimeException("Debe pasar el entity personalTrainer!");
        }
        return new PersonalTrainerDto(
                personalTrainer.getId(),
                personalTrainer.getSpecialization(),
                personalTrainer.getExperienceYears(),
                personalTrainer.getAvailability()
        );
    }
}

