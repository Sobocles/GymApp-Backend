package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class PersonalTrainerDto {
    private Long id;
    private String specialization;
    private Integer experienceYears;
    private Boolean availability;

    // Constructor que necesita el mapeador DtoMapperPersonalTrainer
    public PersonalTrainerDto(Long id, String specialization, Integer experienceYears, Boolean availability) {
        this.id = id;
        this.specialization = specialization;
        this.experienceYears = experienceYears;
        this.availability = availability;
    }

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSpecialization() {
        return specialization;
    }

    public void setSpecialization(String specialization) {
        this.specialization = specialization;
    }

    public Integer getExperienceYears() {
        return experienceYears;
    }

    public void setExperienceYears(Integer experienceYears) {
        this.experienceYears = experienceYears;
    }

    public Boolean getAvailability() {
        return availability;
    }

    public void setAvailability(Boolean availability) {
        this.availability = availability;
    }
}
