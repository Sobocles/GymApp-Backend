package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class TrainerAssignmentRequest {
    private String specialization;
    private Integer experienceYears;
    private Boolean availability;
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