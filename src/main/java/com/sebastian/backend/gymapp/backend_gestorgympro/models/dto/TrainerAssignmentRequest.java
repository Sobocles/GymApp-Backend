package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;

public class TrainerAssignmentRequest {
    private String specialization;
    private Integer experienceYears;
    private Boolean availability;
    private BigDecimal monthlyFee;

    // Nuevos campos
    private String title;
    private String studies;
    private String certifications;
    private String description;

    private String instagramUrl;
    private String whatsappNumber;

    public String getInstagramUrl() {
        return instagramUrl;
    }
    public void setInstagramUrl(String instagramUrl) {
        this.instagramUrl = instagramUrl;
    }
    public String getWhatsappNumber() {
        return whatsappNumber;
    }
    public void setWhatsappNumber(String whatsappNumber) {
        this.whatsappNumber = whatsappNumber;
    }
    // Getters y Setters de todos los campos
    public String getSpecialization() { return specialization; }
    public void setSpecialization(String specialization) { this.specialization = specialization; }

    public Integer getExperienceYears() { return experienceYears; }
    public void setExperienceYears(Integer experienceYears) { this.experienceYears = experienceYears; }

    public Boolean getAvailability() { return availability; }
    public void setAvailability(Boolean availability) { this.availability = availability; }

    public BigDecimal getMonthlyFee() { return monthlyFee; }
    public void setMonthlyFee(BigDecimal monthlyFee) { this.monthlyFee = monthlyFee; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getStudies() { return studies; }
    public void setStudies(String studies) { this.studies = studies; }

    public String getCertifications() { return certifications; }
    public void setCertifications(String certifications) { this.certifications = certifications; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
