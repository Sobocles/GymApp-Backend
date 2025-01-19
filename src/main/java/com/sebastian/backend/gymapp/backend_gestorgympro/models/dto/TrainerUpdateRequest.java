package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;

public class TrainerUpdateRequest {
    private String title;

    private String studies;

    private String certifications;

    private String description;

    private BigDecimal monthlyFee;

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
    public String getTitle() {
        return title;
    }
    public void setTitle(String title) {
        this.title = title;
    }
    public String getStudies() {
        return studies;
    }
    public void setStudies(String studies) {
        this.studies = studies;
    }
    public String getCertifications() {
        return certifications;
    }
    public void setCertifications(String certifications) {
        this.certifications = certifications;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public BigDecimal getMonthlyFee() {
        return monthlyFee;
    }
    public void setMonthlyFee(BigDecimal monthlyFee) {
        this.monthlyFee = monthlyFee;
    }
}
