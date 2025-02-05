package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

// package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDate;

public class ActiveClientInfoDTO {
    private Long clientId;
    private String clientName;
    private String clientEmail;
    
    // Si el cliente tiene un Plan activo que incluye a este entrenador:
    private String planName;        // nombre del plan
    private LocalDate planStart;    // fecha inicio
    private LocalDate planEnd;      // fecha fin

    // Si el cliente tiene un "trainer only" (PersonalTrainerSubscription):
    private LocalDate trainerStart;
    private LocalDate trainerEnd;

    // Podrías agregar más campos: si está activo, etc.

    // Getters y setters
    // (o usa Lombok @Data)
    public Long getClientId() {
        return clientId;
    }
    public void setClientId(Long clientId) {
        this.clientId = clientId;
    }

    public String getClientName() {
        return clientName;
    }
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }
    
    public String getClientEmail() {
        return clientEmail;
    }
    public void setClientEmail(String clientEmail) {
        this.clientEmail = clientEmail;
    }

    public String getPlanName() {
        return planName;
    }
    public void setPlanName(String planName) {
        this.planName = planName;
    }

    public LocalDate getPlanStart() {
        return planStart;
    }
    public void setPlanStart(LocalDate planStart) {
        this.planStart = planStart;
    }

    public LocalDate getPlanEnd() {
        return planEnd;
    }
    public void setPlanEnd(LocalDate planEnd) {
        this.planEnd = planEnd;
    }

    public LocalDate getTrainerStart() {
        return trainerStart;
    }
    public void setTrainerStart(LocalDate trainerStart) {
        this.trainerStart = trainerStart;
    }

    public LocalDate getTrainerEnd() {
        return trainerEnd;
    }
    public void setTrainerEnd(LocalDate trainerEnd) {
        this.trainerEnd = trainerEnd;
    }
}

