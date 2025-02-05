// src/main/java/com/sebastian/backend/gymapp/backend_gestorgympro/models/dto/PaymentPersonalTrainerDTO.java

package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.LocalDate;

public class PaymentPersonalTrainerDTO {
    private Long paymentId;
    private String username;
    private BigDecimal transactionAmount;
    private String status;
    private String paymentMethod;
    private LocalDateTime paymentDate;
    
    // Datos de suscripción de entrenador personal
    private LocalDate trainerSubscriptionStartDate;
    private LocalDate trainerSubscriptionEndDate;
    private String personalTrainerName;

    // Constructor requerido por JPQL
    public PaymentPersonalTrainerDTO(Long paymentId, String username, BigDecimal transactionAmount, 
                                     String status, String paymentMethod, LocalDateTime paymentDate, 
                                     LocalDate trainerSubscriptionStartDate, 
                                     LocalDate trainerSubscriptionEndDate, String personalTrainerName) {
        this.paymentId = paymentId;
        this.username = username;
        this.transactionAmount = transactionAmount;
        this.status = status;
        this.paymentMethod = paymentMethod;
        this.paymentDate = paymentDate;
        this.trainerSubscriptionStartDate = trainerSubscriptionStartDate;
        this.trainerSubscriptionEndDate = trainerSubscriptionEndDate;
        this.personalTrainerName = personalTrainerName;
    }

    // Getters y Setters
    public Long getPaymentId() {
        return paymentId;
    }
    public void setPaymentId(Long paymentId) {
        this.paymentId = paymentId;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public BigDecimal getTransactionAmount() {
        return transactionAmount;
    }
    public void setTransactionAmount(BigDecimal transactionAmount) {
        this.transactionAmount = transactionAmount;
    }
    public String getStatus() {
        return status;
    }
    public void setStatus(String status) {
        this.status = status;
    }
    public String getPaymentMethod() {
        return paymentMethod;
    }
    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }
    public LocalDateTime getPaymentDate() {
        return paymentDate;
    }
    public void setPaymentDate(LocalDateTime paymentDate) {
        this.paymentDate = paymentDate;
    }
    public LocalDate getTrainerSubscriptionStartDate() {
        return trainerSubscriptionStartDate;
    }
    public void setTrainerSubscriptionStartDate(LocalDate trainerSubscriptionStartDate) {
        this.trainerSubscriptionStartDate = trainerSubscriptionStartDate;
    }
    public LocalDate getTrainerSubscriptionEndDate() {
        return trainerSubscriptionEndDate;
    }
    public void setTrainerSubscriptionEndDate(LocalDate trainerSubscriptionEndDate) {
        this.trainerSubscriptionEndDate = trainerSubscriptionEndDate;
    }
    public String getPersonalTrainerName() {
        return personalTrainerName;
    }
    public void setPersonalTrainerName(String personalTrainerName) {
        this.personalTrainerName = personalTrainerName;
    }

    // Puedes eliminar el comentario redundante de getters y setters
}
