package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

public class PaymentPlanDTO {
        private Long paymentId;
    private Long planId;
    private String username;
    private BigDecimal transactionAmount;
    private String status;
    private String paymentMethod;
    private LocalDateTime paymentDate;
    
    // Datos de suscripción
    private LocalDate subscriptionStartDate;
    private LocalDate subscriptionEndDate;
    
    // Datos de suscripción de entrenador personal (si aplica)
    private LocalDate trainerSubscriptionStartDate;
    private LocalDate trainerSubscriptionEndDate;
    private String personalTrainerName;

    public PaymentPlanDTO(Long paymentId, Long planId, String username, BigDecimal transactionAmount, 
    String status, String paymentMethod, LocalDateTime paymentDate, 
    LocalDate subscriptionStartDate, LocalDate subscriptionEndDate, 
    LocalDate trainerSubscriptionStartDate, LocalDate trainerSubscriptionEndDate, 
    String personalTrainerName) {
this.paymentId = paymentId;
this.planId = planId;
this.username = username;
this.transactionAmount = transactionAmount;
this.status = status;
this.paymentMethod = paymentMethod;
this.paymentDate = paymentDate;
this.subscriptionStartDate = subscriptionStartDate;
this.subscriptionEndDate = subscriptionEndDate;
this.trainerSubscriptionStartDate = trainerSubscriptionStartDate;
this.trainerSubscriptionEndDate = trainerSubscriptionEndDate;
this.personalTrainerName = personalTrainerName;
}
    
    public Long getPaymentId() {
        return paymentId;
    }
    public void setPaymentId(Long paymentId) {
        this.paymentId = paymentId;
    }
    public Long getPlanId() {
        return planId;
    }
    public void setPlanId(Long planId) {
        this.planId = planId;
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
    public LocalDate getSubscriptionStartDate() {
        return subscriptionStartDate;
    }
    public void setSubscriptionStartDate(LocalDate subscriptionStartDate) {
        this.subscriptionStartDate = subscriptionStartDate;
    }
    public LocalDate getSubscriptionEndDate() {
        return subscriptionEndDate;
    }
    public void setSubscriptionEndDate(LocalDate subscriptionEndDate) {
        this.subscriptionEndDate = subscriptionEndDate;
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
}
