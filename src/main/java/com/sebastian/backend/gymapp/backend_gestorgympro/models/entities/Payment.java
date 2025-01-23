package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "payments")
public class Payment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Relación muchos a uno con User
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;

    // Relación muchos a uno con Plan
    @ManyToOne
    @JoinColumn(name = "plan_id", nullable = true)
    @JsonIgnore
    private Plan plan;

    @OneToOne(mappedBy = "payment")
    @JsonIgnore
    private Subscription subscription;

    @Column(name = "mercado_pago_id", nullable = true)
    private String mercadoPagoId;

    private String status; 

    @Column(name = "transaction_amount")
    private BigDecimal transactionAmount;

    @Column(name = "payment_method")
    private String paymentMethod;

    @Column(name = "payment_date")
    private LocalDateTime paymentDate;

    @Column(name = "update_date")
    private LocalDateTime updateDate;

    @Column(name = "external_reference")
    private String externalReference;

    @Column(name = "trainer_id", nullable = true)
    private Long trainerId;

    @Column(name = "plan_included", nullable = false)
    private boolean planIncluded = false;

    @Column(name = "trainer_included", nullable = false)
    private boolean trainerIncluded = false;

    @Column(name = "payment_type", nullable = false)
    private String paymentType; 


        public Subscription getSubscription() {
        return subscription;
    }

    public void setSubscription(Subscription subscription) {
        this.subscription = subscription;
    }

    public String getPaymentType() {
        return paymentType;
    }

    public void setPaymentType(String paymentType) {
        this.paymentType = paymentType;
    }

        // Getters y Setters
        public Long getTrainerId() { return trainerId; }

        public void setTrainerId(Long trainerId) { this.trainerId = trainerId; }

        public boolean isPlanIncluded() { return planIncluded; }

        public void setPlanIncluded(boolean planIncluded) { this.planIncluded = planIncluded; }

        public boolean isTrainerIncluded() { return trainerIncluded; }

        public void setTrainerIncluded(boolean trainerIncluded) { this.trainerIncluded = trainerIncluded; }

    
    public void setExternalReference(String externalReference) {
        this.externalReference = externalReference;
    }

    public Long getId() {
        return id;
    }
    public String getExternalReference() {
        return externalReference;
    }
    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Plan getPlan() {
        return plan;
    }

    public void setPlan(Plan plan) {
        this.plan = plan;
    }

    public String getMercadoPagoId() {
        return mercadoPagoId;
    }

    public void setMercadoPagoId(String mercadoPagoId) {
        this.mercadoPagoId = mercadoPagoId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public BigDecimal getTransactionAmount() {
        return transactionAmount;
    }

    public void setTransactionAmount(BigDecimal transactionAmount) {
        this.transactionAmount = transactionAmount;
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

    public LocalDateTime getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(LocalDateTime updateDate) {
        this.updateDate = updateDate;
    }

  
  
}

