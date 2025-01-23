package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;


import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "subscriptions")
public class Subscription {
    
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
        @JoinColumn(name = "plan_id", nullable = false)
        private Plan plan;

        @OneToOne
        @JoinColumn(name = "payment_id")
        private Payment payment;

          @Column(name = "plan_name_snapshot")
    private String planNameSnapshot;

    @Column(name = "plan_price_snapshot")
    private BigDecimal planPriceSnapshot;

    // En Subscription.java
    @Column(name = "plan_version_snapshot")
    private Integer planVersionSnapshot; // en vez de int

    
        public Payment getPayment() {
            return payment;
        }

        public void setPayment(Payment payment) {
            this.payment = payment;
        }

        @Column(name = "start_date", nullable = false)
        private LocalDate startDate;
    
        @Column(name = "end_date", nullable = false)
        private LocalDate endDate;
    
        private Boolean active;

    public Long getId() {
        return id;
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

    public LocalDate getStartDate() {
        return startDate;
    }

    public void setStartDate(LocalDate startDate) {
        this.startDate = startDate;
    }

    public LocalDate getEndDate() {
        return endDate;
    }

    public void setEndDate(LocalDate endDate) {
        this.endDate = endDate;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    
    public String getPlanNameSnapshot() {
        return planNameSnapshot;
    }

    public void setPlanNameSnapshot(String planNameSnapshot) {
        this.planNameSnapshot = planNameSnapshot;
    }

    public BigDecimal getPlanPriceSnapshot() {
        return planPriceSnapshot;
    }

    public void setPlanPriceSnapshot(BigDecimal planPriceSnapshot) {
        this.planPriceSnapshot = planPriceSnapshot;
    }

    public Integer getPlanVersionSnapshot() {
        return planVersionSnapshot;
    }
    public void setPlanVersionSnapshot(Integer planVersionSnapshot) {
        this.planVersionSnapshot = planVersionSnapshot;
    }
    



}

