package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;


import jakarta.persistence.*;
import java.time.LocalDate;

@Entity
@Table(name = "subscriptions")
public class Subscription {
    
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
    
        // Relación muchos a uno con User
        @ManyToOne
        @JoinColumn(name = "user_id", nullable = false)
        private User user;
    
        // Relación muchos a uno con Plan
        @ManyToOne
        @JoinColumn(name = "plan_id", nullable = false)
        private Plan plan;
    
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


}

