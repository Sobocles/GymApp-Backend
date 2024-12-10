package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "bookings")
public class Booking {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Quién reserva (User)
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Entrenador asignado (puede ser inferido desde el timeslot)
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private PersonalTrainer trainer;

    // Fecha y hora específica del slot reservado
    @Column(name = "start_date_time", nullable = false)
    private LocalDateTime startDateTime;

    @Column(name = "end_date_time", nullable = false)
    private LocalDateTime endDateTime;

    // ... otros campos que necesites

    public Long getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
         this.user = user;
    }

    public PersonalTrainer getTrainer() {
         return trainer;
    }

    public void setTrainer(PersonalTrainer trainer) {
         this.trainer = trainer;
    }

    public LocalDateTime getStartDateTime() {
         return startDateTime;
    }

    public void setStartDateTime(LocalDateTime startDateTime) {
         this.startDateTime = startDateTime;
    }

    public LocalDateTime getEndDateTime() {
         return endDateTime;
    }

    public void setEndDateTime(LocalDateTime endDateTime) {
         this.endDateTime = endDateTime;
    }
}

