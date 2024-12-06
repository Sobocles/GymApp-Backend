package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;

@Entity
@Table(name = "trainer_clients")
public class TrainerClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // El entrenador
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private User trainer;

    // El cliente
    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private User client;

    // Getters y Setters

    public Long getId() {
        return id;
    }

    public User getTrainer() {
        return trainer;
    }

    public void setTrainer(User trainer) {
        this.trainer = trainer;
    }

    public User getClient() {
        return client;
    }

    public void setClient(User client) {
        this.client = client;
    }
}
