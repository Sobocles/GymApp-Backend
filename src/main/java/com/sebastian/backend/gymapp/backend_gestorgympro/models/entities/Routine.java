package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "routines")
public class Routine {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Cliente al que pertenece la rutina
    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private User client;

    // Entrenador que asigna la rutina
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private User trainer;

    private String title;
    private String description;
    private LocalDateTime assignedDate;

    // Getters y Setters
    // ...
}

