package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "body_measurements")
public class BodyMeasurement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Cliente al que pertenece la medición
    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private User client;

    // Entrenador que registra la medición
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private User trainer;

    private Double weight; // Peso en kg
    private Double height; // Altura en cm
    private Double bodyFatPercentage; // Porcentaje de grasa corporal
    private LocalDateTime date; // Fecha de la medición

    // Getters y Setters
    // ...
}

