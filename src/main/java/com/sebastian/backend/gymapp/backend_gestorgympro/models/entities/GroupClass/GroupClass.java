package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass;

import jakarta.persistence.*;
import java.time.LocalDateTime;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

@Entity
@Table(name = "group_classes")
public class GroupClass {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String className; // Ej: Zumba, Spinning, etc.

    @Column(nullable = false)
    private LocalDateTime startTime;

    @Column(nullable = false)
    private LocalDateTime endTime;

    @Column(nullable = false)
    private int maxParticipants;

    // Entrenador asignado (opcional, solo si hay uno asignado)
    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = true)
    private PersonalTrainer assignedTrainer;

    // Getter y Setters...
    
    public Long getId() {return id;}
    public void setId(Long id){this.id = id;}
    public String getClassName(){return className;}
    public void setClassName(String className){this.className = className;}
    public LocalDateTime getStartTime(){return startTime;}
    public void setStartTime(LocalDateTime startTime){this.startTime = startTime;}
    public LocalDateTime getEndTime(){return endTime;}
    public void setEndTime(LocalDateTime endTime){this.endTime = endTime;}
    public int getMaxParticipants(){return maxParticipants;}
    public void setMaxParticipants(int maxParticipants){this.maxParticipants = maxParticipants;}
    public PersonalTrainer getAssignedTrainer(){return assignedTrainer;}
    public void setAssignedTrainer(PersonalTrainer assignedTrainer){this.assignedTrainer = assignedTrainer;}
}
