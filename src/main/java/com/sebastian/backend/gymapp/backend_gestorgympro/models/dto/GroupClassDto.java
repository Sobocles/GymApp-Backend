package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;

public class GroupClassDto {
    private Long id;
    private String className;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private int maxParticipants;
    private int availableSlots; // Cupos disponibles

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public LocalDateTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalDateTime startTime) {
        this.startTime = startTime;
    }

    public LocalDateTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalDateTime endTime) {
        this.endTime = endTime;
    }

    public int getMaxParticipants() {
        return maxParticipants;
    }

    public void setMaxParticipants(int maxParticipants) {
        this.maxParticipants = maxParticipants;
    }

    public int getAvailableSlots() {
        return availableSlots;
    }

    public void setAvailableSlots(int availableSlots) {
        this.availableSlots = availableSlots;
    }

    public GroupClassDto(GroupClass groupClass, long currentBookings) {
        this.id = groupClass.getId();
        this.className = groupClass.getClassName();
        this.startTime = groupClass.getStartTime();
        this.endTime = groupClass.getEndTime();
        this.maxParticipants = groupClass.getMaxParticipants();
        this.availableSlots = (int) (groupClass.getMaxParticipants() - currentBookings);
    }

    // Getters y Setters...
}
