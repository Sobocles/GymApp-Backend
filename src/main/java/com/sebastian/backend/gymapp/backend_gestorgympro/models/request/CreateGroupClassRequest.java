package com.sebastian.backend.gymapp.backend_gestorgympro.models.request;

import java.time.LocalDateTime;

public class CreateGroupClassRequest {
    private String className;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private int maxParticipants;
    private Long trainerId; // Nuevo campo opcional

    public Long getTrainerId() {
        return trainerId;
    }
    public void setTrainerId(Long trainerId) {
        this.trainerId = trainerId;
    }
    // Getters y setters
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
}
