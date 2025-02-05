package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

public class TimeSlotDTO {
    private Long trainerId;
    private LocalDateTime startDateTime;
    private LocalDateTime endDateTime;
    private boolean available;

    // Getters y setters
    public Long getTrainerId() {
        return trainerId;
    }

    public void setTrainerId(Long trainerId) {
        this.trainerId = trainerId;
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

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }
}
