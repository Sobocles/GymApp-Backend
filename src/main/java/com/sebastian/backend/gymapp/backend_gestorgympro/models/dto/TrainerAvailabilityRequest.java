// src/main/java/com/sebastian/backend/gymapp/backend_gestorgympro/models/dto/TrainerAvailabilityRequest.java
package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDate;
import java.time.LocalTime;

public class TrainerAvailabilityRequest {
    private LocalDate day;
    private LocalTime startTime;
    private LocalTime endTime;

    // Getters y Setters
    public LocalDate getDay() {
        return day;
    }

    public void setDay(LocalDate day) {
        this.day = day;
    }

    public LocalTime getStartTime() {
        return startTime;
    }

    public void setStartTime(LocalTime startTime) {
        this.startTime = startTime;
    }

    public LocalTime getEndTime() {
        return endTime;
    }

    public void setEndTime(LocalTime endTime) {
        this.endTime = endTime;
    }
}
