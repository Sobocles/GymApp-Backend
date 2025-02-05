package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

public class CalendarEventDTO {
    private Long id;               
    private String title;          
    private LocalDateTime start;  
    private LocalDateTime end;     
    private String eventType;
    
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getTitle() {
        return title;
    }
    public void setTitle(String title) {
        this.title = title;
    }
    public LocalDateTime getStart() {
        return start;
    }
    public void setStart(LocalDateTime start) {
        this.start = start;
    }
    public LocalDateTime getEnd() {
        return end;
    }
    public void setEnd(LocalDateTime end) {
        this.end = end;
    }
    public String getEventType() {
        return eventType;
    }
    public void setEventType(String eventType) {
        this.eventType = eventType;
    }      


}

