package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass;

import jakarta.persistence.*;
import java.time.LocalDateTime;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

@Entity
@Table(name = "group_class_bookings",
       uniqueConstraints = {@UniqueConstraint(columnNames = {"user_id","group_class_id"})})
public class GroupClassBooking {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Usuario que reserva la clase
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Clase grupal a la que se reserva
    @ManyToOne
    @JoinColumn(name = "group_class_id", nullable = false)
    private GroupClass groupClass;

    @Column(nullable = false)
    private LocalDateTime bookingTime;

    public Long getId(){return id;}
    public void setId(Long id){this.id = id;}
    public User getUser(){return user;}
    public void setUser(User user){this.user = user;}
    public GroupClass getGroupClass(){return groupClass;}
    public void setGroupClass(GroupClass groupClass){this.groupClass = groupClass;}
    public LocalDateTime getBookingTime(){return bookingTime;}
    public void setBookingTime(LocalDateTime bookingTime){this.bookingTime = bookingTime;}
}
