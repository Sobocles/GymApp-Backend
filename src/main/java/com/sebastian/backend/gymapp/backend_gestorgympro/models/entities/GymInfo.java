package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "gym_info")
public class GymInfo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String gymName;
    private String address;
    private String phone;
    private String email;
    private String instagram;
    private String facebook;
    private String whatsapp;
    private String twitter;

    // Constructores
    public GymInfo() {}

    public GymInfo(String gymName, String address, String phone, String email,
                   String instagram, String facebook, String whatsapp, String twitter) {
        this.gymName = gymName;
        this.address = address;
        this.phone = phone;
        this.email = email;
        this.instagram = instagram;
        this.facebook = facebook;
        this.whatsapp = whatsapp;
        this.twitter = twitter;
    }

    // Getters y Setters

    public Long getId() {
        return id;
    }

    public String getGymName() {
        return gymName;
    }

    public void setGymName(String gymName) {
        this.gymName = gymName;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }

    public String getInstagram() {
        return instagram;
    }
    
    public void setInstagram(String instagram) {
        this.instagram = instagram;
    }
    
    public String getFacebook() {
        return facebook;
    }
    
    public void setFacebook(String facebook) {
        this.facebook = facebook;
    }
    
    public String getWhatsapp() {
        return whatsapp;
    }
    
    public void setWhatsapp(String whatsapp) {
        this.whatsapp = whatsapp;
    }
    
    public String getTwitter() {
        return twitter;
    }
    
    public void setTwitter(String twitter) {
        this.twitter = twitter;
    }
}