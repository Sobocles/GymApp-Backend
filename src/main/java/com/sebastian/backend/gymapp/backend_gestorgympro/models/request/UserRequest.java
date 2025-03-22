package com.sebastian.backend.gymapp.backend_gestorgympro.models.request;



import com.sebastian.backend.gymapp.backend_gestorgympro.models.IUser;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public class UserRequest implements IUser {
    
    @NotBlank
    @Size(min = 4, max = 8)
    private String username;

    @NotEmpty
    @Email
    private String email;

    @NotBlank
    private String password;

    private String instagramUrl;

    private String whatsappNumber;
    

    public String getInstagramUrl() {
        return instagramUrl;
    }
    public void setInstagramUrl(String instagramUrl) {
        this.instagramUrl = instagramUrl;
    }
    public String getWhatsappNumber() {
        return whatsappNumber;
    }
    public void setWhatsappNumber(String whatsappNumber) {
        this.whatsappNumber = whatsappNumber;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    private boolean admin;
    private boolean trainer; 

    @Override
    public boolean isTrainer() {
        return trainer;
    }
    public void setTrainer(boolean trainer) {
        this.trainer = trainer;
    }
    @Override
    public boolean isAdmin() {
        return admin;
    }
    public void setAdmin(boolean admin) {
        this.admin = admin;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

    
}

