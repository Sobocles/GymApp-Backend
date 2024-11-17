package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class UserDto {
    private Long id;
    private String username;
    private String email;
    private boolean admin;
    private boolean trainer;
    private String profileImageUrl; 

    public String getProfileImageUrl() {
        return profileImageUrl;
    }
    public void setProfileImageUrl(String profileImageUrl) {
        this.profileImageUrl = profileImageUrl;
    }
    public boolean isTrainer() {
        return trainer;
    }
    public void setTrainer(boolean trainer) {
        this.trainer = trainer;
    }
    public boolean isAdmin() {
        return admin;
    }
    public void setAdmin(boolean admin) {
        this.admin = admin;
    }
    public UserDto(Long id, String username, String email, boolean admin, boolean trainer, String profileImageUrl) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.admin = admin;
        this.trainer = trainer;
        this.profileImageUrl = profileImageUrl;
    }
    public UserDto() {
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
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
