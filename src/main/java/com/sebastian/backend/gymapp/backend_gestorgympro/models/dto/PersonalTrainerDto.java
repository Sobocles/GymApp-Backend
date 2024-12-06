package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class PersonalTrainerDto {
    private Long id;
    private String username;
    private String email;
    private String specialization;
    private Integer experienceYears;
    
    private Boolean availability;
    private String profileImageUrl;

    // Nuevos campos
    private String title;
    private String studies;
    private String certifications;
    private String description;

    public PersonalTrainerDto(Long id, String username, String email, String specialization,
    Integer experienceYears, Boolean availability, String profileImageUrl,
    String title, String studies, String certifications, String description) {
    this.id = id;
    this.username = username;
    this.email = email;
    this.specialization = specialization;
    this.experienceYears = experienceYears;
    this.availability = availability;
    this.profileImageUrl = profileImageUrl;
    this.title = title;
    this.studies = studies;
    this.certifications = certifications;
    this.description = description;
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

    public String getSpecialization() {
        return specialization;
    }

    public void setSpecialization(String specialization) {
        this.specialization = specialization;
    }

    public Integer getExperienceYears() {
        return experienceYears;
    }

    public void setExperienceYears(Integer experienceYears) {
        this.experienceYears = experienceYears;
    }

    public Boolean getAvailability() {
        return availability;
    }

    public void setAvailability(Boolean availability) {
        this.availability = availability;
    }

    public String getProfileImageUrl() {
        return profileImageUrl;
    }

    public void setProfileImageUrl(String profileImageUrl) {
        this.profileImageUrl = profileImageUrl;
    }



    // Getters y Setters para los nuevos campos
    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getStudies() {
        return studies;
    }

    public void setStudies(String studies) {
        this.studies = studies;
    }

    public String getCertifications() {
        return certifications;
    }

    public void setCertifications(String certifications) {
        this.certifications = certifications;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    // Resto de getters y setters existentes...
}
