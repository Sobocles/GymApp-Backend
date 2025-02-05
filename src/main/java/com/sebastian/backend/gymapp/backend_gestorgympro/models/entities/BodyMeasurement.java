package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "body_measurements")
public class BodyMeasurement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private User client;

    @ManyToOne
    @JoinColumn(name = "trainer_id", nullable = false)
    private User trainer;

    private String clientName;
  
 
  
    private Double weight; // Peso en kg
    private Double height; // Altura en cm
    private Double bodyFatPercentage; // Porcentaje de grasa corporal
    private LocalDateTime date; // Fecha de evaluación

    // Información de salud
    private String injuries; // Lesiones
    private String medications; // Medicamentos
    private String otherHealthInfo; // Otros

    // Información deportiva
    private Boolean currentlyExercising; // Ejercita actualmente
    private String sportsPracticed; // Deportes que practica

    // Información IMC
    private Double currentWeight; // Peso actual
    private Double bmi; // IMC

    // Perímetros corporales
    private Double relaxedArm; // Brazo relajado
    private Double waist; // Cintura
    private Double midThigh; // Muslo medio
    private Double flexedArm; // Brazo en contracción
    private Double hips; // Cadera
    private Double calf; // Pantorrilla

    // Perfil antropométrico
    private Double tricepFold;
    private Double subscapularFold;
    private Double bicepFold;
    private Double suprailiacFold;

    // Interpretación de datos
    private Double sumOfFolds;
    private Double percentageOfFolds;
    private Double fatMass;
    private Double leanMass;
    private Double muscleMass;

    // Peso ideal
    private Double idealMinWeight;
    private Double idealMaxWeight;
    private String trainerRecommendations;

    private Integer age;

    public String getClientName() {
        return clientName;
    }
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public Integer getAge() {
        return age;
    }
    public void setAge(Integer age) {
        this.age = age;
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public User getClient() {
        return client;
    }
    public void setClient(User client) {
        this.client = client;
    }
    public User getTrainer() {
        return trainer;
    }
    public void setTrainer(User trainer) {
        this.trainer = trainer;
    }
    public Double getWeight() {
        return weight;
    }
    public void setWeight(Double weight) {
        this.weight = weight;
    }
    public Double getHeight() {
        return height;
    }
    public void setHeight(Double height) {
        this.height = height;
    }
    public Double getBodyFatPercentage() {
        return bodyFatPercentage;
    }
    public void setBodyFatPercentage(Double bodyFatPercentage) {
        this.bodyFatPercentage = bodyFatPercentage;
    }
    public LocalDateTime getDate() {
        return date;
    }
    public void setDate(LocalDateTime date) {
        this.date = date;
    }
    public String getInjuries() {
        return injuries;
    }
    public void setInjuries(String injuries) {
        this.injuries = injuries;
    }
    public String getMedications() {
        return medications;
    }
    public void setMedications(String medications) {
        this.medications = medications;
    }
    public String getOtherHealthInfo() {
        return otherHealthInfo;
    }
    public void setOtherHealthInfo(String otherHealthInfo) {
        this.otherHealthInfo = otherHealthInfo;
    }
    public Boolean getCurrentlyExercising() {
        return currentlyExercising;
    }
    public void setCurrentlyExercising(Boolean currentlyExercising) {
        this.currentlyExercising = currentlyExercising;
    }
    public String getSportsPracticed() {
        return sportsPracticed;
    }
    public void setSportsPracticed(String sportsPracticed) {
        this.sportsPracticed = sportsPracticed;
    }
    public Double getCurrentWeight() {
        return currentWeight;
    }
    public void setCurrentWeight(Double currentWeight) {
        this.currentWeight = currentWeight;
    }
    public Double getBmi() {
        return bmi;
    }
    public void setBmi(Double bmi) {
        this.bmi = bmi;
    }
    public Double getRelaxedArm() {
        return relaxedArm;
    }
    public void setRelaxedArm(Double relaxedArm) {
        this.relaxedArm = relaxedArm;
    }
    public Double getWaist() {
        return waist;
    }
    public void setWaist(Double waist) {
        this.waist = waist;
    }
    public Double getMidThigh() {
        return midThigh;
    }
    public void setMidThigh(Double midThigh) {
        this.midThigh = midThigh;
    }
    public Double getFlexedArm() {
        return flexedArm;
    }
    public void setFlexedArm(Double flexedArm) {
        this.flexedArm = flexedArm;
    }
    public Double getHips() {
        return hips;
    }
    public void setHips(Double hips) {
        this.hips = hips;
    }
    public Double getCalf() {
        return calf;
    }
    public void setCalf(Double calf) {
        this.calf = calf;
    }
    public Double getTricepFold() {
        return tricepFold;
    }
    public void setTricepFold(Double tricepFold) {
        this.tricepFold = tricepFold;
    }
    public Double getSubscapularFold() {
        return subscapularFold;
    }
    public void setSubscapularFold(Double subscapularFold) {
        this.subscapularFold = subscapularFold;
    }
    public Double getBicepFold() {
        return bicepFold;
    }
    public void setBicepFold(Double bicepFold) {
        this.bicepFold = bicepFold;
    }
    public Double getSuprailiacFold() {
        return suprailiacFold;
    }
    public void setSuprailiacFold(Double suprailiacFold) {
        this.suprailiacFold = suprailiacFold;
    }
    public Double getSumOfFolds() {
        return sumOfFolds;
    }
    public void setSumOfFolds(Double sumOfFolds) {
        this.sumOfFolds = sumOfFolds;
    }
    public Double getPercentageOfFolds() {
        return percentageOfFolds;
    }
    public void setPercentageOfFolds(Double percentageOfFolds) {
        this.percentageOfFolds = percentageOfFolds;
    }
    public Double getFatMass() {
        return fatMass;
    }
    public void setFatMass(Double fatMass) {
        this.fatMass = fatMass;
    }
    public Double getLeanMass() {
        return leanMass;
    }
    public void setLeanMass(Double leanMass) {
        this.leanMass = leanMass;
    }
    public Double getMuscleMass() {
        return muscleMass;
    }
    public void setMuscleMass(Double muscleMass) {
        this.muscleMass = muscleMass;
    }
    public Double getIdealMinWeight() {
        return idealMinWeight;
    }
    public void setIdealMinWeight(Double idealMinWeight) {
        this.idealMinWeight = idealMinWeight;
    }
    public Double getIdealMaxWeight() {
        return idealMaxWeight;
    }
    public void setIdealMaxWeight(Double idealMaxWeight) {
        this.idealMaxWeight = idealMaxWeight;
    }
    public String getTrainerRecommendations() {
        return trainerRecommendations;
    }
    public void setTrainerRecommendations(String trainerRecommendations) {
        this.trainerRecommendations = trainerRecommendations;
    }

    // Getters y Setters
    // ...
}
