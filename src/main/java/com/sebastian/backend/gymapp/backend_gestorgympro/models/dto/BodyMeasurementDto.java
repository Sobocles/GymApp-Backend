package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.time.LocalDateTime;

public class BodyMeasurementDto {

    private Integer age; 

    private String clientName;

    // Getters y Setters
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
    private Double weight;
    private Double height;
    private Double bodyFatPercentage;
    private LocalDateTime date;

    private String injuries;
    private String medications;
    private String otherHealthInfo;

    private Boolean currentlyExercising;
    private String sportsPracticed;

    private Double currentWeight;
    private Double bmi;

    private Double relaxedArm;
    private Double waist;
    private Double midThigh;
    private Double flexedArm;
    private Double hips;
    private Double calf;

    private Double tricepFold;
    private Double subscapularFold;
    private Double bicepFold;
    private Double suprailiacFold;

    private Double sumOfFolds;
    private Double percentageOfFolds;
    private Double fatMass;
    private Double leanMass;
    private Double muscleMass;

    private Double idealMinWeight;
    private Double idealMaxWeight;
    private String trainerRecommendations;

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

