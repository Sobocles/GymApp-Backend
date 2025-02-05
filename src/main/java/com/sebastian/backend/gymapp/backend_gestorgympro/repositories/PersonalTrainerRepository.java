package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PersonalTrainerRepository extends JpaRepository<PersonalTrainer, Long> {

    boolean existsByUserId(Long userId);

    List<PersonalTrainer> findByAvailability(Boolean availability);

    Optional<PersonalTrainer> findByUserId(Long userId); 

   
}






