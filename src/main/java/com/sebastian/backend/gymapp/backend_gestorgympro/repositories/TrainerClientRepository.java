package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface TrainerClientRepository extends JpaRepository<TrainerClient, Long> {

    List<TrainerClient> findByTrainerId(Long trainerId);

    List<TrainerClient> findByClientId(Long clientId);

    boolean existsByTrainerIdAndClientId(Long trainerId, Long clientId);
}
