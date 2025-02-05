package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;
import org.springframework.data.jpa.repository.JpaRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GymInfo;

public interface GymInfoRepository extends JpaRepository<GymInfo, Long> {

}
