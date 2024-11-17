package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.CarouselImage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CarouselImageRepository extends JpaRepository<CarouselImage, Long> {
    List<CarouselImage> findAllByOrderByOrderNumberAsc();
}
