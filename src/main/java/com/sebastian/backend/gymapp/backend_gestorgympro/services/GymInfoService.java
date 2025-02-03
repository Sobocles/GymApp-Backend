package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GymInfo;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GymInfoRepository;

@Service
public class GymInfoService {

        private final GymInfoRepository gymInfoRepository;
    
    @Autowired
    public GymInfoService(GymInfoRepository gymInfoRepository) {
        this.gymInfoRepository = gymInfoRepository;
    }
    
    public GymInfo saveGymInfo(GymInfo gymInfo) {
        return gymInfoRepository.save(gymInfo);
    }

    public List<GymInfo> getAllGymInfos() {
        return gymInfoRepository.findAll();
    }

    public GymInfo updateGymInfo(Long id, GymInfo gymInfoDetails) {
        GymInfo existing = gymInfoRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("GymInfo no encontrado"));
        
        existing.setGymName(gymInfoDetails.getGymName());
        existing.setAddress(gymInfoDetails.getAddress());
        existing.setPhone(gymInfoDetails.getPhone());
        existing.setEmail(gymInfoDetails.getEmail());
        existing.setInstagram(gymInfoDetails.getInstagram());
        existing.setFacebook(gymInfoDetails.getFacebook());
        existing.setWhatsapp(gymInfoDetails.getWhatsapp());
        existing.setTwitter(gymInfoDetails.getTwitter());
        
        return gymInfoRepository.save(existing);
    }

}
