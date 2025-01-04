package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
        List<Payment> findByUserId(Long userId);

        Optional<Payment> findByMercadoPagoId(String mercadoPagoId);

        Optional<Payment> findByExternalReference(String externalReference);

   

                /**
         * Calcula la suma total de los pagos filtrados por tipo de servicio.
         *
         * @param serviceType El tipo de servicio para filtrar los pagos.
         * @return La suma total de los pagos filtrados como BigDecimal.
         * 
         * 
         */

         @Query("SELECT COALESCE(SUM(p.transactionAmount), 0) FROM Payment p WHERE p.status = 'approved'")
        BigDecimal getTotalApprovedRevenue();

        @Query("SELECT COALESCE(SUM(p.transactionAmount), 0) FROM Payment p " +
       "WHERE p.planIncluded = false AND p.trainerIncluded = false AND p.status = 'approved'")
        BigDecimal getTotalApprovedProductRevenue();


        

        // Total de ingresos de planes (pagos donde planIncluded es true)
@Query("SELECT COALESCE(SUM(p.transactionAmount), 0) FROM Payment p WHERE p.planIncluded = true AND p.status = 'approved'")
BigDecimal getTotalApprovedPlanRevenue();



        @Query("SELECT COALESCE(SUM(p.transactionAmount), 0) " +
        "FROM Payment p " +
        "WHERE p.planIncluded = :planIncluded AND p.trainerIncluded = :trainerIncluded")
        BigDecimal getRevenueByIncludedFlags(@Param("planIncluded") boolean planIncluded, 
                                        @Param("trainerIncluded") boolean trainerIncluded);

                                        @Query("SELECT p.plan.name AS planName, COALESCE(SUM(p.transactionAmount), 0) AS total " +
                                        "FROM Payment p " +
                                        "WHERE p.plan IS NOT NULL AND p.status = 'approved' " +
                                        "GROUP BY p.plan.name")
                                 List<Object[]> getRevenueGroupedByPlanName();
                                 
         List<Payment> findByUserIdAndStatus(Long userId, String status);  
         
         @Query("SELECT COALESCE(SUM(p.transactionAmount), 0) FROM Payment p WHERE p.planIncluded = false AND p.trainerIncluded = false")
        BigDecimal getTotalProductRevenue();

}


