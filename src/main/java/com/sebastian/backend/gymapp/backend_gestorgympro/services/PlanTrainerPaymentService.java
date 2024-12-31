package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;

@Service
public class PlanTrainerPaymentService {

    @Autowired
    private UserService userService;

    @Autowired
    private PlanService planService;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    @Autowired
    private PaymentCreationService paymentCreationService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PaymentService paymentService;

    /**
     * Crea un pago y la preferencia de Mercado Pago para:
     *   - Solo Plan
     *   - Solo Entrenador
     *   - Plan + Entrenador
     *
     * Reproduce la misma lógica que estaba en createPlanPaymentPreference:
     *  - (onlyTrainer && planId != null) => excepción
     *  - Si planId != null => busca plan, suma precio
     *  - Si trainerId != null => busca entrenador, suma tarifa
     *  - Si no se selecciona nada => excepción
     *  - Crea Payment y Preference
     *  - Envío de correo.
     *
     * @param userEmail   Email del usuario autenticado
     * @param planId      ID del plan (puede ser null)
     * @param trainerId   ID del entrenador (puede ser null)
     * @param onlyTrainer Flag que indica "solo entrenador"
     * @return Preference de Mercado Pago
     * @throws MPException si ocurre error con MercadoPago
     */
    public Preference createPlanTrainerPayment(String userEmail,
    Long planId,
    Long trainerId,
    boolean onlyTrainer) throws MPException {
        User user = getUserOrThrow(userEmail);
        validatePlanTrainerCombination(onlyTrainer, planId);
        Plan plan = retrievePlanIfPresent(planId);
        PersonalTrainer trainer = retrieveTrainerIfPresent(trainerId);
        BigDecimal totalPrice = calculateTotalPrice(plan, trainer);
        Payment payment = buildPayment(user, plan, trainer, totalPrice);
        Preference preference = createPreferenceInMercadoPago(payment);
        sendConfirmationEmail(user, plan, trainer, totalPrice);
        return preference;

        
    }
    private User getUserOrThrow(String userEmail) {
        return userService.findByEmail(userEmail)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    }
    
    private void validatePlanTrainerCombination(boolean onlyTrainer, Long planId) {
        if (onlyTrainer && planId != null) {
            throw new IllegalArgumentException("No se puede comprar solo entrenador si se selecciona un plan.");
        }
    }
    
    private Plan retrievePlanIfPresent(Long planId) {
        if (planId == null) return null;
        Plan plan = planService.getPlanById(planId);
        if (plan == null) {
            throw new IllegalArgumentException("Plan no encontrado con ID: " + planId);
        }
        return plan;
    }
    
    private PersonalTrainer retrieveTrainerIfPresent(Long trainerId) {
        if (trainerId == null) return null;
        PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
            .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
        if (!trainer.getAvailability()) {
            throw new IllegalArgumentException("El entrenador no está disponible.");
        }
        if (trainer.getMonthlyFee() == null) {
            throw new IllegalArgumentException("El entrenador no tiene una tarifa definida.");
        }
        return trainer;
    }
    
    private BigDecimal calculateTotalPrice(Plan plan, PersonalTrainer trainer) {
        BigDecimal total = BigDecimal.ZERO;
        if (plan != null) {
            total = total.add(plan.getPrice());
        }
        if (trainer != null) {
            total = total.add(trainer.getMonthlyFee());
        }
        if (total.compareTo(BigDecimal.ZERO) == 0) {
            throw new IllegalArgumentException("Debe seleccionar al menos un plan o un entrenador.");
        }
        return total;
    }
    
    private Payment buildPayment(User user, Plan plan, PersonalTrainer trainer, BigDecimal totalPrice) {
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setPlan(plan);
        payment.setTrainerId(trainer != null ? trainer.getId() : null);
        payment.setStatus("pending");
        payment.setTransactionAmount(totalPrice);
        payment.setTrainerIncluded(trainer != null);
        payment.setPlanIncluded(plan != null);
        return payment;
    }
    
    private Preference createPreferenceInMercadoPago(Payment payment) throws MPException {
        return paymentCreationService.createPayment(payment, "Compra de Plan/Entrenador");
    }
    
    private void sendConfirmationEmail(User user, Plan plan, PersonalTrainer trainer, BigDecimal totalPrice) {
        String emailBody = buildEmailBody(user, plan, trainer, totalPrice);
        emailService.sendEmail(user.getEmail(), "Confirmación de compra - GestorGymPro", emailBody);
    }
    

    /**
     * Construye el cuerpo del correo de confirmación
     * con toda la información de plan y/o entrenador.
     */
    private String buildEmailBody(User user, Plan plan, PersonalTrainer trainer, BigDecimal totalPrice) {
        StringBuilder sb = new StringBuilder();
        sb.append("Hola ").append(user.getUsername()).append(",\n\n")
          .append("Tu compra de ");
        
        if (plan != null) {
            sb.append("el plan '").append(plan.getName()).append("' ");
        }
        if (trainer != null) {
            sb.append(plan != null ? "y el entrenador " : "el entrenador ")
              .append(trainer.getUser().getUsername()).append(" ");
        }
        sb.append("se ha registrado con éxito.\n\n")
          .append("Monto total: $").append(totalPrice).append("\n")
          .append("Gracias por tu compra.");

        return sb.toString();
    }
}

