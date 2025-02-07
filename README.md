# 🏋️♂️ Gym Pro  

[![Licencia](https://img.shields.io/badge/Licencia-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Estado](https://img.shields.io/badge/Estado-En%20Desarrollo-orange)](https://github.com/tu-usuario/gym-pro)

🔍 **Plataforma integral para gestión de gimnasios**  
Solución todo-en-uno que combina e-commerce de suplementos, gestión de usuarios, planes personalizados y reservas con personal trainers. Desarrollada con **React + TypeScript** (frontend) y **Java Spring Boot** (backend).

---

## 📌 Tabla de Contenidos  
- [Características](#-características)  
- [Demo](#-demo)  
- [Tecnologías](#-tecnologías)  
- [Instalación](#-instalación)  
- [Uso](#-uso)  
- [Contribuir](#-contribuir)  
- [Licencia](#-licencia)  
- [Contacto](#-contacto)  

---

## 🌟 Características  

Usuario 
ROLE_ADMIN: Kawakami@gmail.com<br>
contraseña: 123456Kawakami

### 🛒 **E-commerce de Suplementos**  
- **CRUD de productos** con filtros avanzados (sabor, marca, precio, más vendidos).  
- **Sistema de ofertas** con descuentos personalizables (razón y porcentaje).  
- **Integración con Mercado Pago** para transacciones seguras.  
- **Subida de imágenes** mediante Cloudinary.  
- **Notificaciones por email** con JavaMailSender post-compra.  

### 👥 **Gestión de Usuarios**  
- **Roles personalizados**: Usuario, Personal Trainer, Administrador.  
- **CRUD de perfiles** con carga de imágenes de usuario.  

### 📅 **Reservas con Personal Trainers**  
- Selección de trainers y horarios disponibles.  
- Gestión de disponibilidad por parte de administradores.  

### 💪 **Planes de Gimnasio Personalizables**  
- Flexibilidad en duración (mensual, trimestral, anual o personalizada).  
- Aplicación de descuentos a planes.  

### 📊 **Dashboard Administrativo**  
- Visualización de facturas y estadísticas en tiempo real:  
  - Ganancias totales.  
  - Productos y planes más populares.  

### 🔐 **Interfaz Segura**  
- Rutas públicas/privadas según rol del usuario.  
- Autenticación JWT con Spring Security.  

---

## 🎥 Demo  
![Dashboard Administrativo](https://via.placeholder.com/600x400)  
**Enlace a Demo**: [demo.gympro.com](https://...) *(próximamente)*  

---

## 🛠️ Tecnologías  
### **Frontend**  
![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-646CFF?logo=vite&logoColor=white)
![React Router](https://img.shields.io/badge/React_Router-CA4245?logo=reactrouter&logoColor=white)

**Core:**
- React 18 + Vite 5 (TypeScript)
- Gestión de estado con Redux Toolkit 2.2
- Enrutamiento con React Router 6.26

**UI/Componentes:**
- Material UI 6.2 + X Date Pickers 7.23
- FontAwesome 6.6 (iconos)
- Swiper 11.2 (carruseles interactivos)
- React Big Calendar 1.16 (gestión horarios)

**Formularios y Validación:**
- Formik 2.4 + Yup 1.4
- Validación de esquemas avanzada

**Utilidades:**
- Axios 1.7 (peticiones HTTP)
- SweetAlert2 11.14 (notificaciones)
- date-fns 2.29 (manejo de fechas)

**Dev Tools:**
- ESLint 9.11 + Typescript 5.5
- Hot Module Replacement (HMR)
- Build optimizado con Vite

### **Backend**  
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3.4-6DB33F?logo=springboot&logoColor=white)
![Java](https://img.shields.io/badge/Java-23-ED8B00?logo=openjdk&logoColor=white)
![Spring Security](https://img.shields.io/badge/Spring_Security-6DB33F?logo=springsecurity&logoColor=white)

**Core:**
- Spring Boot 3.3.4 + Java 23
- Spring Data JPA (Hibernate)
- Validación de datos con Bean Validation
- Hot reload con Spring DevTools

**Seguridad:**
- Autenticación JWT (jjwt 0.11.2)
- Spring Security 6.1
- CORS configurado
- Protección CSRF

**Integraciones:**
- Cloudinary SDK 2.0 (gestión de imágenes)
- Mercado Pago SDK 2.1.29 (pasarela de pagos)
- Spring Mail (notificaciones email)
- MySQL Connector/J 8.0

**Herramientas:**
- Configuración con dotenv-java 2.2.4
- Monitorización con Spring Actuator
- Testing con Spring Boot Test
- Build con Maven Wrapper

**Patrones:**
- Arquitectura RESTful
- Inyección de dependencias
- Transacciones ACID
- DTOs para transferencia de datos

### **Integraciones**  
![Mercado Pago](https://img.shields.io/badge/Mercado_Pago-00B1EA?logo=mercadopago&logoColor=white)  
![Cloudinary](https://img.shields.io/badge/Cloudinary-3448C5?logo=cloudinary&logoColor=white)  
![Spring Mail](https://img.shields.io/badge/Spring_Mail-6DB33F?logo=spring&logoColor=white)  

# ⚙️ Instalación  
1. Clona el repositorio:  
   ```bash
   git clone https://github.com/Sobocles/GymApp.git
   ```
2. Construir proyecto y descargar dependencias:
  ```bash
    mvn clean install -DskipTest
  ```

3. Ejecutar la aplicación Spring Boot:
  ```bash
   mvn spring-boot:run -Dspring-boot.run.profiles=dev
  ```
El servidor API se iniciará en:
  ```bash 
   http://localhost:8080 
  ```
Configuración de Ngrok (Para desarrollo local)

Descargar e instalar ngrok https://download.ngrok.com/downloads/windows

Autenticar: ./ngrok config add-authtoken <TU_TOKEN>

 Exponer el puerto del backend: 
   ```bash 
 ./ngrok http 8080
  ```

 Actualizar application.properties con la URL HTTPS generada: 
 mercadopago.base-url=https://{subdominio-ngrok}.ngrok-free.app

Variables de Entorno Clave

Crear archivo .env en el backend con:
  ```bash
    CLOUDINARY_URL=cloudinary://api_key:api_secret@cloud_name
    MP_ACCESS_TOKEN=TEST-XXXXXXXXXXXXXXXX
    SPRING_DATASOURCE_URL=jdbc:mysql://localhost:3306/gympro_db
  ```
Para poder realizar una transaccion con mercado pago, se pueden user credenciales de prueba en: https://www.mercadopago.cl/developers/es/docs/your-integrations/test/cards <br>

Por ejemplo:<br>
numero de targeta: 4023 6535 2391 4373<br>
codigo de seguridad: 123<br>
Fecha de caducidad: 11/30<br>
estado de pago: APRO<br>
Documento de identidad: 123456789<br>

