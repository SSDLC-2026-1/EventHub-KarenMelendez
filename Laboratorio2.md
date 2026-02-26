# Lab2 - Secure Coding Practices for Cryptography and Session Management
## Universidad del Rosario - 2026 – 1

## Sección Teórica 
El objetivo de esta sección es evaluar la comprensión precisa de los conceptos teóricos cubiertos en clase. Las preguntas son de opción múltiple y siguen el modelo de examen del Certified Application Security Engineer y de DevSecOps Essentials.

1. **¿Cuál de los siguientes no es un tipo de autorización?**
   - [ ] a) Managed Access Control  
   - [ ] b) Mandatory Access Control  
   - [ ] c) Discretionary Access Control  
   - [ ] d) Role Based Access Control  

2. **¿Qué mecanismo de seguridad implementarías para restringir el acceso de los usuarios a recursos específicos dentro de una aplicación?**
   - [ ] a) Autenticación  
   - [ ] b) Autorización  
   - [ ] c) Delegación  
   - [ ] d) Impersonación  

3. **Según las prácticas de autenticación y autorización segura en el desarrollo de aplicaciones, ¿con qué tipo de privilegios no se debe ejecutar una aplicación?**
   - [ ] a) Privilegios de cuenta de administrador  
   - [ ] b) Privilegios de cuenta de usuario  
   - [ ] c) Privilegios de cuenta de invitado  
   - [ ] d) Privilegios de cuenta normal  

4. **¿Cuál de las siguientes técnicas de seguridad implica el proceso de convertir datos potencialmente peligrosos en formatos seguros que se pueden mostrar o almacenar de forma segura?**
   - [ ] a) Input Validation  
   - [ ] b) Encryption and Hashing  
   - [ ] c) Output Encoding  
   - [ ] d) Access Control  

5. **¿Cuál es el principio central de la práctica de seguridad "Secure by Default"?**
   - [ ] a) Los sistemas deben estar diseñados para fallar en un estado seguro.  
   - [ ] b) Diseñar la seguridad en los niveles físico, identidad y acceso, perímetro, red, cómputo, aplicación y datos.  
   - [ ] c) Requiere autenticación y autorización para cada acción.  
   - [ ] d) Los requisitos de seguridad deben definirse al inicio del proceso de desarrollo de la aplicación.  

## Sección Práctica 

En este laboratorio implementarán mecanismos reales de protección de
información dentro de la aplicación EventHub. El propósito no es
únicamente aplicar funciones criptográficas, sino comprender cuándo se
debe cifrar, cuándo se debe hashear y cómo deben gestionarse
correctamente las sesiones de usuario.

A lo largo de este ejercicio trabajarán sobre tres pilares fundamentales
de la seguridad en aplicaciones web:

-   Protección de credenciales
-   Protección de datos sensibles almacenados
-   Control del ciclo de vida de la sesión

El objetivo final es que la aplicación no almacene información sensible
en texto plano y que el acceso autenticado tenga una duración limitada y
controlada.

------------------------------------------------------------------------

## Actividades a implementar

### 1️⃣ Implementación del mecanismo de Logout

En caso de que no se haya implementado en el laboratorio anterior.

La aplicación debe permitir que el usuario finalice su sesión de manera
explícita. Al hacer logout:

-   Toda la información almacenada en la sesión debe eliminarse
    completamente. Pista: usar `session.clear()`
-   El usuario debe ser redirigido a la página principal o de login.
-   No debe quedar ningún dato residual en la sesión activa.
-   Debe existir un botón visible en la barra superior de la aplicación para que el usuario de click y se cierre su sesión.

------------------------------------------------------------------------

### 2️⃣ Protección de contraseñas mediante hashing con salt

La aplicación no debe almacenar contraseñas en texto plano. Deberán
modificar el flujo de registro, Utilizando la función `hash_password()` desarrollada en clase, para que:

-   Cada contraseña sea procesada mediante PBKDF2-HMAC-SHA256.
-   Se genere una salt aleatoria distinta para cada usuario.
-   Se almacenen:
    -   El algoritmo utilizado.
    -   El número de iteraciones.
    -   La salt generada.
    -   El hash derivado.

El flujo de login, con la función `verify_password()` desarrollada en clase, deberá:

-   Recuperar la salt almacenada.
-   Recalcular el hash con la contraseña ingresada.
-   Comparar utilizando comparación constante.

------------------------------------------------------------------------

### 3️⃣ Cifrado de datos sensibles almacenados

Deberán cifrar antes de almacenar, con la función `encrypt_aes()` desarrollada en clase:

-   El correo electrónico ingresado en el formulario de pago.
-   El número de teléfono ingresado en el formulario de registro.

Requisitos:

-   Usar AES en modo EAX.
-   Generar un nonce único por operación.
-   Guardar junto al dato cifrado:
    -   El nonce.
    -   El tag de autenticación.
-   **Utilizar una llave global.**

------------------------------------------------------------------------

### 4️⃣ Minimización de datos sensibles: no almacenar CVV

Aunque el formulario de pago incluya el campo CVV, este no debe
almacenarse en la base de datos bajo ninguna circunstancia.

**No debe:**

-   Guardarse en texto plano.
-   Guardarse cifrado.
-   Persistirse en ningún archivo.

------------------------------------------------------------------------

### 5️⃣ Ofuscación del número de tarjeta de crédito

El número completo de tarjeta de crédito no debe almacenarse en la base
de datos.

En su lugar:

-   Solo deberán almacenarse los últimos 4 dígitos.
-   El valor almacenado debe aparecer ofuscado, por ejemplo:

```{=html}
    **** **** **** 1234
```
-   No debe ser posible reconstruir el número original a partir del
    valor almacenado.

------------------------------------------------------------------------

### 6️⃣ Implementación de expiración de sesión (3 minutos)

La aplicación debe implementar un mecanismo de expiración automática de
sesión.

Una vez el usuario se autentique:

-   Debe almacenarse el momento exacto del login.
-   Cada vez que el usuario acceda a una ruta protegida debe verificarse
    el tiempo transcurrido.
-   Si han pasado más de 3 minutos (180 segundos), la sesión debe
    invalidarse automáticamente.
-   El usuario debe ser redirigido al formulario de login.


------------------------------------------------------------------------
## Rubrica de Evaluación



| Componente                             | Criterios evaluados                                                                                                                                          | Puntaje Máximo |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------- |
| **Sección Teórica**                    | Respuestas correctas en preguntas de opción múltiple. Evidencia comprensión de conceptos como autorización, secure by default, output encoding, privilegios mínimos y mecanismos de control de acceso.                                                   | **1.0**        |
| **Logout Seguro**                    | Implementación funcional de `/logout`. Uso de `session.clear()`. Redirección correcta. Botón visible en navbar. No quedan datos de sesión activos tras cerrar sesión.            | **0.5**        |
| **Hash + Salt en Registro/Login**             | Uso correcto de `hash_password()` y `verify_password()`. Salt distinta por usuario. No almacenamiento en texto plano. Comparación segura. Login funcional con verificación correcta.            | **1.2**        |
| **Cifrado AES de Email y Teléfono**         | Uso correcto de `encrypt_aes()`. Almacenamiento de nonce y tag. Uso de llave global. Datos sensibles no quedan visibles en texto plano en la base de datos. | **1.0**        |
| **Minimización de Datos (CVV + Tarjeta)** | CVV no almacenado bajo ninguna forma. Tarjeta almacenada únicamente con últimos 4 dígitos ofuscados. No es posible reconstruir el número original.                                                             | **0.8**        |
| **Expiración de Sesión (3 min)** | CVV no almacenado bajo ninguna forma. Tarjeta almacenada únicamente con últimos 4 dígitos ofuscados. No es posible reconstruir el número original.                                                             | **0.5**        |
| **Total**                              |                                                                                                                                                              | **5.0**        |



