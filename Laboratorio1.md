# Lab1 - Secure Coding Practices for Input Validation, Authentication and Authorization

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

---

## Sección Práctica
En esta sección deberán fortalecer la aplicación EventHub implementando controles de seguridad en tres frentes fundamentales del desarrollo seguro:

- Protección contra fuerza bruta (Account Lockout)
- Validación robusta de entradas
- Control de acceso basado en autenticación y roles

El propósito es que la aplicación no solo funcione correctamente, sino que incorpore principios reales de seguridad en backend y frontend.

### **Implementación de Seguridad en Autenticación y Autorización**


#### **1️⃣ Control de Intentos Fallidos en Autenticación**
En este ejercicio deberán implementar un mecanismo de bloqueo temporal de cuenta cuando se detecten múltiples intentos fallidos de autenticación. El objetivo es mitigar ataques de fuerza bruta y credential stuffing.

1. **Definir variables globales**: 
   - Definir variables para almacenar el número máximo de intentos permitidos.
   - Definir el tiempo de bloqueo (5 minutos por defecto).
   - Crear un diccionario para registrar el estado de los usuarios: `{ "usuario": { "intentos": 0, "tiempoBloqueo": 0 } }`

2. **Validar si el correo existe en la base de datos**:
   - Si el usuario existe y la contraseña es correcta, resetear su contador de intentos fallidos a cero.
   - Si la contraseña es incorrecta, incrementar el contador de intentos fallidos.

3. **Bloquear la cuenta si se exceden los intentos permitidos**:
   - Si se superan los 3 intentos fallidos, actualizar el `tiempoBloqueo` en el diccionario, estableciéndolo al tiempo de bloqueo.

4. **Verificar si la cuenta está bloqueada**:
   - Antes de procesar la autenticación, verificar si el usuario sigue en estado de bloqueo.
   - Si el tiempo de bloqueo no ha terminado, mostrar un mensaje informando cuánto tiempo queda hasta el desbloqueo.

#### **2️⃣ Implementación de Control de Acceso Basado en Roles (1pt)**
En este ejercicio deberán implementar control de acceso basado en autenticación y rol.

Se espera la creación de una función `require_login()` que restrinja el acceso a rutas protegidas cuando no exista una sesión activa. Además, deben implementar lógica de autorización basada en el rol del usuario.

1. **Las siguientes rutas deben protegerse:**

    - `/admin/users`: Debe ser accesible exclusivamente para usuarios con rol admin. Usuarios autenticados sin rol admin deben recibir un error 403 Forbidden.

    - `/checkout/<event_id>`: Debe ser accesible únicamente para usuarios autenticados (rol user o admin).

    - `/profile` y `/dashboard`: Deben ser accesibles únicamente para usuarios autenticados.

2. **Autorización en la Interfaz (Navbar Dinámico)**
Además de la protección en backend, deben implementar autorización visual en la interfaz mediante la modificación dinámica del navbar según el estado del usuario.
La lógica esperada es la siguiente:

    - Si el usuario no está autenticado:
        - Mostrar los botones Login y Register.

    - Si el usuario está autenticado:

        - Ocultar Login y Register.

        - Mostrar My Profile.

    - Si el usuario tiene rol admin:

        - Mostrar adicionalmente un enlace Admin Panel que redirija a /admin/users.


#### **3️⃣ Implementación Validación de Entradas (1pt)**
En este ejercicio deberán implementar validación robusta de entradas en los formularios críticos de la aplicación: registro, login y edición de perfil.

La validación debe basarse en principios de:

- Normalización de datos (por ejemplo, eliminación de espacios innecesarios).
- Whitelisting (permitir únicamente formatos y estructuras esperadas).
- Mensajes de error claros y específicos por campo.

No persistir información inválida en la base de datos.

1. **Registro**: El formulario de registro debe validar adecuadamente:

    - **Nombre completo:** longitud mínima de dos caracteres y una longitud máxima de sesenta caracteres. Solo se permiten letras (incluyendo caracteres acentuados), espacios, apóstrofes y guiones. No deben aceptarse números ni símbolos especiales distintos a los mencionados. Además, los espacios múltiples deben colapsarse en uno solo y deben eliminarse espacios al inicio y al final del texto.
    - **Correo electrónico:** debe tener una longitud máxima de 254 caracteres y cumplir un formato básico válido. Debe contener exactamente un símbolo @, una parte local antes del símbolo y un dominio después del mismo. El dominio debe incluir al menos un punto. El valor debe normalizarse a minúsculas antes de almacenarse. **No debe permitirse el registro de un correo electrónico que ya exista en la base de datos.**
    - **Número de teléfono:** debe permitir únicamente dígitos. No deben aceptarse letras ni otros caracteres especiales. La longitud total debe estar entre siete y quince dígitos. No deben almacenarse espacios internos.
    - **Contraseña:** debe tener una longitud mínima de ocho caracteres y una máxima de sesenta y cuatro. Debe contener al menos una letra mayúscula, una letra minúscula, un número y un carácter especial (por ejemplo:` ! @ # $ % ^ & * ( ) - _ = + [ ] { } < > ?`). No se deben permitir espacios en blanco. La contraseña no puede ser igual al correo electrónico del usuario. Además, el campo de confirmación de contraseña debe coincidir exactamente con la contraseña ingresada.

    - No debe permitirse la creación de usuarios con datos inválidos o inconsistentes.

2. **Login**: El proceso de autenticación debe:

    - Validar que los campos no estén vacíos.
    - Validar estructura mínima del correo antes de consultar la base de datos.
    - Mostrar un mensaje genérico ante credenciales inválidas.
    - No revelar si el error corresponde al correo o a la contraseña.

3. **Edición de perfil**: La vista de perfil debe validar:

    - Cambios en nombre y teléfono.
    - Cambio de contraseña, incluyendo:
        - Verificación de contraseña actual.
        - Validación de nueva contraseña.
        - Confirmación de coincidencia entre nueva contraseña y su verificación.
        - No deben persistirse cambios inválidos.

## Rubrica de Evaluación



| Componente                             | Criterios evaluados                                                                                                                                          | Puntaje Máximo |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------- |
| **Sección Teórica**                    | Comprensión clara de autenticación, autorización, validación y lockout. Respuestas correctas y coherentes.                                                   | **1.0**        |
| **Account Lockout**                    | Conteo de intentos fallidos, bloqueo tras límite definido, control de tiempo de bloqueo, reinicio tras login exitoso, comportamiento verificable.            | **1.0**        |
| **Validación de Entradas**             | Validación completa en registro, login y perfil. No persistencia de datos inválidos. Mensajes claros por campo. Validación ejecutada en backend.             | **1.5**        |
| **Protección de Rutas (RBAC)**         | Implementación de `require_login()`, restricción correcta de `/admin/users`, protección de `/checkout`, `/profile` y `/dashboard`, uso adecuado de HTTP 403. | **1.0**        |
| **Navbar Dinámico (UI Authorization)** | Mostrar/ocultar opciones según sesión y rol. Coherencia visual. No sustituye protección backend.                                                             | **0.5**        |
| **Total**                              |                                                                                                                                                              | **5.0**        |
