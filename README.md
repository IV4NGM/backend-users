# Backend de usuarios

Este es un backend para la administración de usuarios de un sistema. Contiene CRUD básico de usuarios, así como las siguientes funcionalidades:

- Al crear un usuario el sistema manda un correo electrónico solicitando confirmar el email registrado. Si no se verifica, no es posible realizar ninguna otra opción concerniente a este nuevo usuario.
- Existe una opción de volver a enviar el correo electrónico de verificación.
- Hay una opción para restablecer la contraseña en caso de que se haya olvidado. Para esto se envía un correo electrónico con las instrucciones a seguir, y posteriormente se manda un correo electrónico avisando que se han realizado estos cambios.
