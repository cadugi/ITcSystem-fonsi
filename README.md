# ITcSystem-fonsi

Repositorio que centraliza scripts de soporte técnico para mis clientes.

## Herramienta principal: `diagnostics.ps1`

Script de PowerShell pensado para Windows 10/11 y Windows Server 2012 o superior. Reúne los chequeos más habituales de soporte:

- Salud general de la red (interfaces, DHCP, DNS, latencias, puertos comunes, etc.).
- Estado de la VPN y del antivirus WatchGuard EPDR.
- Servicios críticos de Windows, perfiles de usuario y certificados locales.
- Salud básica de Outlook/Exchange, impresoras, spooler y espacio en disco.
- Controles específicos de dominio/Active Directory tanto desde el lado cliente como servidor.
- Verificaciones de servidores (DNS, replicación, Hyper-V, RAID, copias de seguridad, puertos internos y eventos críticos).

El script genera dos menús (Cliente y Servidor) que pueden ejecutarse tanto desde consola como desde una interfaz gráfica basada en Windows Forms.

### Requisitos

- PowerShell 5.1 o superior.
- Permisos de administrador (el script se relanza automáticamente si son necesarios).
- Módulos/roles estándar de Windows (no requiere dependencias externas).

### Uso básico

```powershell
# Abrir con GUI (por defecto)
PowerShell -ExecutionPolicy Bypass -File .\diagnostics.ps1

# Forzar modo consola (útil en Server Core)
PowerShell -ExecutionPolicy Bypass -File .\diagnostics.ps1 -NoGui

# Ejecutar sin relanzar como administrador (solo si ya se abrió una consola elevada)
PowerShell -ExecutionPolicy Bypass -File .\diagnostics.ps1 -SkipAdminCheck

# Ejecutar comprobaciones concretas sin menús (automatizaciones)
PowerShell -ExecutionPolicy Bypass -File .\diagnostics.ps1 -RunClientChecks 'VPN WatchGuard','Red / Conectividad'
PowerShell -ExecutionPolicy Bypass -File .\diagnostics.ps1 -RunServerChecks '*'
```

La salida de cada comprobación se muestra en pantalla y también se registra en `diagnostics.log` dentro de la misma carpeta del script. Cada entrada del log incluye marca de tiempo, nivel (INFO/ADVERTENCIA/ERROR) y los detalles completos devueltos por el chequeo (latencias, IPs resueltas, servicios caídos, etc.) para que puedas explicar al cliente o al técnico exactamente qué está ocurriendo.

Cuando se utilizan los parámetros `-RunClientChecks` o `-RunServerChecks` el script ejecuta directamente las pruebas indicadas, imprime los resultados en consola y finaliza sin mostrar los menús. Puedes pasar el nombre exacto de cada check (tal y como aparece en la interfaz) o utilizar `'*'` para forzar la ejecución de todos los chequeos de ese bloque.

### Personalización rápida

Todas las constantes utilizadas por los chequeos (puerta de enlace, nombre del DC, puertos a sondear, servicios críticos, IPs de impresoras, etc.) se almacenan en la tabla `$DiagnosticConfig` al inicio del script. Puedes adaptar estas claves según tu entorno:

- `PrinterIPs`: agrega IPs de impresoras estáticas para que se verifique la conectividad.
- `BackupServices`: lista de servicios de copia de seguridad que deben estar en ejecución (Veeam, Cobian, etc.).
- `HyperVServices`: servicios a vigilar cuando el servidor usa Hyper-V.
- `CriticalClientServices` y `CriticalServerServices`: servicios esenciales que deben estar iniciados.
- `ExchangeDomain`: host objetivo que se usa para comprobar Autodiscover.

Actualiza estas entradas antes de distribuir el script para cada cliente y guarda la versión personalizada en tu gestor de configuraciones si es necesario.

### Notas

- El script intenta detectar automáticamente la puerta de enlace, controladores de dominio, servidores DNS y ficheros de log, pero siempre es recomendable revisar los valores detectados en la parte superior de `$DiagnosticConfig`.
- En entornos sin interfaz gráfica disponible, se utilizará automáticamente el menú de consola.
- Algunas comprobaciones opcionales (por ejemplo, `repadmin`, `dcdiag`, estado del RAID mediante WMI) solo devolverán resultados cuando las herramientas correspondientes estén instaladas en el servidor.
