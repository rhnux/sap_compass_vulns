# SAP CVE Data Updater - Guía de Uso

## Descripción
Script mejorado para actualizar datos de CVEs de SAP usando SploitScan y CVE_Prioritizer. Procesa todos los CVE-IDs del archivo existente y genera un CSV actualizado con la misma estructura.

## Características

### ✨ Mejoras Principales
- **Procesamiento por lotes**: Divide CVEs en lotes para no saturar APIs
- **Concurrencia controlada**: Usa threads con límite configurable
- **Sistema de checkpoint**: Puede reanudar desde donde quedó si se interrumpe
- **Rate limiting**: Respeta límites de API con delays configurables
- **Logging detallado**: Registra todo el proceso con timestamps
- **Manejo de errores robusto**: Captura y registra fallos sin detener el proceso
- **Salida compatible**: Mantiene estructura del CSV original

### 🔧 Configuración Avanzada

#### Variables de Configuración (en el script)
```python
BATCH_SIZE = 10              # CVEs por lote
MAX_WORKERS = 3              # Threads concurrentes
DELAY_BETWEEN_BATCHES = 5    # Segundos entre lotes
DELAY_BETWEEN_REQUESTS = 2   # Segundos entre requests
CHECKPOINT_INTERVAL = 20     # Guardar progreso cada N CVEs
```

#### Variables de Entorno Necesarias

Crear archivo `.env` en el directorio del proyecto:

```bash
# APIs opcionales pero recomendadas
NIST_API=tu_api_key_aqui
VULNCHECK_API=tu_api_key_aqui
OPENAI_API=tu_api_key_aqui  # Opcional para SploitScan

# Para SploitScan: crear config.json
# Ver: https://github.com/xaitax/SploitScan#configuration
```

## Instalación

### 1. Requisitos
```bash
# Python 3.8+
python3 --version

# Instalar dependencias
pip install sploitscan cve-prioritizer
```

### 2. Configurar APIs (Recomendado)

#### NIST NVD API
```bash
# Solicitar en: https://nvd.nist.gov/developers/request-an-api-key
# Configurar CVE_Prioritizer:
cve_prioritizer -sa
# Ingresar NIST API key cuando solicite
```

#### VulnCheck API (Más rápido)
```bash
# Registrarse en: https://vulncheck.com/
# Configurar:
cve_prioritizer -sa
# Ingresar VulnCheck API key
```

#### OpenAI (Opcional - para análisis AI)
```bash
# Crear config.json para SploitScan
mkdir -p ~/.sploitscan
cat > ~/.sploitscan/config.json << 'EOF'
{
  "OPENAI_API_KEY": "tu_openai_api_key",
  "VULNCHECK_API_KEY": "tu_vulncheck_api_key"
}
EOF
```

### 3. Estructura de Archivos
```
project/
├── sap_cve_updater.py          # Script principal
├── sap_cve_last_01.csv         # CSV original
├── .env                        # Variables de entorno
├── output/
│   ├── sap_cve_updated.csv    # CSV actualizado
│   ├── update_log.txt         # Log de ejecución
│   └── checkpoint.json        # Estado de progreso
```

## Uso

### Uso Básico
```bash
# Procesar CSV por defecto
python sap_cve_updater.py

# Con archivo específico
python sap_cve_updater.py -i data/sap_cve_last_01.csv -o output/updated.csv
```

### Opciones Avanzadas
```bash
# Ayuda
python sap_cve_updater.py --help

# Especificar todos los archivos
python sap_cve_updater.py \
  --input sap_cve_last_01.csv \
  --output sap_cve_updated.csv \
  --log logs/update.log \
  --checkpoint checkpoints/state.json

# Omitir verificación de dependencias
python sap_cve_updater.py --skip-check
```

### Reanudar Ejecución Interrumpida
```bash
# El script automáticamente carga el checkpoint y continúa
python sap_cve_updater.py

# Para empezar desde cero, eliminar checkpoint
rm checkpoint.json
python sap_cve_updater.py
```

## Campos del CSV Actualizado

### Campos Originales (preservados)
- CVE_ID
- CVSS_Score
- CVSS_Vector
- Description
- References
- ... (todos los campos originales)

### Campos Nuevos/Actualizados
- **EPSS_Score**: Probabilidad de explotación (0-1)
- **EPSS_Percentile**: Percentil EPSS
- **Priority**: A+, A, B, C, D (según CVSS+EPSS+KEV)
- **Public_Exploits**: Yes/No
- **Exploit_Count**: Número de exploits públicos
- **CISA_KEV**: Yes/No (Known Exploited Vulnerability)
- **Last_Updated**: Fecha de actualización (YYYY-MM-DD)

## Gestión de Rate Limits

### Sin API Keys (Límites Públicos)
```
NVD: 5 requests/30s = ~600 requests/hora
Delay entre requests: 6s (automático)
Tiempo estimado para 1000 CVEs: ~3.3 horas
```

### Con NIST API Key
```
NVD: 50 requests/30s = ~6000 requests/hora
Delay entre requests: 1s
Tiempo estimado para 1000 CVEs: ~20 minutos
```

### Con VulnCheck API (Recomendado)
```
VulnCheck: ~240 requests/minuto
Delay entre requests: 0.25s
Tiempo estimado para 1000 CVEs: ~8 minutos
```

## Monitoreo y Logs

### Salida en Consola
```
2024-01-15 10:30:45 - INFO - =====================================
2024-01-15 10:30:45 - INFO - Iniciando actualización de datos SAP CVE
2024-01-15 10:30:45 - INFO - =====================================
2024-01-15 10:30:45 - INFO - CVEs a procesar: 150 de 150 totales
2024-01-15 10:30:46 - INFO - ====================================
2024-01-15 10:30:46 - INFO - Procesando lote 1/15 (10 CVEs)
2024-01-15 10:30:46 - INFO - ====================================
2024-01-15 10:30:47 - INFO - Procesando CVE-2024-1234...
2024-01-15 10:30:52 - INFO - ✓ CVE-2024-1234 procesado exitosamente
```

### Archivo de Log
Contiene información detallada incluyendo:
- Timestamp de cada operación
- CVEs procesados/fallidos
- Errores específicos
- Estadísticas de tiempo

### Checkpoint
```json
{
  "processed": ["CVE-2024-1234", "CVE-2024-5678", ...],
  "timestamp": "2024-01-15T10:30:45.123456"
}
```

## Manejo de Errores

### Errores Comunes

#### 1. Herramientas no instaladas
```
ERROR: Herramientas no encontradas: sploitscan, cve_prioritizer

Solución:
pip install sploitscan cve-prioritizer
```

#### 2. Timeout de API
```
WARNING: Timeout en SploitScan para CVE-2024-1234

Causa: API lenta o no responde
Acción: El script continúa, se marca como fallido
```

#### 3. Rate Limit Exceeded
```
ERROR: Rate limit exceeded

Solución: 
- Aumentar DELAY_BETWEEN_REQUESTS
- Reducir MAX_WORKERS
- Configurar API keys
```

#### 4. API Key inválida
```
ERROR: VulnCheck requires an API key

Solución:
cve_prioritizer -sa
# Ingresar API key válida
```

## Optimización de Rendimiento

### Para Procesamiento Rápido (con APIs configuradas)
```python
BATCH_SIZE = 20
MAX_WORKERS = 5
DELAY_BETWEEN_BATCHES = 2
DELAY_BETWEEN_REQUESTS = 0.5
```

### Para Modo Conservador (sin APIs)
```python
BATCH_SIZE = 5
MAX_WORKERS = 2
DELAY_BETWEEN_BATCHES = 10
DELAY_BETWEEN_REQUESTS = 6
```

### Para Datasets Grandes (>1000 CVEs)
```python
BATCH_SIZE = 50
MAX_WORKERS = 8
CHECKPOINT_INTERVAL = 50
DELAY_BETWEEN_REQUESTS = 0.25  # Solo con VulnCheck
```

## Comparación con Script Original

### Mejoras vs sap_security_automation.py

| Característica | Script Original | Nuevo Script |
|----------------|-----------------|--------------|
| Procesamiento | Secuencial | Por lotes + threads |
| Checkpoint | No | Sí |
| Rate limiting | Básico | Avanzado y configurable |
| Manejo errores | Detiene ejecución | Continúa y registra |
| Logging | Básico | Detallado con timestamps |
| Reanudar | No | Sí |
| APIs soportadas | Limitadas | SploitScan + CVE_Prioritizer |
| CSV output | Nueva estructura | Mantiene estructura |

## Troubleshooting

### Script muy lento
1. Verificar que APIs estén configuradas
2. Revisar logs para identificar bottlenecks
3. Ajustar parámetros de concurrencia
4. Verificar conexión a internet

### Muchos CVEs fallan
1. Verificar formato de CVE-IDs en CSV
2. Revisar logs para errores específicos
3. Verificar que herramientas estén actualizadas:
   ```bash
   pip install --upgrade sploitscan cve-prioritizer
   ```

### Checkpoint no se carga
1. Verificar que archivo checkpoint.json exista
2. Verificar permisos de lectura
3. Revisar formato JSON (debe ser válido)

## Contribución y Personalización

### Agregar Nuevas Fuentes de Datos
```python
def run_custom_tool(self, cve_id):
    """Agrega tu propia herramienta aquí"""
    # Tu código
    pass

# En merge_data():
custom_data = self.run_custom_tool(cve_id)
if custom_data:
    # Procesar datos
    pass
```

### Modificar Campos de Salida
Editar `merge_data()` para incluir/excluir campos según necesidad.

## Recursos Adicionales

- [SploitScan GitHub](https://github.com/xaitax/SploitScan)
- [CVE_Prioritizer GitHub](https://github.com/TURROKS/CVE_Prioritizer)
- [NIST NVD API](https://nvd.nist.gov/developers)
- [VulnCheck](https://vulncheck.com/)
- [EPSS](https://www.first.org/epss/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Licencia
Script basado en herramientas open source. Respetar licencias de SploitScan (GPL) y CVE_Prioritizer (BSD).

## Soporte
Para issues relacionados con:
- **Este script**: Revisar logs y documentación
- **SploitScan**: https://github.com/xaitax/SploitScan/issues
- **CVE_Prioritizer**: https://github.com/TURROKS/CVE_Prioritizer/issues
