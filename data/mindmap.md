# Vulnerabilidades SAP y Priorización

## 1. Panorama General de Vulnerabilidades SAP (2021-2024)
*   **Reporte Total (hasta 14-Dic-2024):**
    *   578 Notas de Seguridad SAP [1]
    *   546 CVE-IDs relacionados [1]
    *   (Nota anterior mencionaba 560 Notas / 529 CVEs hasta 14-Oct-2024) [2]
    *   Dataset de análisis: 641 filas hasta Sep-2024 [3, 4]
*   **Tendencias Anuales [5, 6]:**
    *   Total CVEs: Pico en 2023 (162), 2024 (130 hasta fecha de análisis) [5, 6]
    *   Vulnerabilidades Críticas: Pico en 2022 y 2023 (20), Descenso en 2024 (8) [5, 6]
    *   CVSS Promedio: Más alto en 2022 (6.92), Más bajo en 2024 (5.84) [5, 6]
    *   EPSS Promedio: Alto en 2022 (9.18), Muy bajo en 2023 (0.11) [5, 6]
*   **Distribución de Severidad [6-11]:**
    *   **Media (Medium): Dominan consistentemente todos los años** [6-13]
    *   Considerable presencia de Alta (High) y Hot News [8, 9]
    *   Ligero aumento en vulnerabilidades bajas (Low) en años recientes [6, 7]
*   **Tipos Comunes (CWE) [14-16]:**
    1.  **CWE-79: Cross-Site Scripting (XSS)** (Rank 2 en CWE Top 25 2023) [14-16]
    2.  **CWE-862: Missing Authorization** (Rank 11 en CWE Top 25 2023) [14-16]
    3.  CWE-200: Information Disclosure [14-16]
    *   Otros notables en 2024: CWE-918 (SSRF), Vulnerabilidades de Carga de Archivos [17, 18]
*   **Productos Más Vulnerables [10, 19-21]:**
    *   **Consistentemente:**
        1.  SAP NetWeaver Application Server ABAP [10, 19-21]
        2.  SAP NetWeaver Application Server Java [10, 19-21]
    *   Otros frecuentes: SAP BusinessObjects Business Intelligence Platform, SAP Business One, SAP 3D Visual Enterprise Viewer, SAP NetWeaver Enterprise Portal [22, 23]

## 2. Desafíos y Motivación
*   Las empresas no priorizan SAP en la gestión de vulnerabilidades, requiere coordinación compleja [24].
*   Necesidad de integrar SAP en la gestión de seguridad (S-SDLC, ASPM) [25].
*   **Solución prometedora: Cultura DevSecOps** [25].
*   Objetivo: Incorporar % EPSS, referenciar CWE, análisis/monitoreo continuo [25].

## 3. Metodología de Análisis y Priorización
*   **Pasos [26]:**
    1.  Recopilación de CVE-IDs (SAP Security Patch Day) [26, 27]
    2.  Procesamiento con herramientas (CVE_Prioritizer, SploitScan) [26, 27]
    3.  Creación de dataset (641 filas, 24 columnas, datos hasta Sep-2024) [3, 4, 26, 28, 29]
    4.  Filtrado por prioridad/criticidad [26]
    5.  Verificación KEV (Known Exploited Vulnerabilities Catalog) [26, 30]
    6.  Desarrollo de modelo automatizado [26]
*   **Dataset:** Valores EPSS promedio bajos (0.03) [23, 31, 32]. Scores CVSS SAP y Sploitscan tienen diferencias, pero promedios/std similares [9, 33, 34].

## 4. Herramientas de Priorización (CVE_Prioritizer y SploitScan)
*   Asignan prioridad basadas en **EPSS, CVSS y KEV** [35].
*   **CVE_Prioritizer:** Valores Priority (1+, 1, 2, 3, 4) [35].
    *   Mayoría: Priority 2 (62.25%), Priority 4 (33.54%) [35].
    *   Priority 1+ es KEV [35].
    *   Sesgo en clasificación (pocas 1 y 3) [36, 37]. Ajustar thresholds (EPSS 0.2, CVSS 6.0) [36].
*   **SploitScan:** Valores (A+, A, B, C, D) [36].
    *   Mayoría: D (64.59%), B (29.64%) [36].
    *   A+ es KEV o exploits públicos [38].
    *   A-D basado en matriz CVSS/EPSS [38].
    *   Sesgo en clasificación (pocas A y C) [37, 38].
*   Ambas herramientas asignan máxima prioridad (1+ | A+) a los mismos KEVs en promedio [8].
*   Recomendable usar ambas y comparar [8].

## 5. Modelo Avanzado de Priorización ("Rethink Priority Score")
*   Propuesta para mejorar evaluación de riesgos [39].
*   Utiliza **puntuación compuesta (composite_score)** [39].
*   **Componentes y Pesos [40]:**
    *   KEV: Peso 3 (si True)
    *   CVSS Score: Peso 2 (multiplicado por score)
    *   EPSS Score: Peso 2 (multiplicado por promedio EPSS, ajustado por tendencia: Up*3, Down*1, Stable*2) [40]
    *   CWE Top 25: Peso 1.5 (si pertenece) [40]
    *   Priority Level (Placeholder): Peso 1 [40]
*   **Ranking:** Basado en puntuación compuesta [41].
*   **Ejemplo Principal:** CVE-2022-22965 rankea alto por CVSS (9.8), KEV, EPSS alto (97.48%), CWE Top 25 [41, 42].
*   Otras críticas con alto score compuesto: CVE-2021-44832 (23.178), CVE-2020-11023 (22.304) - alto CVSS, KEV, alto EPSS, CWE Top 25 [39, 43].
*   **Impacto del Modelo:** Reasigna prioridades más altas al **25% de las vulnerabilidades SAP Medium** [12, 37]. Selecciona 24 CVEs únicos de 358 Medium reportadas, incluyendo 3 en KEV y 14 en CWE Top 25 [12]. Selecciona 145 CVEs únicos de 578 totales, incluyendo 12 en KEV y 97 en CWE Top 25 [44].

## 6. Validación del Modelo
*   Medir eficiencia con métricas [45].
*   **Métricas Clave [46, 47]:**
    *   **Precision at the Top:** CVEs de mayor prioridad del modelo vs explotados en la práctica [46, 47].
    *   **Exploit Prediction Accuracy:** Qué tan bien predice la explotación [47, 48].
    *   **Correlation with EPSS Score:** Alinear ranking con EPSS [47, 48].
    *   **Mean Time to Patch (MTTP):** Reducción en tiempo de remediación [47, 49].
    *   Incident Rate Reduction: Reducción de incidentes por CVEs [50].
    *   False Positive/Negative Rate [47, 50].
    *   User Satisfaction Score (Feedback de equipos) [47, 51].
    *   A/B Testing (Comparar con otros métodos) [47, 52].
    *   Model Throughput (Velocidad de procesamiento) [47, 53].
    *   Incident Correlation Score (Resaltar CVEs que causaron incidentes) [47, 53].

## 7. Ejemplos de Vulnerabilidades Específicas
*   **CVE-2021-42063:** XSS en SAP Knowledge Warehouse [54]. CVSS 6.1 (Medium) [55]. EPSS 0.38% (baja prob. de explotación) [55]. Impacto: Exposición de datos, secuestro de sesión [54, 55]. Mitigación: Parches (Nota 3102769) [56].
*   **CVE-2022-22536:** HTTP Request Smuggling en SAP NetWeaver AS (ICM, Web Dispatcher) [57-60]. **CVSS 9.8 (Critical)** [57-60], (otro reporte dice 10.0 [61]). Impacto: Alto en Confidencialidad, Integridad, Disponibilidad [57-60]. Riesgos: Acceso no autorizado, secuestro de sesión, DoS [57-60]. Permite RCE, PE, DoS, Exfiltración [62]. MITRE ATT&CK: T1071.001 (Web Protocols), T1190 (Exploit Public-Facing Application), etc. [63]. Mitigación: **Aplicar parches inmediatamente**, mejorar monitoreo/defensas [61, 64, 65].

## 8. Recomendaciones Estratégicas
*   Priorizar evaluaciones de seguridad en ecosistema SAP, Apache, jQuery [66].
*   Implementar mecanismos de autorización robustos [66].
*   Enfocarse en mitigar riesgos de XSS y divulgación de información [66].
*   Desarrollar estrategias integrales de gestión de parches [66].
*   Monitorear continuamente tendencias [66].
*   **Acción inmediata** en vulnerabilidades críticas por modelo, plan escalonado para alta prioridad [67].
*   Prevenir vulnerabilidades comunes (XSS, auth/autenticación) y capacitar al equipo de desarrollo [67].

## 9. Próximos Pasos Considerados
*   Agregar modelo **SSVC** (Stakeholder-Specific Vulnerability Categorization) para clasificar según contexto/scope organizacional [68].
*   Desarrollo de **DevSecOps Pipelines para SAP** (Git & Abap) [68].

## 10. Limitaciones
*   Dataset es una instantánea, algunas vulns pueden no ser reportadas [44, 66].
*   El riesgo real depende de la implementación y contexto específico [44, 66].
