#!/usr/bin/env python3
"""
SAP CVE Updater - Setup and Environment Checker
Verifica y configura el entorno necesario para ejecutar el updater
"""

try:
    from rhnux_ansi import display_ansi_art
    display_ansi_art()
except ImportError:
    pass

import os
import sys
import subprocess
import json
from pathlib import Path


class EnvironmentChecker:
    def __init__(self):
        self.issues = []
        self.warnings = []
        self.info = []
        
    def print_header(self, text):
        print(f"\n{'='*70}")
        print(f"  {text}")
        print(f"{'='*70}")
    
    def print_status(self, status, message):
        symbols = {
            'ok': '✓',
            'warning': '⚠',
            'error': '✗',
            'info': 'ℹ'
        }
        colors = {
            'ok': '\033[92m',
            'warning': '\033[93m',
            'error': '\033[91m',
            'info': '\033[94m',
            'reset': '\033[0m'
        }
        
        symbol = symbols.get(status, '•')
        color = colors.get(status, '')
        reset = colors['reset']
        
        print(f"{color}{symbol} {message}{reset}")
    
    def check_python_version(self):
        """Verifica la versión de Python"""
        self.print_header("Verificando Python")
        
        version = sys.version_info
        if version.major == 3 and version.minor >= 8:
            self.print_status('ok', f"Python {version.major}.{version.minor}.{version.micro}")
        else:
            self.print_status('error', f"Python {version.major}.{version.minor}.{version.micro} - Se requiere 3.8+")
            self.issues.append("Python 3.8+ requerido")
    
    def check_tool_installed(self, tool_name, command=None):
        """Verifica si una herramienta está instalada"""
        if command is None:
            command = [tool_name, '--help']
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=5,
                text=True
            )
            return True, result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False, None
    
    def check_dependencies(self):
        """Verifica dependencias principales"""
        self.print_header("Verificando Dependencias")
        
        # SploitScan
        installed, output = self.check_tool_installed('sploitscan')
        if installed:
            # Extraer versión si es posible
            version = "instalado"
            if output and "version" in output.lower():
                for line in output.split('\n'):
                    if 'version' in line.lower():
                        version = line.strip()
                        break
            self.print_status('ok', f"SploitScan: {version}")
        else:
            self.print_status('error', "SploitScan: NO instalado")
            self.issues.append("Instalar: pip install sploitscan")
        
        # CVE_Prioritizer
        installed, output = self.check_tool_installed('cve_prioritizer')
        if not installed:
            installed, output = self.check_tool_installed('cve-prioritizer')
        
        if installed:
            self.print_status('ok', "CVE_Prioritizer: instalado")
        else:
            self.print_status('error', "CVE_Prioritizer: NO instalado")
            self.issues.append("Instalar: pip install cve-prioritizer")
    
    def check_api_keys(self):
        """Verifica configuración de API keys"""
        self.print_header("Verificando API Keys")
        
        # Variables de entorno
        env_keys = {
            'NIST_API': 'NIST NVD',
            'VULNCHECK_API': 'VulnCheck',
            'OPENAI_API_KEY': 'OpenAI'
        }
        
        has_any_key = False
        for env_var, service in env_keys.items():
            if os.getenv(env_var):
                self.print_status('ok', f"{service}: Configurada")
                has_any_key = True
            else:
                self.print_status('warning', f"{service}: NO configurada (opcional)")
        
        # Archivo .env
        if os.path.exists('.env'):
            self.print_status('ok', "Archivo .env encontrado")
        else:
            self.print_status('info', "Archivo .env no encontrado (opcional)")
        
        # Config de SploitScan
        sploitscan_configs = [
            Path.home() / '.sploitscan' / 'config.json',
            Path.home() / '.config' / 'sploitscan' / 'config.json',
            Path('config.json')
        ]
        
        config_found = False
        for config_path in sploitscan_configs:
            if config_path.exists():
                self.print_status('ok', f"Config SploitScan: {config_path}")
                config_found = True
                break
        
        if not config_found:
            self.print_status('info', "Config SploitScan: NO configurado (opcional)")
        
        # Config de CVE_Prioritizer
        if os.path.exists('.env') or has_any_key:
            self.print_status('info', "CVE_Prioritizer usará variables de entorno")
        else:
            self.print_status('warning', "CVE_Prioritizer sin API keys configuradas")
            self.warnings.append("Recomendado: Configurar API keys para mejor rendimiento")
            self.info.append("Ejecutar: cve_prioritizer -sa")
    
    def check_input_file(self):
        """Verifica archivo de entrada"""
        self.print_header("Verificando Archivos de Entrada")
        
        default_input = 'sap_cve_last_01.csv'
        if os.path.exists(default_input):
            self.print_status('ok', f"{default_input}: Encontrado")
            
            # Verificar formato básico
            try:
                with open(default_input, 'r') as f:
                    header = f.readline()
                    if 'CVE' in header:
                        self.print_status('ok', "Formato CSV válido")
                    else:
                        self.print_status('warning', "Encabezado CSV no contiene 'CVE'")
            except Exception as e:
                self.print_status('error', f"Error leyendo CSV: {e}")
        else:
            self.print_status('warning', f"{default_input}: NO encontrado")
            self.warnings.append(f"Especificar archivo con: -i <archivo.csv>")
    
    def check_output_directory(self):
        """Verifica directorio de salida"""
        self.print_header("Verificando Permisos de Escritura")
        
        test_file = '.write_test'
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            self.print_status('ok', "Permisos de escritura: OK")
        except Exception as e:
            self.print_status('error', f"No se puede escribir en directorio actual: {e}")
            self.issues.append("Verificar permisos del directorio")
    
    def estimate_performance(self):
        """Estima rendimiento según configuración"""
        self.print_header("Estimación de Rendimiento")
        
        has_nist = bool(os.getenv('NIST_API'))
        has_vulncheck = bool(os.getenv('VULNCHECK_API'))
        
        if has_vulncheck:
            self.print_status('ok', "Modo: RÁPIDO (VulnCheck API)")
            self.print_status('info', "~240 CVEs/minuto")
            self.print_status('info', "1000 CVEs: ~8 minutos")
        elif has_nist:
            self.print_status('ok', "Modo: NORMAL (NIST API)")
            self.print_status('info', "~100 CVEs/minuto")
            self.print_status('info', "1000 CVEs: ~20 minutos")
        else:
            self.print_status('warning', "Modo: LENTO (Sin API keys)")
            self.print_status('info', "~10 CVEs/minuto")
            self.print_status('info', "1000 CVEs: ~3 horas")
            self.warnings.append("Recomendado: Configurar API keys para mejor rendimiento")
    
    def print_summary(self):
        """Imprime resumen final"""
        self.print_header("RESUMEN")
        
        if not self.issues:
            self.print_status('ok', "✓ Sistema listo para ejecutar")
        else:
            self.print_status('error', f"✗ {len(self.issues)} problema(s) encontrado(s):")
            for issue in self.issues:
                print(f"    • {issue}")
        
        if self.warnings:
            print(f"\n⚠ {len(self.warnings)} advertencia(s):")
            for warning in self.warnings:
                print(f"    • {warning}")
        
        if self.info:
            print(f"\nℹ Información adicional:")
            for info in self.info:
                print(f"    • {info}")
        
        return len(self.issues) == 0
    
    def print_setup_guide(self):
        """Imprime guía de configuración"""
        self.print_header("GUÍA DE CONFIGURACIÓN RÁPIDA")
        
        print("""
1. Instalar herramientas:
   pip install sploitscan cve-prioritizer

2. Configurar API keys (RECOMENDADO):
   
   Opción A - VulnCheck (Más rápido):
   • Registrarse en: https://vulncheck.com/
   • Ejecutar: cve_prioritizer -sa
   • Ingresar VulnCheck API key
   
   Opción B - NIST NVD:
   • Solicitar en: https://nvd.nist.gov/developers/request-an-api-key
   • Ejecutar: cve_prioritizer -sa
   • Ingresar NIST API key
   
   Opción C - Archivo .env:
   • Crear archivo .env con:
     NIST_API=tu_api_key
     VULNCHECK_API=tu_api_key

3. Configurar SploitScan (OPCIONAL):
   mkdir -p ~/.sploitscan
   cat > ~/.sploitscan/config.json << 'EOF'
   {
     "OPENAI_API_KEY": "tu_openai_api_key",
     "VULNCHECK_API_KEY": "tu_vulncheck_api_key"
   }
   EOF

4. Ejecutar updater:
   python sap_cve_updater.py -i sap_cve_last_01.csv
""")
    
    def run(self):
        """Ejecuta todas las verificaciones"""
        print("\n" + "="*70)
        print("  SAP CVE UPDATER - VERIFICACIÓN DE ENTORNO")
        print("="*70)
        
        self.check_python_version()
        self.check_dependencies()
        self.check_api_keys()
        self.check_input_file()
        self.check_output_directory()
        self.estimate_performance()
        
        is_ready = self.print_summary()
        
        if not is_ready:
            self.print_setup_guide()
            return False
        
        return True


def create_sample_config():
    """Crea archivos de configuración de ejemplo"""
    print("\n" + "="*70)
    print("  CREAR CONFIGURACIÓN DE EJEMPLO")
    print("="*70)
    
    # .env
    env_content = """# API Keys para CVE_Prioritizer
NIST_API=your_nist_api_key_here
VULNCHECK_API=your_vulncheck_api_key_here

# Opcional: OpenAI para análisis AI
OPENAI_API_KEY=your_openai_api_key_here
"""
    
    if not os.path.exists('.env'):
        with open('.env.example', 'w') as f:
            f.write(env_content)
        print("✓ Creado: .env.example")
        print("  Renombrar a .env y agregar tus API keys")
    else:
        print("ℹ .env ya existe")
    
    # config.json para SploitScan
    config_dir = Path.home() / '.sploitscan'
    config_file = config_dir / 'config.json'
    
    if not config_file.exists():
        config_dir.mkdir(parents=True, exist_ok=True)
        config_content = {
            "OPENAI_API_KEY": "your_openai_api_key_here",
            "VULNCHECK_API_KEY": "your_vulncheck_api_key_here"
        }
        with open(config_file, 'w') as f:
            json.dump(config_content, f, indent=2)
        print(f"✓ Creado: {config_file}")
        print("  Editar y agregar tus API keys")
    else:
        print(f"ℹ {config_file} ya existe")
    
    print("\n✓ Archivos de ejemplo creados")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Verifica el entorno para SAP CVE Updater'
    )
    parser.add_argument(
        '--create-config',
        action='store_true',
        help='Crear archivos de configuración de ejemplo'
    )
    parser.add_argument(
        '--guide',
        action='store_true',
        help='Mostrar guía de configuración'
    )
    
    args = parser.parse_args()
    
    if args.create_config:
        create_sample_config()
        return
    
    checker = EnvironmentChecker()
    is_ready = checker.run()
    
    if args.guide or not is_ready:
        checker.print_setup_guide()
    
    sys.exit(0 if is_ready else 1)


if __name__ == '__main__':
    main()
