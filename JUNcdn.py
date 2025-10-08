import re
import time
import getpass
import sys
import os
from datetime import datetime
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError, ConnectAuthError, ConnectTimeoutError, ConnectRefusedError
from jnpr.junos.utils.start_shell import StartShell
from typing import Dict, List, Tuple, Optional, Set
import ipaddress


# Встроенный список VRF (fallback если файл не найден)
DEFAULT_VRFS = [
    "ADGS_VKS.inet.0",
    "AFM.inet.0",
    "AFM_SPS.inet.0",
    "AIS_ROLP.inet.0",
    "ARRFR.inet.0",
    "ATS33-AKMT_M40.l2vpn.0",
    "Cloud_video_dp_RT.inet.0",
    "FINPOL.inet.0",
    "Gen_Prokuratura.inet.0",
    "KCMR_KAZYNA.inet.0",
    "KGIP.inet.0",
    "KMS.inet.0",
    "KNB.inet.0",
    "KNB_AS_9/12.inet.0",
    "KOM_STAT.inet.0",
    "KUIS.inet.0",
    "KUIS_Video.inet.0",
    "KUZR.inet.0",
    "KVGA.inet.0",
    "MINFIN.inet.0",
    "MNG_for_Zabbix.inet.0",
    "MNP.l2vpn.0",
    "MO_VSPD.inet.0",
    "MO_Video.inet.0",
    "MRCSV_VPN.inet.0",
    "MSH.inet.0",
    "MVD_Video.inet.0",
    "NIT_COD_INTERNAL.inet.0",
    "NSVM_KNB.l2vpn.0",
    "Nac_Gvardia_VPN.inet.0",
    "SALYK.inet.0",
    "SAT_MNG.inet.0",
    "SPS_KNB.inet.0",
    "Skud_and_Video.inet.0",
    "TELEMEDICINA.inet.0",
    "Translation.inet.0",
    "VERH_SUD.inet.0",
    "VIDEO_KPM2.inet.0",
    "VKS_CZSS_ALM.inet.0",
    "VKS_L3.inet.0",
    "VPLS_Internet_KTC.l2vpn.0",
    "VPLS_Video.l2vpn.0",
    "VPLS_for_KNB_Local.l2vpn.0",
    "VPN_MTK.inet.0",
    "VRF_DATA.inet.0",
    "VRF_DATA_Mobile.inet.0",
    "astel-czss.l2vpn.0",
    "beeline.l2vpn.0",
    "bgp.l2vpn.0",
    "bgp.l3vpn.0",
    "inet.0",
    "inet.3",
    "l2circuit.0",
    "mpls.0",
    "vpls-go-vpn-atc33.l2vpn.0",
    "vpls-internet-atc33.l2vpn.0",
    "vpls-majilis.l2vpn.0",
    "vpls_Asyltau-nit.l2vpn.0",
    "vpls_Satelite_KTK.l2vpn.0",
    "vpls_mchs-nit.l2vpn.0",
    "vpls_vpn-to-nit.l2vpn.0"
]


class VRFManager:
    """Управление списками VRF"""
    
    WINDOWS_INVALID_CHARS = '<>:"/\\|?*'
    
    @staticmethod
    def is_vrf_filename_safe(vrf: str) -> bool:
        """Проверить, безопасно ли имя VRF для создания файлов в Windows"""
        for char in VRFManager.WINDOWS_INVALID_CHARS:
            if char in vrf:
                return False
        return True
    
    @staticmethod
    def sanitize_vrf_for_filename(vrf: str) -> str:
        """Заменить недопустимые символы в имени VRF для создания файлов"""
        sanitized = vrf
        for char in VRFManager.WINDOWS_INVALID_CHARS:
            sanitized = sanitized.replace(char, '_')
        return sanitized
    
    @staticmethod
    def load_vrfs_from_file(filepath: str = "vrfs.txt") -> Optional[List[str]]:
        """Загрузить список VRF из файла"""
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                vrfs = []
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line and line not in vrfs:
                        vrfs.append(line)
                return vrfs if vrfs else None
        except Exception as e:
            print(f"[-] Ошибка чтения файла {filepath}: {e}")
            return None
    
    @staticmethod
    def save_vrfs_to_file(vrfs: List[str], filepath: str = "vrfs.txt"):
        """Сохранить список VRF в файл"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Список VRF для проверки (ПОЛНЫЕ названия с суффиксами)\n")
                f.write("# Каждый VRF на отдельной строке\n")
                f.write("# Строки начинающиеся с # игнорируются\n\n")
                for vrf in sorted(vrfs):
                    f.write(f"{vrf}\n")
            print(f"[+] Список VRF сохранен в {filepath}")
            return True
        except Exception as e:
            print(f"[-] Ошибка сохранения файла {filepath}: {e}")
            return False
    
    @staticmethod
    def get_vrf_list(vrf_file: Optional[str] = None) -> List[str]:
        """Получить список VRF"""
        if vrf_file:
            vrfs = VRFManager.load_vrfs_from_file(vrf_file)
            if vrfs:
                print(f"[+] Загружено {len(vrfs)} VRF из {vrf_file}")
                return vrfs
        
        vrfs = VRFManager.load_vrfs_from_file("vrfs.txt")
        if vrfs:
            print(f"[+] Загружено {len(vrfs)} VRF из vrfs.txt")
            return vrfs
        
        print(f"[*] Используется встроенный список VRF ({len(DEFAULT_VRFS)} шт)")
        return DEFAULT_VRFS.copy()


class CredentialManager:
    """Управление учетными данными для устройств"""
    
    def __init__(self):
        self.credentials: Dict[str, Dict[str, str]] = {}
        self.default_user = None
        self.default_password = None
        self.failed_hosts: Set[str] = set()
    
    def set_default(self, username: str, password: str):
        """Установить креды по умолчанию"""
        self.default_user = username
        self.default_password = password
    
    def get_credentials(self, host: str) -> Tuple[str, str]:
        """Получить креды для хоста"""
        if host in self.credentials:
            return self.credentials[host]['user'], self.credentials[host]['password']
        return self.default_user, self.default_password
    
    def add_credentials(self, host: str, username: str, password: str):
        """Добавить специфичные креды для хоста"""
        self.credentials[host] = {'user': username, 'password': password}
    
    def mark_host_failed(self, host: str):
        """Отметить хост как недоступный"""
        self.failed_hosts.add(host)
    
    def is_host_failed(self, host: str) -> bool:
        """Проверить, помечен ли хост как недоступный"""
        return host in self.failed_hosts
    
    def prompt_for_credentials(self, host: str) -> Optional[Tuple[str, str]]:
        """Запросить креды у пользователя"""
        print(f"\n[!] Требуется ручной ввод учетных данных для {host}")
        print("[!] Нажмите Enter без ввода для пропуска этого хоста")
        username = input(f"Username для {host}: ").strip()
        
        if not username:
            print(f"[*] Хост {host} будет пропущен")
            return None
        
        password = getpass.getpass(f"Password для {host}: ")
        self.add_credentials(host, username, password)
        return username, password


class RouteParser:
    """Парсер вывода команд Juniper"""
    
    @staticmethod
    def parse_route_output(output: str, target_prefix: str) -> List[Dict]:
        """
        Парсит вывод show route и возвращает информацию о найденных маршрутах
        ВАЖНО: Теперь проверяем активность маршрута (символ *)
        """
        results = []
        current_vrf = None
        current_prefix = None
        in_route_block = False
        next_hops = []
        protocol = None
        is_active = False  # НОВОЕ: флаг активного маршрута
        
        lines = output.split('\n')
        
        for i, line in enumerate(lines):
            # Определяем VRF/таблицу
            vrf_match = re.match(r'^([\w\-\.\/]+\.(inet|l2vpn|l3vpn)\.\d+):', line)
            if vrf_match:
                current_vrf = vrf_match.group(1)
                continue
            
            # Ищем префикс маршрута
            # ВАЖНО: Проверяем наличие * (активный маршрут)
            prefix_match = re.match(r'^(\d+\.\d+\.\d+\.\d+/\d+)\s+(\*?)\[([^\]]+)\]', line)
            if prefix_match:
                # Сохраняем предыдущий маршрут
                if current_prefix and next_hops:
                    results.append({
                        'vrf': current_vrf,
                        'prefix': current_prefix,
                        'protocol': protocol,
                        'next_hops': next_hops.copy(),
                        'is_active': is_active  # НОВОЕ
                    })
                
                current_prefix = prefix_match.group(1)
                is_active = (prefix_match.group(2) == '*')  # НОВОЕ: проверяем *
                protocol_info = prefix_match.group(3)
                protocol = protocol_info.split('/')[0]
                next_hops = []
                in_route_block = True
                
                # Проверяем next-hop в той же строке
                nexthop_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                if nexthop_match:
                    next_hops.append({
                        'type': 'device',
                        'address': nexthop_match.group(1)
                    })
                continue
            
            # Ищем next-hop в следующих строках
            if in_route_block:
                # Next-hop через устройство: "to X.X.X.X via interface"
                nexthop_match = re.search(r'>\s+to\s+(\d+\.\d+\.\d+\.\d+)\s+via\s+([\w\-\/\.]+)', line)
                if nexthop_match:
                    next_hops.append({
                        'type': 'interface',
                        'gateway': nexthop_match.group(1),
                        'interface': nexthop_match.group(2)
                    })
                    continue
                
                # Direct interface: "> via interface"
                direct_match = re.search(r'>\s+via\s+([\w\-\/\.]+)', line)
                if direct_match and not re.search(r'to\s+\d+\.\d+\.\d+\.\d+', line):
                    next_hops.append({
                        'type': 'direct',
                        'interface': direct_match.group(1)
                    })
                    continue
                
                # Если новая секция начинается
                if line.strip() and not line.startswith(' ') and not line.startswith('>'):
                    in_route_block = False
        
        # Сохраняем последний маршрут
        if current_prefix and next_hops:
            results.append({
                'vrf': current_vrf,
                'prefix': current_prefix,
                'protocol': protocol,
                'next_hops': next_hops.copy(),
                'is_active': is_active  # НОВОЕ
            })
        
        return results
    
    @staticmethod
    def find_matching_routes(parsed_routes: List[Dict], target_ip: str) -> List[Dict]:
        """
        Найти маршруты, которые покрывают целевой IP
        НОВОЕ: Фильтруем только АКТИВНЫЕ маршруты и сортируем по специфичности
        """
        try:
            target = ipaddress.ip_address(target_ip)
        except ValueError:
            return []
        
        matching = []
        for route in parsed_routes:
            # НОВОЕ: Берем только активные маршруты
            if not route.get('is_active', False):
                continue
                
            try:
                network = ipaddress.ip_network(route['prefix'], strict=False)
                if target in network:
                    matching.append(route)
            except ValueError:
                continue
        
        # Сортируем по длине префикса (более специфичные первые)
        matching.sort(key=lambda x: int(x['prefix'].split('/')[1]), reverse=True)
        return matching


class JuniperDevice:
    """Обертка для работы с устройством Juniper"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 22, timeout: int = 30):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.device: Optional[Device] = None
    
    def connect(self) -> bool:
        """Подключиться к устройству"""
        try:
            print(f"[*] Подключение к {self.host} (порт {self.port})...")
            
            self.device = Device(
                host=self.host,
                user=self.username,
                password=self.password,
                port=self.port,
                timeout=self.timeout,
                normalize=True,
                ssh_config=None,
                ssh_private_key_file=None,
                auto_probe=10,
                gather_facts=False
            )
            
            self.device.open()
            
            print(f"[+] Успешно подключились к {self.host}")
            print(f"[+] Устройство: {self.device.facts.get('hostname', 'Unknown')}")
            print(f"[+] Модель: {self.device.facts.get('model', 'Unknown')}")
            
            return True
            
        except (ConnectAuthError, ConnectTimeoutError, ConnectRefusedError, ConnectError) as e:
            error_name = type(e).__name__
            print(f"[-] Ошибка подключения к {self.host}: {error_name}")
            return False
            
        except Exception as e:
            print(f"[-] Неожиданная ошибка при подключении к {self.host}: {type(e).__name__}: {e}")
            return False
    
    def execute_command(self, command: str) -> Optional[str]:
        """Выполнить CLI команду"""
        if not self.device:
            return None
        
        try:
            result = self.device.cli(command, warning=False)
            return result
        except Exception as e:
            print(f"[-] Ошибка выполнения команды '{command}' на {self.host}: {e}")
            return None
    
    def get_interface_config(self, interface: str) -> Optional[str]:
        """Получить конфигурацию интерфейса"""
        command = f"show configuration interfaces {interface}"
        return self.execute_command(command)
    
    def close(self):
        """Закрыть соединение"""
        if self.device:
            try:
                self.device.close()
                print(f"[*] Отключились от {self.host}")
            except:
                pass


class RouteTracer:
    """Основной класс для трассировки маршрутов"""
    
    def __init__(self, cred_manager: CredentialManager, vrf_list: List[str], port: int = 22):
        self.cred_manager = cred_manager
        self.vrf_list = vrf_list
        self.port = port
        self.visited_devices: Set[str] = set()
        self.max_hops = 20
        self.results = []
    
    def trace_route(self, host: str, target_ip: str, specific_vrfs: Optional[List[str]] = None, 
                    hop_count: int = 0, parent_vrf: str = None) -> bool:
        """
        Рекурсивная трассировка маршрута
        """
        
        # Защита от циклов
        if hop_count >= self.max_hops:
            print(f"[!] Достигнут максимум хопов ({self.max_hops})")
            return False
        
        device_key = f"{host}#{hop_count}"
        if device_key in self.visited_devices:
            print(f"[!] Устройство {host} уже было посещено на этом уровне")
            return False
        
        # НОВОЕ: Проверяем, не помечен ли хост как недоступный
        if self.cred_manager.is_host_failed(host):
            print(f"[!] Хост {host} ранее был помечен как недоступный, пропускаем")
            return False
        
        self.visited_devices.add(device_key)
        
        # Получаем креды
        username, password = self.cred_manager.get_credentials(host)
        
        # Подключаемся
        device = JuniperDevice(host, username, password, port=self.port)
        
        max_retries = 1  # ИЗМЕНЕНО: только 1 попытка
        
        if not device.connect():
            # НОВОЕ: Спрашиваем пользователя
            creds = self.cred_manager.prompt_for_credentials(host)
            if creds is None:
                # Пользователь решил пропустить
                self.cred_manager.mark_host_failed(host)
                return False
            
            username, password = creds
            device = JuniperDevice(host, username, password, port=self.port)
            
            if not device.connect():
                print(f"[-] Не удалось подключиться к {host}, пропускаем")
                self.cred_manager.mark_host_failed(host)
                return False
        
        try:
            # Определяем список VRF для проверки
            if specific_vrfs:
                vrfs_to_check = specific_vrfs
            else:
                vrfs_to_check = self.vrf_list.copy()
            
            # Если указан parent_vrf, проверяем его первым
            if parent_vrf and parent_vrf in vrfs_to_check:
                vrfs_to_check.remove(parent_vrf)
                vrfs_to_check.insert(0, parent_vrf)
            
            all_found_routes = []  # НОВОЕ: собираем ВСЕ найденные маршруты
            
            print(f"\n[*] Будет проверено {len(vrfs_to_check)} VRF на {host}")
            
            # Проверяем каждый VRF
            for idx, vrf_full in enumerate(vrfs_to_check, 1):
                if not VRFManager.is_vrf_filename_safe(vrf_full):
                    print(f"\n[!] [{idx}/{len(vrfs_to_check)}] ПРОПУЩЕН {vrf_full} - содержит недопустимые символы")
                    continue
                
                vrf_display = vrf_full if vrf_full != "inet.0" else "default (inet.0)"
                
                print(f"\n[*] [{idx}/{len(vrfs_to_check)}] Проверяем {target_ip} в {vrf_display} на {host}...")
                
                if vrf_full == "inet.0":
                    command = f"show route {target_ip}"
                else:
                    command = f"show route {target_ip} table {vrf_full}"
                
                output = device.execute_command(command)
                
                if not output:
                    continue
                
                # Сохраняем полный вывод
                self.save_output(host, vrf_full, command, output, hop_count)
                
                # Парсим маршруты
                parsed = RouteParser.parse_route_output(output, target_ip)
                matching = RouteParser.find_matching_routes(parsed, target_ip)
                
                if matching:
                    print(f"[+] Найдено {len(matching)} АКТИВНЫХ маршрутов в {vrf_display}")
                    for route in matching:
                        print(f"    - {route['prefix']} через {route['protocol']}")
                    all_found_routes.extend([(vrf_full, route) for route in matching])
            
            if not all_found_routes:
                print(f"[-] Активные маршруты к {target_ip} не найдены на {host}")
                return False
            
            # НОВОЕ: Выбираем САМЫЙ СПЕЦИФИЧНЫЙ маршрут
            print(f"\n[*] Всего найдено активных маршрутов: {len(all_found_routes)}")
            
            # Сортируем по специфичности (длина префикса)
            all_found_routes.sort(key=lambda x: int(x[1]['prefix'].split('/')[1]), reverse=True)
            
            best_vrf, best_route = all_found_routes[0]
            
            print(f"\n[+++] ВЫБРАН НАИБОЛЕЕ СПЕЦИФИЧНЫЙ МАРШРУТ:")
            print(f"[+++] VRF: {best_vrf}")
            print(f"[+++] Префикс: {best_route['prefix']}")
            print(f"[+++] Протокол: {best_route['protocol']}")
            
            # Обрабатываем ТОЛЬКО выбранный маршрут
            final_interface_found = False
            
            for nh in best_route['next_hops']:
                if nh['type'] == 'direct':
                    # Конечный интерфейс найден!
                    print(f"\n[+++] НАЙДЕН КОНЕЧНЫЙ ИНТЕРФЕЙС: {nh['interface']} на {host} в VRF {best_vrf}")
                    config = device.get_interface_config(nh['interface'])
                    if config:
                        self.save_interface_config(host, nh['interface'], best_vrf, config, hop_count)
                    final_interface_found = True
                
                elif nh['type'] == 'interface' and 'gateway' in nh:
                    # Есть next-hop устройство
                    next_hop_ip = nh['gateway']
                    print(f"\n[->] Next-hop: {next_hop_ip} через {nh['interface']}")
                    
                    # Рекурсивно проверяем следующее устройство
                    print(f"\n{'='*60}")
                    print(f"[*] Переходим на следующее устройство: {next_hop_ip} (hop {hop_count + 1})")
                    print(f"[*] Продолжаем поиск в VRF: {best_vrf}")
                    print(f"{'='*60}")
                    
                    self.trace_route(next_hop_ip, target_ip, [best_vrf], hop_count + 1, best_vrf)
            
            return final_interface_found
        
        finally:
            device.close()
    
    def save_output(self, host: str, vrf: str, command: str, output: str, hop: int):
        """Сохранить вывод команды"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vrf_safe = VRFManager.sanitize_vrf_for_filename(vrf)
        filename = f"trace_{host}_{vrf_safe}_hop{hop}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Host: {host}\n")
            f.write(f"VRF: {vrf}\n")
            f.write(f"Hop: {hop}\n")
            f.write(f"Command: {command}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write("="*80 + "\n\n")
            f.write(output)
        
        print(f"[*] Вывод сохранен в {filename}")
    
    def save_interface_config(self, host: str, interface: str, vrf: str, config: str, hop: int):
        """Сохранить конфигурацию интерфейса"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vrf_safe = VRFManager.sanitize_vrf_for_filename(vrf)
        interface_safe = interface.replace('/', '_')
        filename = f"FINAL_interface_{host}_{interface_safe}_{vrf_safe}_hop{hop}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"=== FINAL INTERFACE CONFIGURATION ===\n")
            f.write(f"Host: {host}\n")
            f.write(f"Interface: {interface}\n")
            f.write(f"VRF: {vrf}\n")
            f.write(f"Hop: {hop}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write("="*80 + "\n\n")
            f.write(config)
        
        print(f"[+++] Конфигурация интерфейса сохранена в {filename}")


def interactive_menu():
    """Интерактивное меню выбора режима"""
    print("\n" + "="*80)
    print("Выберите режим работы:")
    print("="*80)
    print("1. Использовать список VRF из файла vrfs.txt")
    print("2. Указать другой файл со списком VRF")
    print("3. Ввести VRF вручную (один или несколько через запятую)")
    print("4. Использовать встроенный список VRF")
    print("5. Создать файл vrfs.txt из встроенного списка")
    
    choice = input("\nВаш выбор (1-5): ").strip()
    
    if choice == "1":
        vrfs = VRFManager.get_vrf_list()
        return vrfs
    
    elif choice == "2":
        filepath = input("Введите путь к файлу: ").strip()
        vrfs = VRFManager.get_vrf_list(filepath)
        return vrfs
    
    elif choice == "3":
        vrf_input = input("Введите VRF (через запятую для нескольких, ПОЛНЫЕ названия с .inet.0/.l2vpn.0): ").strip()
        vrfs = [v.strip() for v in vrf_input.split(',') if v.strip()]
        if vrfs:
            print(f"[+] Будет проверено VRF: {', '.join(vrfs)}")
            # Проверяем на проблемные символы
            for vrf in vrfs:
                if not VRFManager.is_vrf_filename_safe(vrf):
                    print(f"[!] ВНИМАНИЕ: VRF '{vrf}' содержит недопустимые символы для Windows!")
                    print(f"    Этот VRF будет пропущен при сохранении файлов")
            return vrfs
        else:
            print("[-] Не введено ни одного VRF, используется встроенный список")
            return DEFAULT_VRFS.copy()
    
    elif choice == "4":
        print(f"[+] Используется встроенный список ({len(DEFAULT_VRFS)} VRF)")
        return DEFAULT_VRFS.copy()
    
    elif choice == "5":
        VRFManager.save_vrfs_to_file(DEFAULT_VRFS, "vrfs.txt")
        print("[*] Файл создан. Запустите скрипт снова и выберите опцию 1")
        sys.exit(0)
    
    else:
        print("[-] Неверный выбор, используется встроенный список")
        return DEFAULT_VRFS.copy()


def main():
    """Главная функция"""
    print("="*80)
    print("Juniper Route Tracer v2.2 - FIXED VRF Names")
    print("="*80)
    
    # Выбор режима работы с VRF
    vrf_list = interactive_menu()
    
    # Получаем начальные параметры
    print("\n" + "="*80)
    print("Параметры трассировки")
    print("="*80)
    
    start_host = input("\nВведите IP начального устройства: ").strip()
    target_ip = input("Введите целевой IP адрес для трассировки: ").strip()
    
    # Настройка порта SSH
    print("\n" + "="*80)
    print("Настройка подключения")
    print("="*80)
    port_input = input("SSH порт (нажмите Enter для 22): ").strip()
    port = int(port_input) if port_input else 22
    
    # Настройка аутентификации
    print("\n" + "="*80)
    print("Настройка аутентификации")
    print("="*80)
    
    default_user = input("Username по умолчанию: ").strip()
    default_pass = getpass.getpass("Password по умолчанию: ")
    
    cred_manager = CredentialManager()
    cred_manager.set_default(default_user, default_pass)
    
    # Запускаем трассировку
    print("\n" + "="*80)
    print("Начинаем трассировку")
    print("="*80)
    print(f"[*] Устройство: {start_host}")
    print(f"[*] Целевой IP: {target_ip}")
    print(f"[*] SSH порт: {port}")
    print(f"[*] VRF для проверки: {len(vrf_list)} шт")
    
    # Проверяем проблемные VRF
    problematic_vrfs = [vrf for vrf in vrf_list if not VRFManager.is_vrf_filename_safe(vrf)]
    if problematic_vrfs:
        print(f"\n[!] ВНИМАНИЕ: Обнаружено {len(problematic_vrfs)} VRF с недопустимыми символами для Windows:")
        for vrf in problematic_vrfs:
            print(f"    - {vrf}")
        print(f"[!] Эти VRF будут пропущены при сохранении файлов")
    
    tracer = RouteTracer(cred_manager, vrf_list, port=port)
    
    try:
        tracer.trace_route(start_host, target_ip, hop_count=0)
    except KeyboardInterrupt:
        print("\n\n[!] Трассировка прервана пользователем")
    except Exception as e:
        print(f"\n[-] Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*80)
    print("Трассировка завершена")
    print("="*80)
    print(f"[*] Посещено устройств: {len(tracer.visited_devices)}")
    print("[*] Проверьте файлы с префиксом 'trace_' и 'FINAL_interface_' для результатов")


if __name__ == "__main__":
    main()
