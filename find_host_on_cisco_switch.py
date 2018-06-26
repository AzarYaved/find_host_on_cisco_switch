# -*- coding: utf-8 -*-

from netmiko import ConnectHandler
import getpass
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
import subprocess
import argparse
import sys
import textfsm
import re
import socket
import telnetlib
import os
from tqdm import tqdm


def ping_check(ip_device):
    #ip_address_resolve = socket.gethostbyname(ip_device)
    ping_result = subprocess.run(['ping', '-c', '3', '-n', ip_device], stdout=subprocess.PIPE, encoding='utf-8')
    ip_address_resolve_match = re.search('PING \S+ \((?P<ip>(\d{1,3}.){3}\d{1,3})\)',ping_result.stdout)
    if ip_address_resolve_match:
        ip_address_device = ip_address_resolve_match.group('ip')

    if ping_result.returncode == 0:
        print('Устройство с ip-адресом',ip_address_device, 'отвечает на icmp-запросы - OK', end='\n')
    else:
        print('Устройство с ip-адресом',ip_device, 'не отвечает на icmp-запросы - Fail\nПродолжить поиск устройства?')
        proceed_seach = input('yes/no\n')
        if proceed_seach == 'yes':
            print('\nПродолжаю поиск',ip_device)
        else:
            print('\nРабота скрипта завершена')
            sys.exit()

    return ip_address_device

def gateway_find(ip_address_device,show_traceroute):
    root_priv = os.environ['USER']
    if root_priv =='root':
        traceroute_pc_result = subprocess.run(['traceroute', '-n', '-4', '-m 15', '-I', ip_address_device],
                                              stdout=subprocess.PIPE, encoding='utf-8')
    else:
        print(' !!! Скрипт запушен без прав суперпользователя, поиск шлюза может быть выполнен некорректно !!!\n'
              ' >>> Права суперпользователя нужны для использования icmp утилитой traceroute\n')

        traceroute_pc_result = subprocess.run(['traceroute', '-n', '-4', '-m 15', ip_address_device],
                                              stdout=subprocess.PIPE, encoding='utf-8')

    template = open('traceroute.template')
    fsm = textfsm.TextFSM(template)
    pc_traceroute_result = traceroute_pc_result.stdout
    result = fsm.ParseText(pc_traceroute_result)

    if show_traceroute:
        for hops in result:
            print(','.join(hops).replace(',','  -->  '))

    len_of_hops = len(result)
    gateway_number = len_of_hops - 2
    gataway_ip = result[gateway_number][1]

    print('Скрипт определил, что адрес шлюза',gataway_ip,'для устройства', ip_address_device)

    return gataway_ip


def ssh_or_telnet(gateway_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result_ssh = sock.connect_ex((gateway_ip, 22))

    if result_ssh == 0:
        print('Доступно подключение по ssh для ip', gateway_ip)
        return True
    else:
        result_telnet = sock.connect_ex((gateway_ip, 23))
        if result_telnet ==0:
            print('Доступно подключение по telnet для ip',gateway_ip)
            return False
        else:
            print('\nssh и telnet недоступны на этом устройстве')
            sys.exit()



def ssh_connect(gateway_ip, ip_address_device):
    # Запрашиваем данные для авторизации
    print('\nВведите данные авторизации для шлюза', gateway_ip, end='\n')
    user = input('Username: ')
    password = getpass.getpass()
    #enable_password = getpass.getpass(prompt='Enter enable password, if necessary: ')
    print('\nВыполняю подключение и поиск по заданным критериям...')



    connect_keys = ['device_type', 'ip', 'username', 'password', 'secret']
    connect_params = dict.fromkeys(connect_keys)

    connect_params['device_type'] = 'cisco_ios'
    connect_params['ip'] = gateway_ip
    connect_params['username'] = user
    connect_params['password'] = password
    #connect_params['secret'] = enable_password

    show_arp = 'show arp | include {}'.format(ip_address_device)
    try:
        with ConnectHandler(**connect_params) as ssh:
            output_show_arp = ssh.send_command(show_arp)
            arp_result_match = re.search('\w+\s+(?P<ip>(\d{1,3}.){3}\d{1,3})\s+(?P<age>\d{1,3})\s+(?P<mac>(\w{4}.){2}\w{4})\s+ARPA\s+Vlan(?P<vlan>\d+)', output_show_arp.strip())
            if arp_result_match:
                ip_host = arp_result_match.group('ip')
                mac_host = arp_result_match.group('mac')
                vlan = arp_result_match.group('vlan')

                traceroute_mac ='traceroute mac {} {} detail'.format(mac_host,mac_host)
                output_traceroute_mac = ssh.send_command(traceroute_mac)
                output_traceroute_mac_splitted = output_traceroute_mac.split('\n')
                for line in output_traceroute_mac_splitted:
                    switch_match = re.search('\d\s(?P<hostname>\S+)\s/\s(?P<model>\S+)\s/\s(?P<ip_switch>(\d{1,3}.){3}\d{1,3}).+',line)
                    port_match = re.search('\s+(?P<port>\w+(/\d{1,3})*)\s\[', line)
                    ip_phone_match = re.search('Unable to send a l2trace request to (?P<ip_phone>(\d{1,3}.){3}\d{1,3}).+',line)

                    if switch_match:
                        sw_hostname = switch_match.group('hostname')
                        sw_model = switch_match.group('model')
                        sw_ip = switch_match.group('ip_switch')
                        print('-' * 40)
                        print('{:20}{:20}'.format('Switch hostname:', sw_hostname))
                        print('{:20}{:20}'.format('Switch model:', sw_model))
                        print('{:20}{:20}'.format('Switch ip:', sw_ip))
                    if port_match:
                        sw_port = port_match.group('port')
                        print('{:20}{:20}'.format('Switch port:', sw_port))
                        print('{:20}{:20}'.format('Vlan:', vlan))
                        print('{:20}{:20}'.format('Host mac-address:', mac_host))

                    if ip_phone_match:

                        ip_phone = ip_phone_match.group('ip_phone')
                        show_arp_ip_phone = 'show arp | include {}'.format(ip_phone)
                        output_show_arp_ip_phone = ssh.send_command(show_arp_ip_phone)
                        arp_ip_phone_result_match = re.search('\w+\s+(?P<ip>(\d{1,3}.){3}\d{1,3})\s+(?P<age>\d{1,3})\s+(?P<mac>(\w{4}.){2}\w{4})\s+ARPA\s+Vlan(?P<vlan>\d+)',output_show_arp_ip_phone.strip())
                        if arp_ip_phone_result_match:
                            ip_ip_phone = arp_ip_phone_result_match.group('ip')
                            mac_ip_phone = arp_ip_phone_result_match.group('mac')
                            voice_vlan = arp_ip_phone_result_match.group('vlan')
                            traceroute_mac_ip_phone = 'traceroute mac {} {} detail'.format(mac_ip_phone, mac_ip_phone)
                            output_traceroute_mac_ip_phone = ssh.send_command(traceroute_mac_ip_phone)
                            output_traceroute_mac_ip_phone_splitted = output_traceroute_mac_ip_phone.split('\n')
                            for line in output_traceroute_mac_ip_phone_splitted:
                                switch_match = re.search('\d\s(?P<hostname>\S+)\s/\s(?P<model>\S+)\s/\s(?P<ip_switch>(\d{1,3}.){3}\d{1,3}).+',line)
                                port_match = re.search('\s+(?P<port>\w+(/\d{1,3})*)\s\[', line)

                                if switch_match:
                                    sw_hostname = switch_match.group('hostname')
                                    sw_model = switch_match.group('model')
                                    sw_ip = switch_match.group('ip_switch')
                                    print('-' * 40)
                                    print('{:20}{:20}'.format('Switch hostname:', sw_hostname))
                                    print('{:20}{:20}'.format('Switch model:', sw_model))
                                    print('{:20}{:20}'.format('Switch ip:', sw_ip))
                                if port_match:
                                    sw_port = port_match.group('port')
                                    print('{:20}{:20}'.format('Switch port:', sw_port))
                                    print('{:20}{:20}'.format('Vlan:', vlan))
                                    print('{:20}{:20}'.format('Host mac-address:', mac_host))
                            print('-' * 40)
                            print('Перед хостом найдено подключенное устройство, н.р. ip-телефон или беспроводная точка доступа')
                            print('-' * 40)
                            print('{:20}{:20}'.format('Phone or AP ip:', ip_ip_phone))
                            print('{:20}{:20}'.format('Phone or AP mac:', mac_ip_phone))
                            print('{:20}{:20}'.format('Voice or AP vlan:', voice_vlan))


                print('-' * 40)

    except NetMikoAuthenticationException:
        print('Введены неверные данные авторизации для шлюза устройства')
        sys.exit()
    except NetMikoTimeoutException:
        print(args.host, '- ошибка подключения по таймауту или доступ к ssh заблокирован', end='\n')


def telnet_connect(gateway_ip, ip_address_device):
    # Запрашиваем данные для авторизации
    print('\nВведите данные авторизации для шлюза', gateway_ip, end='\n')
    user = input('Username: ').encode('utf-8')
    password = getpass.getpass().encode('utf-8')

    show_arp = 'show arp | include {}'.format(ip_address_device).encode('utf-8')

    with telnetlib.Telnet(gateway_ip) as t:
        try:
            t.read_until(b'Username:')
            t.write(user + b'\n')

            t.read_until(b'Password:')
            t.write(password + b'\n')
            print('\nВыполняю подключение и поиск по заданным критериям...')

            t.write(b'terminal length 0\n')
            t.read_until(b'#')

            t.write(show_arp + b'\n')
            arp_output = t.read_until(b'>', timeout=5).decode('utf-8')

            arp_result_match = re.search('\w+\s+(?P<ip>(\d{1,3}.){3}\d{1,3})\s+(?P<age>\d{1,3})\s+(?P<mac>(\w{4}.){2}\w{4})\s+ARPA\s+Vlan(?P<vlan>\d+)',arp_output.strip())

            if arp_result_match:
                ip_host = arp_result_match.group('ip')
                mac_host = arp_result_match.group('mac')
                vlan = arp_result_match.group('vlan')


            traceroute_mac = 'traceroute mac {} {} detail'.format(mac_host, mac_host).encode('utf-8')

            t.write(traceroute_mac + b'\n')
            output_traceroute_mac = t.read_until(b'#',timeout=25).decode('utf-8')
            output_traceroute_mac_splitted = output_traceroute_mac.split('\n')


            for line in output_traceroute_mac_splitted:
                switch_match = re.search('\d\s(?P<hostname>\S+)\s/\s(?P<model>\S+)\s/\s(?P<ip_switch>(\d{1,3}.){3}\d{1,3}).+', line)
                port_match = re.search('\s+(?P<port>\w+(/\d{1,3})*)\s\[', line)
                ip_phone_match = re.search('Unable to send a l2trace request to (?P<ip_phone>(\d{1,3}.){3}\d{1,3}).+', line)


                if switch_match:
                    sw_hostname = switch_match.group('hostname')
                    sw_model = switch_match.group('model')
                    sw_ip = switch_match.group('ip_switch')

                    print('-' * 40)
                    print('{:20}{:100}'.format('Switch hostname:', sw_hostname))
                    print('{:20}{:100}'.format('Switch model:', sw_model))
                    print('{:20}{:100}'.format('Switch ip:', sw_ip))

                if port_match:
                    sw_port = port_match.group('port')
                    print('{:20}{:100}'.format('Switch port:', sw_port))
                    print('{:20}{:100}'.format('Vlan:', vlan))
                    print('{:20}{:100}'.format('Host mac-address:', mac_host))

                if ip_phone_match:
                    ip_phone = ip_phone_match.group('ip_phone')
                    show_arp_ip_phone = 'show arp | include {}'.format(ip_phone).encode('utf-8')

                    t.write(show_arp_ip_phone + b'\n')
                    output_show_arp_ip_phone = t.read_until(b'#',timeout=5).decode('utf-8')

                    arp_ip_phone_result_match = re.search('\w+\s+(?P<ip>(\d{1,3}.){3}\d{1,3})\s+(?P<age>\d{1,3})\s+(?P<mac>(\w{4}.){2}\w{4})\s+ARPA\s+Vlan(?P<vlan>\d+)',output_show_arp_ip_phone.strip())

                    if arp_ip_phone_result_match:
                        ip_ip_phone = arp_ip_phone_result_match.group('ip')
                        mac_ip_phone = arp_ip_phone_result_match.group('mac')
                        voice_vlan = arp_ip_phone_result_match.group('vlan')

                        traceroute_mac_ip_phone = 'traceroute mac {} {} detail'.format(mac_ip_phone, mac_ip_phone).encode('utf-8')

                        t.write(traceroute_mac_ip_phone + b'\n')
                        output_traceroute_mac_ip_phone = t.read_until(b'#', timeout=15).decode('utf-8')
                        output_traceroute_mac_ip_phone_splitted = output_traceroute_mac_ip_phone.split('\n')

                        for line in output_traceroute_mac_ip_phone_splitted:
                            switch_match = re.search('\d\s(?P<hostname>\S+)\s/\s(?P<model>\S+)\s/\s(?P<ip_switch>(\d{1,3}.){3}\d{1,3}).+', line)
                            port_match = re.search('\s+(?P<port>\w+(/\d{1,3})*)\s\[', line)

                            if switch_match:
                                sw_hostname = switch_match.group('hostname')
                                sw_model = switch_match.group('model')
                                sw_ip = switch_match.group('ip_switch')
                                print('-' * 40)
                                print('{:20}{:20}'.format('Switch hostname:', sw_hostname))
                                print('{:20}{:20}'.format('Switch model:', sw_model))
                                print('{:20}{:20}'.format('Switch ip:', sw_ip))

                            if port_match:
                                sw_port = port_match.group('port')
                                print('{:20}{:20}'.format('Switch port:', sw_port))
                                print('{:20}{:20}'.format('Vlan:', vlan))
                                print('{:20}{:20}'.format('Host mac-address:', mac_host))
                        print('-' * 40)
                        print('Перед хостом найдено подключенное устройство, н.р. ip-телефон или беспроводная точка доступа')
                        print('-' * 40)
                        print('{:20}{:20}'.format('Phone or AP ip:', ip_ip_phone))
                        print('{:20}{:20}'.format('Phone or AP mac:', mac_ip_phone))
                        print('{:20}{:20}'.format('Voice or AP vlan:', voice_vlan))
            print('-' * 40)

        except EOFError:
            print('\nВведены неверные данные авторизации для шлюза устройства')
            t.close()

    t.close()

parser = argparse.ArgumentParser(description='e.g. python3.6 find_host_on_cisco_switch.py 10.10.10.1 -t')
parser.add_argument('host', action="store", help="Ip address or name that we are looking for")
parser.add_argument('-t', action='store_true', dest='traceroute', help="show traceroute result")
parser.add_argument('-g', action='store', dest='force_gateway', metavar='gateway ip', help="forced gateway selection")


args = parser.parse_args()

if __name__ == '__main__':
    ip_address_device = ping_check(args.host)
    if args.force_gateway:
        print('Принудительно выставлен адрес шлюза', args.force_gateway)
        gateway_ip = args.force_gateway
    else:
        gateway_ip = gateway_find(ip_address_device, args.traceroute)
    if ssh_or_telnet(gateway_ip):
        ssh_connect(gateway_ip, ip_address_device)
    else:
        telnet_connect(gateway_ip, ip_address_device)


print('\n','Работа скрипта завершена')
