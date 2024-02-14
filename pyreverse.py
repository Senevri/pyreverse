import os
import configparser
import ipaddress

from pyreverselib import Proxy, check_port

from mylogger import logger


def proxy_cli(proxies):
    exit_requested = False

    print("Reverse Proxy Tool v1.0 by Ark")
    print("\nCommands:")
    print("- list: Show all proxies.")
    print("- reload: reload all proxies from the config.ini.")
    print("- start <ID>: Start a specific proxy.")
    print("- start all: Start all proxies.")
    print("- stop <ID>: Stop a specific proxy.")
    print("- stop all: Stop all proxies.")
    print("- status <ID>: Show the status of a specific proxy.")
    print("- status all: Show the status of all proxies.")
    print("- add <Host> <HttpPort> <HttpsPort> <Mapping>: Add a new proxy.")
    print("- edit <ID> <Host> <HttpPort> <HttpsPort> <Mapping>: Edit an existing proxy.")
    print("- delete <ID>: Delete a specific proxy.")
    print("- help: Displays available commands.")
    print("- exit: Stop all proxies and exit.")

    while True:
        cmd = input("> ").lower().split()

        if len(cmd) == 0:
            continue

        if cmd[0] == "list":
            for i, proxy in enumerate(proxies, start=1):
                status = (
                    "online"
                    if check_port(proxy.host, proxy.http_port) and proxy.running
                    else "offline"
                )
                print(
                    f"Proxy ID: {i}, Host: {proxy.host}, "
                    f"HttpPort: {proxy.http_port}, HttpsPort: {proxy.https_port}, "
                    f"Mapping: {proxy.mapping}, Status: {status}"
                )

        elif cmd[0] == "start":
            if len(cmd) > 1:
                if cmd[1] == "all":
                    for i, proxy in enumerate(proxies, start=1):
                        proxy.start()
                        print(f"Proxy {i} initializing.")
                else:
                    try:
                        proxy_id = int(cmd[1])
                        if 1 <= proxy_id <= len(proxies):
                            proxies[proxy_id - 1].start()
                            print(f"Proxy {proxy_id} initializing.")
                        else:
                            print("Invalid proxy ID.")
                    except ValueError:
                        print("Invalid proxy ID.")
            else:
                print("Usage: start <ID> or start all")

        # Add a new "status" command
        elif cmd[0] == "status":
            if len(cmd) > 1:
                if cmd[1] == "all":
                    for i, proxy in enumerate(proxies, start=1):
                        status = (
                            "online"
                            if check_port(proxy.host, proxy.http_port) and proxy.running
                            else "offline"
                        )
                        print(f"Proxy ID: {i}, Status: {status}")
                else:
                    try:
                        proxy_id = int(cmd[1])
                        if 1 <= proxy_id <= len(proxies):
                            proxy = proxies[proxy_id - 1]
                            status = (
                                "online"
                                if check_port(proxy.host, proxy.http_port) and proxy.running
                                else "offline"
                            )
                            print(f"Proxy ID: {proxy_id}, Status: {status}")
                        else:
                            print("Invalid proxy ID.")
                    except ValueError:
                        print("Invalid proxy ID.")
            else:
                print("Usage: status <ID> or status all")

        elif cmd[0] == "stop":
            if len(cmd) > 1:
                if cmd[1] == "all":
                    for i, proxy in enumerate(proxies, start=1):
                        proxy.stop()
                        print(f"Proxy {i} offline.")
                else:
                    try:
                        proxy_id = int(cmd[1])
                        if 1 <= proxy_id <= len(proxies):
                            proxies[proxy_id - 1].stop()
                            print(f"Proxy {proxy_id} offline.")
                        else:
                            print("Invalid proxy ID.")
                    except ValueError:
                        print("Invalid proxy ID.")
            else:
                print("Usage: stop <ID> or stop all")

        elif cmd[0] == "add":
            if len(cmd) >= 4:
                host, http_port, https_port = cmd[1], int(cmd[2]), int(cmd[3])
                if len(cmd) == 5:
                    mapping = cmd[4] or "/"
                if not valid_ip(host):
                    print("Invalid IP address.")
                elif not valid_port(http_port) or not valid_port(https_port):
                    print("Invalid port number.")
                elif http_port == https_port:
                    print("HttpPort and HttpsPort cannot be the same.")
                elif ports_in_use(proxies, http_port, https_port):
                    print("One or both of the specified ports are already in use.")
                elif not proxy_exists(proxies, host, http_port, https_port):
                    proxy = Proxy(host, http_port, https_port, mapping)
                    proxies.append(proxy)
                    update_config(proxies, config_path)
                    print(
                        f"Added proxy: Host: {host}, HttpPort: {http_port}, HttpsPort: {https_port}"
                    )
                else:
                    print("This proxy already exists.")
            else:
                print("Usage: add <Host> <HttpPort> <HttpsPort>")

        elif cmd[0] == "edit":
            if len(cmd) >= 5:
                try:
                    proxy_id = int(cmd[1])
                    if 1 <= proxy_id <= len(proxies):
                        if not proxies[proxy_id - 1].running:
                            mapping = proxies[proxy_id - 1].mapping
                            host, http_port, https_port = cmd[2], int(cmd[3]), int(cmd[4])
                            if len(cmd) == 6:
                                mapping = cmd[5]
                            if not valid_ip(host):
                                print("Invalid IP address.")
                            elif not valid_port(http_port) or not valid_port(https_port):
                                print("Invalid port number.")
                            elif http_port == https_port:
                                print("HttpPort and HttpsPort cannot be the same.")
                            elif ports_in_use(
                                proxies, http_port, https_port, exclude_proxy_id=proxy_id
                            ):
                                print("One or both of the specified ports are already in use.")
                            else:
                                print(f"About to edit proxy {proxy_id} with the following details:")
                                print(
                                    f"Host: {host}, HttpPort: {http_port}, HttpsPort: {https_port}"
                                    f" Mapping {mapping}"
                                )
                                while True:
                                    confirm = input("Confirm edit? (yes/no): ").lower()
                                    if confirm == "yes":
                                        proxies[proxy_id - 1].host = host
                                        proxies[proxy_id - 1].http_port = http_port
                                        proxies[proxy_id - 1].https_port = https_port
                                        proxies[proxy_id - 1].mapping = mapping
                                        update_config(proxies, config_path)
                                        print(
                                            f"Edited proxy {proxy_id}: Host: {host}, "
                                            f"HttpPort: {http_port}, HttpsPort: {https_port}"
                                            f"Mapping {mapping}"
                                        )
                                        break
                                    elif confirm == "no":
                                        print("Edit canceled.")
                                        break
                                    else:
                                        print("Invalid input. Please enter 'yes' or 'no'.")
                        else:
                            print("Cannot edit running threads.")
                    else:
                        print("Invalid proxy ID.")
                except ValueError:
                    print("Invalid proxy ID.")
            else:
                print("Usage: edit <ID> <Host> <HttpPort> <HttpsPort>")

        elif cmd[0] == "delete":
            if len(cmd) == 2:
                try:
                    proxy_id = int(cmd[1])
                    if 1 <= proxy_id <= len(proxies):
                        if not proxies[proxy_id - 1].running:
                            while True:
                                print(f"About to delete proxy {proxy_id}")
                                confirm = input("Confirm delete? (yes/no): ").lower()
                                if confirm == "yes":
                                    del proxies[proxy_id - 1]
                                    update_config(proxies, config_path)
                                    print(f"Deleted proxy {proxy_id}")
                                    break
                                elif confirm == "no":
                                    print("Delete canceled.")
                                    break
                                else:
                                    print("Invalid input. Please enter 'yes' or 'no'.")
                        else:
                            print("Cannot delete running threads.")
                    else:
                        print("Invalid proxy ID.")
                except ValueError:
                    print("Invalid proxy ID.")
            else:
                print("Usage: delete <ID>")

        elif cmd[0] == "reload":
            proxies = reload_configuration(config_path)
            print("Configuration reloaded.")

        elif cmd[0] == "help":
            print("Reverse Proxy Tool v1.0 by Ark")
            print("\nCommands:")
            print("- list: Show all proxies.")
            print("- reload: reload all proxies from the config.ini.")
            print("- start <ID>: Start a specific proxy.")
            print("- start all: Start all proxies.")
            print("- stop <ID>: Stop a specific proxy.")
            print("- stop all: Stop all proxies.")
            print("- status <ID>: Show the status of a specific proxy.")
            print("- status all: Show the status of all proxies.")
            print("- add <Host> <HttpPort> <HttpsPort> <Mapping>: Add a new proxy.")
            print("- edit <ID> <Host> <HttpPort> <HttpsPort>  <Mapping>: Edit an existing proxy.")
            print("- delete <ID>: Delete a specific proxy.")
            print("- help: Displays available commands.")
            print("- exit: Stop all proxies and exit.")

        elif cmd[0] == "exit":
            while True:
                confirm = input(
                    "Are you sure you want to exit? All threads will be interrupted (yes/no): "
                ).lower()
                if confirm == "yes":
                    # Stop all proxies before exiting
                    for proxy in proxies:
                        proxy.stop()
                    # Set exit_requested flag to True
                    exit_requested = True
                    break
                elif confirm == "no":
                    print("Exit canceled.")
                    break
                else:
                    print("Invalid input. Please enter 'yes' or 'no'.")

        # Add a condition to check the exit_requested flag
        if exit_requested:
            break


def ports_in_use(proxies, http_port, https_port, exclude_proxy_id=None):
    for idx, proxy in enumerate(proxies):
        if exclude_proxy_id is not None and idx == exclude_proxy_id - 1:
            continue
        if proxy.http_port == http_port or proxy.https_port == https_port:
            return True
    return False


def valid_port(port):
    return 1 <= port <= 65535


def valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def reload_configuration(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)

    proxies = []

    for section in config.sections():
        host = config[section]["Host"]
        http_port = int(config[section]["HttpPort"])
        https_port = int(config[section]["HttpsPort"])
        mapping = config[section].get("Mapping", "/")

        proxy = Proxy(host, http_port, https_port, mapping)
        proxies.append(proxy)

    return proxies


def proxy_exists(proxies, host, http_port, https_port):
    for proxy in proxies:
        if proxy.host == host and proxy.http_port == http_port and proxy.https_port == https_port:
            return True
    return False


def update_config(proxies, config_path):
    config = configparser.ConfigParser()
    for i, proxy in enumerate(proxies, start=1):
        section = f"Proxy{i}"
        config[section] = {}
        config[section]["Host"] = proxy.host
        config[section]["HttpPort"] = str(proxy.http_port)
        config[section]["HttpsPort"] = str(proxy.https_port)
        config[section]["Mapping"] = proxy.mapping

    with open(config_path, "w") as config_file:
        config.write(config_file)


if __name__ == "__main__":
    config = configparser.ConfigParser()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.ini")
    config.read(config_path)

    proxies = []

    for section in config.sections():
        host = config[section]["Host"]
        http_port = int(config[section]["HttpPort"])
        https_port = int(config[section]["HttpsPort"])
        mapping = config[section]["Mapping"]

        proxy = Proxy(host, http_port, https_port, mapping)
        proxies.append(proxy)

    try:
        # Start a simple command-line interface to control proxies
        proxy_cli(proxies)
    except KeyboardInterrupt:
        print("Shutting down proxies...")

    for proxy in proxies:
        proxy.stop()
