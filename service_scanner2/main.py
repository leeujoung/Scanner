import json
import csv
import os
import threading
import importlib
from queue import Queue

def load_port_mappings(config_file):
    try:
        with open(config_file, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading port mappings: {e}")
        return {}

def scan_port(host, port, scan_module_name, result_queue):
    try:
        scan_module = importlib.import_module(scan_module_name)
        scan_function = getattr(scan_module, "scan")
        print(f"Scanning port {port} using {scan_module_name}...")
        result = scan_function(host, port)
        result_queue.put(result)
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        result_queue.put({
            "port": port,
            "status": "error",
            "service": "",
            "banner": "",
            "error": str(e)
        })

def save_results(results):
    try:
        if not os.path.exists('results'):
            os.makedirs('results')

        with open('results/scan_results.json', 'w') as json_file:
            json.dump(results, json_file, indent=4)

        csv_columns = ["port", "status", "service", "banner"]
        with open('results/scan_results.csv', 'w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
            writer.writeheader()
            for data in results:
                filtered_data = {key: data.get(key, "") for key in csv_columns}
                writer.writerow(filtered_data)
    except Exception as e:
        print(f"Error saving results: {e}")

def main():
    try:
        host = input("Enter the IP address of the server to scan: ")
        port_mappings = load_port_mappings('config/port_mappings.json')
        
        results = []
        result_queue = Queue()
        threads = []

        for port in range(1, 65335):
            scan_module_name = port_mappings.get(str(port), port_mappings.get("default"))
            thread = threading.Thread(target=scan_port, args=(host, port, scan_module_name, result_queue))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        while not result_queue.empty():
            result = result_queue.get()
            results.append(result)

        save_results(results)

        print("\nOpen Ports Scan Results:")
        for result in results:
            if result["status"] == "open":
                print(json.dumps(result, indent=4))

        print("Scan completed.")
    except Exception as e:
        print(f"Error in main function: {e}")

    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
