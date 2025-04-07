import subprocess
import yaml
import logging

logging.basicConfig(
    filename='kube-audit.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def load_config(file_path):
    """Load namespace and resource configurations from a YAML file."""
    with open(file_path, "r") as file:
        return yaml.safe_load(file)

def check_namespaces(config): # V-242383SS
    namespaces = config.get("namespaces", [])
    system_resources = config.get("system_resources", [])
    
    for ns in namespaces:
        logging.info(f"Checking namespace: {ns}")
        try:
            # Run kubectl command to list resources in the namespace
            cmd = f"kubectl -n {ns} get all --no-headers"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout.strip():
                resources = result.stdout.split("\n")
                user_resources = [r for r in resources if not any(sys_res in r for sys_res in system_resources)]
                
                if user_resources:
                   logging.warning(f"User-managed resources found in {ns} namespace:")
                else:
                    logging.info(f"No user-managed resources found in {ns} namespace.")
            else:
                logging.info(f"No user-managed resources found in {ns} namespace.")
        
        except Exception as e:
            logging.error(f"Error checking namespace {ns}: {e}")

def check_secrets_in_env(): # V-242415
    """Check if secrets are stored as environment variables in pods."""
    logging.info("Checking for secrets stored in environment variables...")
    try:
        cmd = "kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {..env[*].value}{\"\n\"}{end}'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            for line in lines:
                ns, pod, *env_vars = line.split(" ")
                if any(env_vars):
                   logging.warning(f"Pod {pod} in namespace {ns} has environment variables that may contain secrets.")
        else:
            logging.info("No secrets found in environment variables of pods.")
    except Exception as e:
        logging.error(f"Error checking secrets in environment variables: {e}")

def check_pod_security_admission(): # V-254800
    """Check if Kubernetes has a Pod Security Admission control file configured."""
    logging.info("Checking for Pod Security Admission control file...")
    try:
        cmd = "kubectl api-resources | grep podsecuritypolicies"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout.strip():
            logging.info("Pod Security Admission is configured.")
        else:
            logging.info("[WARNING] No Pod Security Admission control file found. Ensure it is configured in the API server.")
    except Exception as e:
        logging.error(f"Error checking Pod Security Admission control file: {e}")

def check_api_server_pps(config): # V-242410 V-242411 V-242412
    """Verify Kubernetes API Server ports and services against PPSM CAL."""
    logging.info("Checking Kubernetes API Server for PPSM CAL compliance...")
    
    allowed_ports = set(config.get("allowed_ports", []))
    allowed_protocols = set(config.get("allowed_protocols", []))

    try:
        # Get active ports and services related to kube-apiserver
        cmd = "kubectl get endpoints -n default kubernetes -o yaml"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            logging.info("[ERROR] Failed to retrieve API server ports.")
            return []

        data = yaml.safe_load(result.stdout)
        ports = [p['port'] for p in data.get("subsets", [{}])[0].get("ports", [])]
        protocols = [p['protocol'] for p in data.get("subsets", [{}])[0].get("ports", [])]

        non_compliant = False
        if ports:
            for port in ports:
                if port not in allowed_ports:
                    logging.warning(f"Non-compliant port {port} found.")
                    non_compliant = True
            
        else:
            logging.info("[WARNING] No API server ports found to check for compliance.")
    
        if protocols:
            for protocol in protocol:
                if protocol not in allowed_protocols:
                    logging.warning(f"Non-compliant protocol {protocol} found.")
                    non_compliant = True
            
        else:
            logging.info("[WARNING] No API server protocols found to check for compliance.")       
    
        if not non_compliant:
            logging.info("Kubernetes API Server PPS settings comply with PPSM CAL.")
        
    except Exception as e:
        logging.error(f"Error checking PPSM compliance: {e}")

def check_privileged_ports(config):
    """Check for use of privileged container and host ports in non-system pods."""
    logging.info("Checking for privileged ports in user pods (excluding system namespaces)...")
    non_compliant = False

    system_namespaces = set(config.get("namespaces", []))

    try:
        cmd = "kubectl get pods --all-namespaces -o yaml"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return []

        pods_data = yaml.safe_load(result.stdout)
        pods = pods_data.get("items", [])
    except Exception as e:
        logging.error(f"Error fetching pods: {e}")

    for pod in pods:
        namespace = pod["metadata"]["namespace"]
        if namespace in system_namespaces:
            continue  # Skip system namespaces

        pod_name = pod["metadata"]["name"]
        for container in pod.get("spec", {}).get("containers", []):
            container_name = container["name"]
            ports = container.get("ports", [])

            for port in ports:
                container_port = port.get("containerPort")
                host_port = port.get("hostPort")

                if container_port is not None and container_port < 1024:
                    logging.warning(f"Privileged container port {container_port} in pod '{pod_name}' (container '{container_name}', ns '{namespace}')")
                    non_compliant = True

                if host_port is not None and host_port < 1024:
                    logging.warning(f"Privileged host port {host_port} in pod '{pod_name}' (container '{container_name}', ns '{namespace}')")
                    non_compliant = True

    if not non_compliant:
        logging.info("No privileged ports found in non-system namespaces.")
    else:
        logging.info("[WARNING] Privileged ports found in user pods.")

if __name__ == "__main__":
    config = load_config("config.yaml")
    check_namespaces(config)
    check_secrets_in_env()
    check_pod_security_admission()
    check_api_server_pps(config)
    check_privileged_ports(config)
