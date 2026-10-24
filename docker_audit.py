import docker
import json
import sys

def audit_docker_containers():
    try:
        # Connect to Docker Daemon via local socket
        client = docker.from_env()
    except Exception as e:
        print(f"[-] Error connecting to Docker daemon: {e}")
        print("[*] Make sure Docker is running and you have permissions (e.g., sudo or docker group).")
        sys.exit(1)

    # Fetch all containers (running and stopped)
    containers = client.containers.list(all=True)
    if not containers:
        print("[!] No containers found on the host.")
        return

    print("="*65)
    print("         DOCKER SECURITY AUDIT REPORT (CISSP Aligned)         ")
    print("="*65)

    audit_results = []

    for container in containers:
        c_info = container.attrs
        name = c_info['Name'].lstrip('/')
        image = c_info['Config']['Image']
        status = c_info['State']['Status']
        
        issues = []
        score = 100

        # Check 1: Non-Root User Execution (CISSP: Least Privilege)
        user = c_info['Config'].get('User', '')
        if not user or user == '0' or user == 'root':
            issues.append("CRITICAL: Container is running as root user (UID 0).")
            score -= 30
        
        # Check 2: Unpinned Base Image Tags (CISSP: Software Development Security)
        if ':' not in image or image.endswith(':latest'):
            issues.append("HIGH: Image uses an unpinned tag ('latest' or missing version tag).")
            score -= 20

        # Check 3: Hardcoded Secrets in Environment Variables (CISSP: Asset Protection)
        env_vars = c_info['Config'].get('Env', [])
        secret_keywords = ['password', 'secret', 'api_key', 'token', 'auth']
        for env in env_vars:
            key_val = env.lower()
            if any(kw in key_val for kw in secret_keywords):
                issues.append(f"HIGH: Potential hardcoded secret in environment variables: {env.split('=')[0]}")
                score -= 25
                break

        # Check 4: Sensitive Host Port Bindings (CISSP: Network Security)
        ports = c_info['NetworkSettings']['Ports']
        if ports:
            for container_port, host_bindings in ports.items():
                if host_bindings:
                    for binding in host_bindings:
                        host_ip = binding.get('HostIp', '')
                        if host_ip == '0.0.0.0' or host_ip == '':
                            issues.append(f"MEDIUM: Port {container_port} is bound to all interfaces (0.0.0.0).")
                            score -= 15

        # Check 5: Read-Only Root Filesystem (CISSP: Security Operations)
        readonly_rootfs = c_info['HostConfig'].get('ReadonlyRootfs', False)
        if not readonly_rootfs:
            issues.append("LOW: Root filesystem is writable (ReadonlyRootfs is disabled).")
            score -= 10

        # Ensure score doesn't drop below 0
        score = max(0, score)

        result = {
            "container_name": name,
            "image": image,
            "status": status,
            "security_score": score,
            "issues": issues
        }
        audit_results.append(result)

        # Print to Console
        print(f"\n[+] Container: {name}")
        print(f"    Image: {image}")
        print(f"    Status: {status}")
        print(f"    Security Score: {score}/100")
        if issues:
            print("    Vulnerabilities Found:")
            for issue in issues:
                print(f"      - {issue}")
        else:
            print("    Status: Secure (No major issues detected)")
        print("-" * 65)

    # Save Report to JSON format for professional delivery
    report_file = "docker_security_audit.json"
    with open(report_file, "w") as f:
        json.dump(audit_results, f, indent=4)
    print(f"\n[+] Full JSON audit report saved successfully to '{report_file}'")

if __name__ == "__main__":
    audit_docker_containers()