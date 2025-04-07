# Canonical Kubernetes DISA STIG Checker

A command-line tool that automates key DISA STIG compliance checks for Canonical Kubernetes. This includes privileged port usage, secrets in environment variables, pod security policies, and API server port validation.

Packaged as a Snap for easy installation and cross-distro usage.

---

## 📋 Features

- ✅ **V-242383**: Emsure no user created resources exist on default namespaces
- ✅ **V-242414**: Detect user pods exposing privileged ports (<1024)
- ✅ **V-242415**: Warn if secrets are exposed in environment variables
- ✅ **V-254800**: Check for Pod Security Admission configuration
- ✅ **V-242410–V-242412**: Verify API Server port/protocol compliance
- ✅ Customizable namespace/resource configuration via `config.yaml`

---

## 📦 Snap Installation

### 🧪 Local Build (For Testing)

1. **Clone the repository**:

```bash
git clone https://github.com/yourusername/stig-checker.git
cd stig-checker
```

2. **Build the Snap**:

```bash
snapcraft
```

3. **Install the Snap**:

```bash
sudo snap install stig-checker_1.0_amd64.snap --dangerous
```

⚠️ Classic confinement is required to allow access to kubectl.

## 🚀 Usage

Before running, ensure:

- `kubectl` is installed and configured (e.g., kubectl get nodes works)
- You have a valid config.yaml in the current directory

```bash
stig-checker
```
