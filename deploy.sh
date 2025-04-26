#!/bin/bash

set -a
source .env
set +a

# Colors
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

# OS check
function check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
            echo "This script is intended for Debian-based systems only. Detected OS: $ID"
            exit 1
        fi
    else
        echo "Unable to determine the operating system. This script supports only Debian-based systems."
        exit 1
    fi
}

# Detect system architecture and write to .env
function get_architecture() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            SYSTEM_ARCH="amd64"
            ;;
        aarch64)
            SYSTEM_ARCH="arm64"
            ;;
        *)
            SYSTEM_ARCH="unknown"
            ;;
    esac

    echo "Detected system architecture: $SYSTEM_ARCH"

    sed -i '/^SYSTEM_ARCH=/d' .env 2>/dev/null || true
    echo "SYSTEM_ARCH=$SYSTEM_ARCH" >> .env
}

# Welcome menu
function display_welcome() {
    echo -e "${GREEN}Hello, this is a bash script that will deploy k8s in a hard way.${RESET}"
    echo -e "${YELLOW}The prerequisites are:${RESET}"
    echo -e "${BLUE}* Your system must be a debian-like${RESET}"
    echo -e "${BLUE}* Each host should have the same user credentials${RESET}"
    echo -e "${BLUE}* The user should be in a sudo group${RESET}"
    echo -e "${BLUE}* The default text editor is $EDITOR, might be changed in the very beginning of this script${RESET}"
    echo -e "${BLUE}* In the current folder there should be a text file with a list of hosts that'll act as k8s controllers and workers${RESET}"
    echo -e "${BLUE}* If there is no such file, we generate one during the installation process${RESET}"
    echo -e "${BLUE}* The script is about to install additional software as well, if it is not installed${RESET}"
    echo -e "${CYAN}*** The original idea comes from here -> https://github.com/kelseyhightower/kubernetes-the-hard-way${RESET}"
    echo -e "${CYAN}*** Find more documentation here -> https://github.com/RComrade/k8s_cluster_via_bash/blob/master/README.md${RESET}"
    echo
}

function check_required_packages() {
     REQUIRED_PACKAGES=("wget" "curl" "nano" "openssl" "sshpass" "yq")
     MISSING_PACKAGES=()
 
     # Checking installed packages
     for PACKAGE in "${REQUIRED_PACKAGES[@]}"; do
         if ! command -v $PACKAGE &> /dev/null; then
             MISSING_PACKAGES+=($PACKAGE)
         fi
     done
 
     # if there are missing packages
     if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
         echo -e "${RED}The following required packages are missing:${RESET}"
         for PACKAGE in "${MISSING_PACKAGES[@]}"; do
             echo -e "${BLUE}$PACKAGE${RESET}"
         done
 
         echo -e "${BLUE}Installing missing packages...${RESET}"
 
         # Installation with sudo password
         echo "$SUDO_PASSWORD" | sudo -S apt-get update
         echo "$SUDO_PASSWORD" | sudo -S apt-get install -y "${MISSING_PACKAGES[@]}"
 
         # Checking if the packages are installed
         for PACKAGE in "${MISSING_PACKAGES[@]}"; do
             if ! command -v $PACKAGE &> /dev/null; then
                 echo -e "${RED}Failed to install $PACKAGE. Please check your system configuration.${RESET}"
                 exit 1
             else
                 echo -e "${GREEN}$PACKAGE was successfully installed.${RESET}"
             fi
         done
     else
         echo -e "${GREEN}All required packages are already installed.${RESET}"
     fi
 }
 
function install_kubectl() {
     KUBECTL_PATH="downloads/kubectl"
 
     # Check if the kubectl file exists in the downloads directory
     if [ ! -f "$KUBECTL_PATH" ]; then
         echo -e "${RED}File kubectl not found in downloads directory! Exiting.${RESET}"
         exit 1
     fi
 
     # Give execute permissions to the file
     chmod +x "$KUBECTL_PATH"
 
     # Copy the file to /usr/local/bin using sudo
     echo "$SUDO_PASSWORD" | sudo -S cp "$KUBECTL_PATH" /usr/local/bin/
 
     # Check if the copy operation was successful
     if [ $? -eq 0 ]; then
         echo -e "${GREEN}kubectl installed successfully!${RESET}"
     else
         echo -e "${RED}Failed to install kubectl. Please check your permissions.${RESET}"
         exit 1
     fi
 
     # Get the kubectl version, color the version numbers and remove KustomizeVersion
     kubectl version --client | sed -E 's/Client Version:/\n&/' | sed "s/ //g" \
         | sed "s/\(v[0-9]*\.[0-9]*\.[0-9]*\)/\x1b[32m\1\x1b[0m/"  # Display version in green
 } 

# Get user credentials
function get_credentials() {
    read -p "Enter the username to access the nodes: " USERNAME
    read -sp "Enter sudo password for the account: " SUDO_PASSWORD
    echo # Newline
}

function download_files() {
    local DOWNLOADS_FILE="configs/downloads.yaml"

    if [ ! -f "$DOWNLOADS_FILE" ]; then
        echo -e "${RED}File $DOWNLOADS_FILE not found! Exiting.${RESET}"
        exit 1
    fi

    echo -e "${YELLOW}Starting file downloads...${RESET}"
    mkdir -p downloads

    # Используем yq для чтения yaml-структуры
    mapfile -t entries < <(yq -r '.downloads[] | "\(.name) \(.url)"' "$DOWNLOADS_FILE")

    for entry in "${entries[@]}"; do
        name=$(awk '{print $1}' <<< "$entry")
        url=$(awk '{print $2}' <<< "$entry")
        path="downloads/$name"

        if [ -f "$path" ]; then
            echo -e "${GREEN}$name already exists. Skipping.${RESET}"
        else
            echo -e "${YELLOW}Downloading $name...${RESET}"
            if ! wget -q --show-progress --https-only --timestamping -O "$path" "$url"; then
                echo -e "${RED}Failed to download $name from $url${RESET}"
                exit 1
            fi
        fi
    done

    echo -e "${GREEN}All files downloaded successfully.${RESET}"
}

function generate_machines_list () {
    OUTPUT_FILE="configs/hosts.yaml"
    
    # Начинаем файл с nodes
    echo "nodes:" > "$OUTPUT_FILE"
    
    # Генерация контроллеров
    echo "  controllers:" >> "$OUTPUT_FILE"
    for i in $(seq 0 $(($CONTROLLER_COUNT - 1))); do
        CONTROLLER_HOSTNAME_VAR="CONTROLLER_${i}_HOSTNAME"
        CONTROLLER_IPV4_VAR="CONTROLLER_${i}_IPV4"

        CONTROLLER_HOSTNAME="${!CONTROLLER_HOSTNAME_VAR}"
        CONTROLLER_IPV4="${!CONTROLLER_IPV4_VAR}"

        # Записываем данные о контроллере в файл
        echo "    - name: ${CONTROLLER_HOSTNAME}" >> "$OUTPUT_FILE"
        echo "      ip: ${CONTROLLER_IPV4}" >> "$OUTPUT_FILE"
        echo "      hostname: ${CONTROLLER_HOSTNAME}" >> "$OUTPUT_FILE"
        echo "      fqdn: ${CONTROLLER_HOSTNAME}.${DOMAIN}" >> "$OUTPUT_FILE"
    done

    # Генерация воркеров
    echo "  workers:" >> "$OUTPUT_FILE"
    for i in $(seq 0 $(($WORKER_COUNT - 1))); do
        WORKER_HOSTNAME_VAR="WORKER_${i}_HOSTNAME"
        WORKER_IPV4_VAR="WORKER_${i}_IPV4"

        WORKER_HOSTNAME="${!WORKER_HOSTNAME_VAR}"
        WORKER_IPV4="${!WORKER_IPV4_VAR}"

        # Записываем данные о воркере в файл
        echo "    - name: ${WORKER_HOSTNAME}" >> "$OUTPUT_FILE"
        echo "      ip: ${WORKER_IPV4}" >> "$OUTPUT_FILE"
        echo "      hostname: ${WORKER_HOSTNAME}" >> "$OUTPUT_FILE"
        echo "      fqdn: ${WORKER_HOSTNAME}.${DOMAIN}" >> "$OUTPUT_FILE"
    done

    # Выводим сообщение о завершении
    echo -e "${GREEN}YAML file generated at $OUTPUT_FILE.${RESET}"
}

function check_availability() {
    # Собираем все IP-адреса из всех нод (контроллеров и воркеров)
    IP_LIST=$(yq -r '.nodes.controllers[].ip, .nodes.workers[].ip' configs/hosts.yaml)

    for IP in $IP_LIST; do
        # Пингуем узел 3 раза и подавляем вывод
        if ping -c 3 "$IP" >/dev/null 2>&1; then
            echo -e "${GREEN}[SUCCESS] Ping to $IP is successful.${RESET}"
        else
            echo -e "${RED}[FAILURE] Ping to $IP failed.${RESET}"
        fi
    done
}

function generate_etchosts() {
    # Путь к файлу для записи
    ETCHOSTS_FILE="configs/etchosts"

    # Проверяем, существует ли файл, если нет, создаём его
    if [ ! -f "$ETCHOSTS_FILE" ]; then
        echo -e "${YELLOW}File $ETCHOSTS_FILE does not exist. Creating...${RESET}"
        touch $ETCHOSTS_FILE
    fi

    # Очищаем файл, чтобы избежать дубликатов
    echo "# /etc/hosts generated from hosts.yaml" > $ETCHOSTS_FILE
    echo "# Generated on $(date)" >> $ETCHOSTS_FILE
    echo "" >> $ETCHOSTS_FILE

    # Получаем список всех нод (контроллеров и воркеров) и записываем в файл
    echo -e "${BLUE}Generating entries for nodes...${RESET}"
    yq -r '.nodes.controllers[], .nodes.workers[] | "\(.ip) \(.fqdn) \(.hostname)"' configs/hosts.yaml >> $ETCHOSTS_FILE

    # Выводим успешное сообщение
    echo -e "${GREEN}Entries generated and written to $ETCHOSTS_FILE${RESET}"
}

function distribute_etchosts() {
    # Путь к файлу etchosts
    ETCHOSTS_FILE="configs/etchosts"
    
    # Получаем список всех нод (контроллеров и воркеров) из YAML
    NODE_LIST=$(yq -r '.nodes.controllers[], .nodes.workers[] | "\(.ip) \(.fqdn)"' configs/hosts.yaml)

    # Обновляем локальный /etc/hosts
    echo -e "${BLUE}Updating local /etc/hosts...${RESET}"
    
    # Формируем временный файл для локального /etc/hosts
    TEMP_HOSTS="/tmp/hosts_temp"
    
    # Сохраняем первые две строки
    sudo sed -n "1,2p" /etc/hosts > "$TEMP_HOSTS"
    
    # Добавляем все записи из etchosts в новый файл, если их нет
    while IFS=" " read -r IP HOSTNAME; do
        # Если IP и HOSTNAME нет в файле, добавляем
        if ! grep -q "$IP" "$TEMP_HOSTS"; then
            echo "$IP $HOSTNAME" >> "$TEMP_HOSTS"
        fi
    done < "$ETCHOSTS_FILE"

    # Перезаписываем локальный /etc/hosts
    sudo mv "$TEMP_HOSTS" /etc/hosts

    echo -e "${GREEN}[SUCCESS] Local /etc/hosts updated.${RESET}"

    # Для каждой ноды добавляем в /etc/hosts на удаленной машине
    for NODE in $NODE_LIST; do
        IP=$(echo "$NODE" | cut -d ' ' -f 1)
        HOSTNAME=$(echo "$NODE" | cut -d ' ' -f 2)

        # Копируем файл на удаленную машину
        echo -e "${BLUE}Copying $ETCHOSTS_FILE to $IP...${RESET}"
        sshpass -p "$SUDO_PASSWORD" scp "$ETCHOSTS_FILE" "$USERNAME@$IP:/tmp/etchosts"

        # Команда для сохранения первых двух строк, удаляя остальные и добавляя новый файл
        echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -n "$USERNAME@$IP" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
            # Сохраняем только первые две строки
            sed -n \"1,2p\" /etc/hosts > /tmp/hosts_temp  # Сохраняем первые две строки
            cat /tmp/etchosts >> /tmp/hosts_temp  # Добавляем новый файл
            # Добавляем запись о текущем хосте, если её нет
            if ! grep -q \"$IP\" /tmp/hosts_temp; then
                echo \"$IP $HOSTNAME\" >> /tmp/hosts_temp
            fi
            mv /tmp/hosts_temp /etc/hosts  # Перезаписываем /etc/hosts
            rm -f /tmp/etchosts  # Удаляем временный файл
        '"

        echo -e "${GREEN}[SUCCESS] /etc/hosts updated on $IP.${RESET}"
    done
}


# Функция для генерации ключей CA и сертификата
function create_ca_crt_and_key() {
    # Генерация частного ключа для CA
    mkdir -p ./keys  # Создаем папку keys, если она еще не существует
    openssl genrsa -out ./keys/ca.key 4096
    openssl req -x509 -new -sha512 -noenc -key ./keys/ca.key -days 3653 -config preconfigs/ca.conf -out ./keys/ca.crt
}

# Функция для добавления записей DNS и IP в kube-api-server_alt_names
function add_controllers_to_alt_names() {
    cp "preconfigs/ca.conf" "configs/ca.conf"
    
    # Считываем IP-адреса и FQDN для всех контроллеров из hosts.yaml
    yq -r '.nodes.controllers[] | "\(.ip) \(.fqdn)"' configs/hosts.yaml | while IFS=" " read -r ip fqdn; do
        # Проверяем, есть ли уже такой IP и FQDN в ca.conf
        if ! grep -q "IP.*$ip" "configs/ca.conf" && ! grep -q "DNS.*$fqdn" "configs/ca.conf"; then
            # Находим максимальные индексы для IP и DNS
            local NEXT_IP_INDEX=$(( $(grep -oP "^IP\.\K\d+" "configs/ca.conf" | sort -n | tail -n 1) + 1 ))
            local NEXT_DNS_INDEX=$(( $(grep -oP "^DNS\.\K\d+" "configs/ca.conf" | sort -n | tail -n 1) + 1 ))

            # Добавляем запись для IP
            echo -e "IP.$NEXT_IP_INDEX = $ip" >> "configs/ca.conf"
            echo "Добавлена запись IP.$NEXT_IP_INDEX = $ip"

            # Добавляем запись для FQDN
            echo -e "DNS.$NEXT_DNS_INDEX = $fqdn" >> "configs/ca.conf"
            echo "Добавлена запись DNS.$NEXT_DNS_INDEX = $fqdn"
        else
            echo "Запись для $fqdn или $ip уже существует. Пропускаем."
        fi
    done
}

# Функция для добавления конфигурации воркеров в ca.conf
function add_workers_to_alt_names() {
    
    # Считываем информацию о воркерах из hosts.yaml с помощью yq
    yq -r '.nodes.workers[] | "\(.hostname) \(.ip)"' configs/hosts.yaml | while IFS=" " read -r WORKER_HOSTNAME IP; do
        # Проверяем, существует ли уже секция для этого воркера в ca.conf
        if grep -q "^\[$WORKER_HOSTNAME\]" "configs/ca.conf"; then
            echo "Конфигурация для $WORKER_HOSTNAME уже существует в configs/ca.conf. Пропускаем."
        else
            # Добавляем секцию конфигурации для воркера в ca.conf
            echo "" >> "configs/ca.conf"
            tee -a "configs/ca.conf" > /dev/null << EOF
[$WORKER_HOSTNAME]
distinguished_name = ${WORKER_HOSTNAME}_distinguished_name
prompt             = no
req_extensions     = ${WORKER_HOSTNAME}_req_extensions

[${WORKER_HOSTNAME}_req_extensions]
basicConstraints     = CA:FALSE
extendedKeyUsage     = clientAuth, serverAuth
keyUsage             = critical, digitalSignature, keyEncipherment
nsCertType           = client
nsComment            = "$WORKER_HOSTNAME Certificate"
subjectAltName       = DNS:$WORKER_HOSTNAME, IP:$IP
subjectKeyIdentifier = hash

[${WORKER_HOSTNAME}_distinguished_name]
CN = system:node:$WORKER_HOSTNAME
O  = system:nodes
C  = US
ST = Washington
L  = Seattle
EOF

            echo "Конфигурация для $WORKER_HOSTNAME была добавлена в configs/ca.conf."
        fi
    done
}

# Function to generate SSH keys automatically
function generate_ssh_keys() {
    # Path to store the generated SSH key (default location)
    local SSH_KEY_PATH="$HOME/.ssh/id_rsa"
    
    # Check if the key already exists
    if [ -f "$SSH_KEY_PATH" ]; then
        echo "SSH key already exists at $SSH_KEY_PATH. Skipping generation."
    else
        # Generate SSH keys with default settings (no passphrase, default location)
        echo "Generating SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_PATH" -N "" &> /dev/null
        if [ $? -eq 0 ]; then
            echo "SSH key pair generated successfully."
            echo "Private key: $SSH_KEY_PATH"
            echo "Public key: $SSH_KEY_PATH.pub"
        else
            echo "Failed to generate SSH key pair."
        fi
    fi
}

# Функция для рассылки SSH-ключей, используя IP из hosts.yaml
function distribute_ssh_keys() {
    # Считываем информацию из hosts.yaml и рассылаем ключи каждому хосту
    for i in $(seq 1 $CONTROLLER_COUNT); do
        controller_ip=$(yq -r ".nodes.controllers[$i-1].ip" configs/hosts.yaml)
        controller_fqdn=$(yq -r ".nodes.controllers[$i-1].fqdn" configs/hosts.yaml)
        
        # Добавляем контроллер в known_hosts
        echo "Adding $controller_fqdn to known_hosts..."
        ssh-keyscan -H "$controller_fqdn" >> "/home/$USERNAME/.ssh/known_hosts" 2>/dev/null
        
        # Рассылаем SSH-ключ на контроллер
        echo "Distributing SSH key to $controller_fqdn..."
        sshpass -p "$SUDO_PASSWORD" ssh-copy-id -i "/home/$USERNAME/.ssh/id_rsa.pub" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USERNAME@$controller_ip" &> /dev/null
        
        if [ $? -eq 0 ]; then
            echo "SSH key successfully copied to $controller_fqdn."
        else
            echo "Failed to copy SSH key to $controller_fqdn."
        fi
    done

    for i in $(seq 1 $WORKER_COUNT); do
        worker_ip=$(yq -r ".nodes.workers[$i-1].ip" configs/hosts.yaml)
        worker_fqdn=$(yq -r ".nodes.workers[$i-1].fqdn" configs/hosts.yaml)
        
        # Добавляем воркер в known_hosts
        echo "Adding $worker_fqdn to known_hosts..."
        ssh-keyscan -H "$worker_fqdn" >> "/home/$USERNAME/.ssh/known_hosts" 2>/dev/null
        
        # Рассылаем SSH-ключ на воркер
        echo "Distributing SSH key to $worker_fqdn..."
        sshpass -p "$SUDO_PASSWORD" ssh-copy-id -i "/home/$USERNAME/.ssh/id_rsa.pub" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USERNAME@$worker_ip" &> /dev/null
        
        if [ $? -eq 0 ]; then
            echo "SSH key successfully copied to $worker_fqdn."
        else
            echo "Failed to copy SSH key to $worker_fqdn."
        fi
    done
}

function generate_common_certs {
    # Create the directory for storing keys if it doesn't exist
    mkdir -p keys

    components=("admin" "kube-proxy" "kube-scheduler" "kube-controller-manager" "kube-api-server" "service-accounts")
    for component in "${components[@]}"; do
        echo "Generating certificate for component: $component"

        # Generate private key
        openssl genpkey -algorithm RSA -out "keys/${component}.key" &> /dev/null

        # Generate certificate signing request (CSR)
        openssl req -new \
            -key "keys/${component}.key" \
            -sha256 \
            -config "configs/ca.conf" \
            -section "${component}" \
            -out "keys/${component}.csr" &> /dev/null

        # Sign the certificate using the CA
        openssl x509 -req \
            -days 3653 \
            -in "keys/${component}.csr" \
            -copy_extensions copyall \
            -sha256 \
            -CA "keys/ca.crt" \
            -CAkey "keys/ca.key" \
            -CAcreateserial \
            -out "keys/${component}.crt" &> /dev/null

        echo "Certificate generated: keys/${component}.crt"
        echo "--------------------------------------------"
    done
}


function generate_worker_certificates() {
    for i in $(seq 1 "$WORKER_COUNT"); do
        local INDEX=$((i - 1))
        local HOSTNAME=$(yq -r ".nodes.workers[$INDEX].hostname" configs/hosts.yaml)

        echo "Generating certificate for $HOSTNAME..."

        # Generate private key
        openssl genpkey -algorithm RSA -out "keys/${HOSTNAME}.key" &> /dev/null

        # Generate certificate signing request (CSR)
        openssl req -new \
            -key "keys/${HOSTNAME}.key" \
            -sha256 \
            -config "configs/ca.conf" \
            -section "${HOSTNAME}" \
            -out "keys/${HOSTNAME}.csr" &> /dev/null

        # Sign the certificate
        openssl x509 -req \
            -days 3653 \
            -in "keys/${HOSTNAME}.csr" \
            -copy_extensions copyall \
            -sha256 \
            -CA "keys/ca.crt" \
            -CAkey "keys/ca.key" \
            -CAcreateserial \
            -out "keys/${HOSTNAME}.crt" &> /dev/null

        echo "Certificate generated: keys/${HOSTNAME}.crt"
        echo "--------------------------------------------"
    done
}

function distribute_all_certs() {
    # Distribute to controllers
    for i in $(seq 1 "$CONTROLLER_COUNT"); do
        CONTROLLER_HOSTNAME=$(yq -r ".nodes.controllers[$((i - 1))].hostname" configs/hosts.yaml)
        
        echo "Distributing certificates to $CONTROLLER_HOSTNAME..."

        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$CONTROLLER_HOSTNAME" \
            "echo $SUDO_PASSWORD | sudo -S mkdir -p /var/lib/kubelet/"

        sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no \
            keys/ca.crt keys/ca.key keys/kube-api-server.crt keys/kube-api-server.key \
            keys/service-accounts.crt keys/service-accounts.key \
            "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"

        echo "Certificates distributed to $CONTROLLER_HOSTNAME."
        echo "--------------------------------------------"
    done

    # Distribute to workers
    for i in $(seq 1 "$WORKER_COUNT"); do
        WORKER_HOSTNAME=$(yq -r ".nodes.workers[$((i - 1))].hostname" configs/hosts.yaml)

        echo "Distributing certificates to $WORKER_HOSTNAME..."

        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" \
            "echo $SUDO_PASSWORD | sudo -S mkdir -p /var/lib/kubelet/"

        sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no \
            keys/ca.crt \
            "keys/${WORKER_HOSTNAME}.crt" \
            "keys/${WORKER_HOSTNAME}.key" \
            "$USERNAME@$WORKER_HOSTNAME:/tmp/"

        sshpass -p "$SUDO_PASSWORD" ssh "$USERNAME@$WORKER_HOSTNAME" \
            "echo $SUDO_PASSWORD | sudo -S mv /tmp/ca.crt /var/lib/kubelet/"
        sshpass -p "$SUDO_PASSWORD" ssh "$USERNAME@$WORKER_HOSTNAME" \
            "echo $SUDO_PASSWORD | sudo -S mv /tmp/${WORKER_HOSTNAME}.crt /var/lib/kubelet/kubelet.crt"
        sshpass -p "$SUDO_PASSWORD" ssh "$USERNAME@$WORKER_HOSTNAME" \
            "echo $SUDO_PASSWORD | sudo -S mv /tmp/${WORKER_HOSTNAME}.key /var/lib/kubelet/kubelet.key"

        echo "Certificates distributed to $WORKER_HOSTNAME."
        echo "--------------------------------------------"
    done
}

function setup_nodes() {
    for i in $(seq 1 "$WORKER_COUNT"); do
        WORKER_HOSTNAME=$(yq -r ".nodes.workers[$((i - 1))].hostname" configs/hosts.yaml)

        echo "Setting up node: $WORKER_HOSTNAME"

        ssh "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
            mkdir -p /etc/cni/net.d /opt/cni/bin /var/lib/kubelet /var/lib/kube-proxy /var/lib/kubernetes /var/run/kubernetes &&
            mkdir -p containerd && 
            tar -xvf crictl.tar.gz && 
            tar -xvf containerd.tar.gz -C containerd && 
            tar -xvf cni-plugins.tgz -C /opt/cni/bin/ && 
            chmod +x crictl kubectl kube-proxy kubelet runc && 
            mv crictl kubectl kube-proxy kubelet runc /usr/local/bin/ && 
            mv containerd/bin/* /bin/ &&
            mv 10-bridge.conf 99-loopback.conf /etc/cni/net.d/ &&
            mkdir -p /etc/containerd/ && 
            mv containerd-config.toml /etc/containerd/config.toml && 
            mv containerd.service /etc/systemd/system/ &&
            mv kubelet-config.yaml /var/lib/kubelet/ && 
            mv kubelet.service /etc/systemd/system/ &&
            mv kube-proxy-config.yaml /var/lib/kube-proxy/ && 
            mv kube-proxy.service /etc/systemd/system/ &&
            systemctl daemon-reload && 
            systemctl enable containerd kubelet kube-proxy && 
            systemctl start containerd kubelet kube-proxy
        '"
    done
}

function generate_and_copy_encryption_config() {
    echo -e "${CYAN}Generating and distributing encryption config...${RESET}"

    # Генерация ключа
    export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
    envsubst < configs/encryption-config.yaml > encryption-config.yaml

    for i in $(seq 1 "$CONTROLLER_COUNT"); do
        CONTROLLER_HOSTNAME=$(yq -r ".nodes.controllers[$((i - 1))].hostname" configs/hosts.yaml)

        echo -e "${BLUE}Copying encryption config to $CONTROLLER_HOSTNAME...${RESET}"
        scp -o StrictHostKeyChecking=no encryption-config.yaml "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/" &> /dev/null

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Encryption config copied to $CONTROLLER_HOSTNAME.${RESET}"
        else
            echo -e "${RED}Failed to copy encryption config to $CONTROLLER_HOSTNAME.${RESET}"
        fi
    done
}


# Функция для генерации kubeconfig для воркеров
function generate_k8s_worker_configs() {
    echo -e "${BLUE}Generating kubeconfigs for workers...${RESET}"

    for i in $(seq 0 $(($WORKER_COUNT - 1))); do
        local WORKER_HOSTNAME=$(yq -r ".nodes.workers[$i].hostname" configs/hosts.yaml)
        local SERVER_URL="https://$(yq -r '.nodes.controllers[0].fqdn' configs/hosts.yaml):6443"

        echo -e "${CYAN}Generating kubeconfig for worker: $WORKER_HOSTNAME...${RESET}"

        kubectl config set-cluster kubernetes-the-hard-way \
            --certificate-authority=keys/ca.crt \
            --embed-certs=true \
            --server="$SERVER_URL" \
            --kubeconfig="configs/${WORKER_HOSTNAME}.kubeconfig" &> /dev/null

        kubectl config set-credentials system:node:${WORKER_HOSTNAME} \
            --client-certificate="keys/${WORKER_HOSTNAME}.crt" \
            --client-key="keys/${WORKER_HOSTNAME}.key" \
            --embed-certs=true \
            --kubeconfig="configs/${WORKER_HOSTNAME}.kubeconfig" &> /dev/null

        kubectl config set-context default \
            --cluster=kubernetes-the-hard-way \
            --user=system:node:${WORKER_HOSTNAME} \
            --kubeconfig="configs/${WORKER_HOSTNAME}.kubeconfig" &> /dev/null

        kubectl config use-context default \
            --kubeconfig="configs/${WORKER_HOSTNAME}.kubeconfig" &> /dev/null

        echo -e "${GREEN}Kubeconfig for worker $WORKER_HOSTNAME created successfully.${RESET}"
    done
}


# Функция для генерации kubeconfig для контроллеров
function generate_k8s_controller_configs() {
    echo -e "${BLUE}Generating kubeconfigs for controller components...${RESET}"

    local SERVER_URL="https://$(yq -r '.nodes.controllers[0].fqdn' configs/hosts.yaml):6443"

    # kube-proxy
    echo -e "${CYAN}Generating kube-proxy kubeconfig...${RESET}"
    kubectl config set-cluster kubernetes-the-hard-way \
        --certificate-authority=keys/ca.crt \
        --embed-certs=true \
        --server="$SERVER_URL" \
        --kubeconfig=configs/kube-proxy.kubeconfig &> /dev/null

    kubectl config set-credentials system:kube-proxy \
        --client-certificate=keys/kube-proxy.crt \
        --client-key=keys/kube-proxy.key \
        --embed-certs=true \
        --kubeconfig=configs/kube-proxy.kubeconfig &> /dev/null

    kubectl config set-context default \
        --cluster=kubernetes-the-hard-way \
        --user=system:kube-proxy \
        --kubeconfig=configs/kube-proxy.kubeconfig &> /dev/null

    kubectl config use-context default \
        --kubeconfig=configs/kube-proxy.kubeconfig &> /dev/null

    # kube-controller-manager
    echo -e "${CYAN}Generating kube-controller-manager kubeconfig...${RESET}"
    kubectl config set-cluster kubernetes-the-hard-way \
        --certificate-authority=keys/ca.crt \
        --embed-certs=true \
        --server="$SERVER_URL" \
        --kubeconfig=configs/kube-controller-manager.kubeconfig &> /dev/null

    kubectl config set-credentials system:kube-controller-manager \
        --client-certificate=keys/kube-controller-manager.crt \
        --client-key=keys/kube-controller-manager.key \
        --embed-certs=true \
        --kubeconfig=configs/kube-controller-manager.kubeconfig &> /dev/null

    kubectl config set-context default \
        --cluster=kubernetes-the-hard-way \
        --user=system:kube-controller-manager \
        --kubeconfig=configs/kube-controller-manager.kubeconfig &> /dev/null

    kubectl config use-context default \
        --kubeconfig=configs/kube-controller-manager.kubeconfig &> /dev/null

    # kube-scheduler
    echo -e "${CYAN}Generating kube-scheduler kubeconfig...${RESET}"
    kubectl config set-cluster kubernetes-the-hard-way \
        --certificate-authority=keys/ca.crt \
        --embed-certs=true \
        --server="$SERVER_URL" \
        --kubeconfig=configs/kube-scheduler.kubeconfig &> /dev/null

    kubectl config set-credentials system:kube-scheduler \
        --client-certificate=keys/kube-scheduler.crt \
        --client-key=keys/kube-scheduler.key \
        --embed-certs=true \
        --kubeconfig=configs/kube-scheduler.kubeconfig &> /dev/null

    kubectl config set-context default \
        --cluster=kubernetes-the-hard-way \
        --user=system:kube-scheduler \
        --kubeconfig=configs/kube-scheduler.kubeconfig &> /dev/null

    kubectl config use-context default \
        --kubeconfig=configs/kube-scheduler.kubeconfig &> /dev/null

    # admin
    echo -e "${CYAN}Generating admin kubeconfig...${RESET}"
    kubectl config set-cluster kubernetes-the-hard-way \
        --certificate-authority=keys/ca.crt \
        --embed-certs=true \
        --server="$SERVER_URL" \
        --kubeconfig=configs/admin.kubeconfig &> /dev/null

    kubectl config set-credentials admin \
        --client-certificate=keys/admin.crt \
        --client-key=keys/admin.key \
        --embed-certs=true \
        --kubeconfig=configs/admin.kubeconfig &> /dev/null

    kubectl config set-context default \
        --cluster=kubernetes-the-hard-way \
        --user=admin \
        --kubeconfig=configs/admin.kubeconfig &> /dev/null

    kubectl config use-context default \
        --kubeconfig=configs/admin.kubeconfig &> /dev/null

    echo -e "${GREEN}Controller kubeconfigs created successfully.${RESET}"
}

function distribute_kube_configs_to_workers() {
    echo -e "${BLUE}Distributing kubeconfigs to worker nodes...${RESET}"

    for i in $(seq 0 $(($WORKER_COUNT - 1))); do
        local WORKER_HOSTNAME=$(yq -r ".nodes.workers[$i].hostname" configs/hosts.yaml)

        echo -e "${CYAN}Copying configs to $WORKER_HOSTNAME...${RESET}"

        # Создание директорий с sudo через sshpass
        echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "sudo -S mkdir -p /var/lib/{kubelet,kube-proxy}"

        # Копирование kubeconfig файлов
        scp -o StrictHostKeyChecking=no configs/kube-proxy.kubeconfig "$USERNAME@$WORKER_HOSTNAME:/tmp/kube-proxy.kubeconfig"
        scp -o StrictHostKeyChecking=no configs/${WORKER_HOSTNAME}.kubeconfig "$USERNAME@$WORKER_HOSTNAME:/tmp/kubelet.kubeconfig"

        # Перемещение файлов с sudo через sshpass
        echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "sudo -S mv /tmp/kube-proxy.kubeconfig /var/lib/kube-proxy/kubeconfig"
        echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "sudo -S mv /tmp/kubelet.kubeconfig /var/lib/kubelet/kubeconfig"

        echo -e "${GREEN}Configs successfully copied to $WORKER_HOSTNAME.${RESET}"
    done
}

function distribute_kube_configs_to_controllers() {
    echo -e "${BLUE}Distributing kubeconfigs to controller nodes...${RESET}"

    for i in $(seq 0 $(($CONTROLLER_COUNT - 1))); do
        local CONTROLLER_HOSTNAME=$(yq -r ".nodes.controllers[$i].hostname" configs/hosts.yaml)

        echo -e "${CYAN}Copying configs to $CONTROLLER_HOSTNAME...${RESET}"

        # Копирование файлов через scp
        scp -o StrictHostKeyChecking=no configs/admin.kubeconfig \
            configs/kube-controller-manager.kubeconfig \
            configs/kube-scheduler.kubeconfig \
            "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"

        echo -e "${GREEN}Configs successfully copied to $CONTROLLER_HOSTNAME.${RESET}"
    done
}

function generate_and_distribute_encryption_config() {
    echo -e "${BLUE}Generating encryption-config.yaml...${RESET}"

    # Генерируем ключ
    export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

    # Генерируем файл на основе preconfigs/encryption-config.yaml
    envsubst < preconfigs/encryption-config.yaml > configs/encryption-config.yaml

    echo -e "${GREEN}Encryption config generated successfully and saved to configs/encryption-config.yaml.${RESET}"

    echo -e "${BLUE}Distributing encryption-config.yaml to all controllers...${RESET}"

    for i in $(seq 0 $(($CONTROLLER_COUNT - 1))); do
        local CONTROLLER_HOSTNAME=$(yq -r ".nodes.controllers[$i].hostname" configs/hosts.yaml)

        echo -e "${CYAN}Copying encryption config to $CONTROLLER_HOSTNAME...${RESET}"

        # Копируем файл на удаленный сервер
        sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no configs/encryption-config.yaml "$USERNAME@$CONTROLLER_HOSTNAME:/tmp/encryption-config.yaml"

        # Создаем нужную папку и перемещаем файл
        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$CONTROLLER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
            mkdir -p /var/lib/kubernetes/
            mv /tmp/encryption-config.yaml /var/lib/kubernetes/encryption-config.yaml
        '"

        echo -e "${GREEN}Encryption config deployed to $CONTROLLER_HOSTNAME.${RESET}"
    done
}

function setup_etcd() {
    echo -e "${BLUE}Installing etcd on all controllers...${RESET}"

    for i in $(seq 0 $(($CONTROLLER_COUNT - 1))); do
        CONTROLLER_HOSTNAME=$(yq -r ".nodes.controllers[$i].hostname" configs/hosts.yaml)
        CONTROLLER_IP=$(yq -r ".nodes.controllers[$i].ip" configs/hosts.yaml)

        echo -e "${CYAN}Installing etcd on $CONTROLLER_HOSTNAME...${RESET}"

        # Подготавливаем переменные окружения
        export HOSTNAME="$CONTROLLER_HOSTNAME"
        export CONTROLLER_IP="$CONTROLLER_IP"
        if [ "$SYSTEM_ARCH" = "amd64" ]; then
            export ETCD_UNSUPPORTED_ARCH=""
        else
            export ETCD_UNSUPPORTED_ARCH="$SYSTEM_ARCH"
        fi

        # Генерируем уникальный сервисный файл
        envsubst < preconfigs/units/etcd.service > configs/units/etcd-$CONTROLLER_HOSTNAME.service

        # Копируем архив и сервисный файл
        sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no downloads/etcd.tar.gz configs/units/etcd-$CONTROLLER_HOSTNAME.service "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
        
        # Выполняем установку и настройку
        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$CONTROLLER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
            mkdir -p /etc/etcd /var/lib/etcd
            chmod 700 /var/lib/etcd

            tar -xvf /home/$USERNAME/etcd.tar.gz
            mv etcd-v$ETCD_V-linux-$SYSTEM_ARCH/etcd* /usr/local/bin/
            rm -rf etcd-v$ETCD_V-linux-$SYSTEM_ARCH
            rm -f /home/$USERNAME/etcd.tar.gz

            cp /home/$USERNAME/ca.crt /home/$USERNAME/kube-api-server.key /home/$USERNAME/kube-api-server.crt /etc/etcd/

            mv -f /home/$USERNAME/etcd-$HOSTNAME.service /etc/systemd/system/etcd.service

            systemctl daemon-reload
            systemctl enable etcd

            systemctl start etcd
            sleep 10
        '"

        echo -e "${GREEN}etcd installed and enabled on $CONTROLLER_HOSTNAME.${RESET}"
    done
}


function setup_kubernetes_master() {
    echo -e "${BLUE}Setting up Kubernetes master components on all controllers...${RESET}"

    local SERVER_URL="https://$(yq -r '.nodes.controllers[0].fqdn' configs/hosts.yaml):6443"

    for i in $(seq 0 $(($CONTROLLER_COUNT - 1))); do
        local CONTROLLER_HOSTNAME=$(yq -r ".nodes.controllers[$i].hostname" configs/hosts.yaml)
        local CONTROLLER_IP=$(yq -r ".nodes.controllers[$i].ip" configs/hosts.yaml)

        echo -e "${CYAN}Setting up Kubernetes master on $CONTROLLER_HOSTNAME...${RESET}"

        # Экспортируем переменные для шаблонов
        export CONTROLLER_IP
        export SERVER_URL
        export BASE_WORKER_SUBNET
        export CLUSTER_IP_RANGE

        # Генерируем уникальные файлы для конкретного контроллера
        envsubst < preconfigs/units/kube-apiserver.service > configs/units/kube-apiserver-$CONTROLLER_HOSTNAME.service
        envsubst < preconfigs/units/kube-controller-manager.service > configs/units/kube-controller-manager-$CONTROLLER_HOSTNAME.service
        cp preconfigs/units/kube-scheduler.service configs/units/kube-scheduler.service # kube-scheduler одинаков для всех!

        # Копируем бинарники и сконфигурированные юниты
        sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no \
            downloads/kube-apiserver \
            downloads/kube-controller-manager \
            downloads/kube-scheduler \
            downloads/kubectl \
            configs/units/kube-apiserver-$CONTROLLER_HOSTNAME.service \
            configs/units/kube-controller-manager-$CONTROLLER_HOSTNAME.service \
            configs/units/kube-scheduler.service \
            configs/kube-scheduler.yaml \
            configs/kube-apiserver-to-kubelet.yaml \
            configs/encryption-config.yaml \
            "$USERNAME@$CONTROLLER_IP:/home/$USERNAME/"

        # Выполняем установку на контроллере
        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$CONTROLLER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
            mkdir -p /etc/kubernetes/config /var/lib/kubernetes

            chmod +x /home/$USERNAME/kube-apiserver /home/$USERNAME/kube-controller-manager /home/$USERNAME/kube-scheduler /home/$USERNAME/kubectl

            mv /home/$USERNAME/kube-apiserver /home/$USERNAME/kube-controller-manager /home/$USERNAME/kube-scheduler /home/$USERNAME/kubectl /usr/local/bin/

            mv /home/$USERNAME/ca.crt /home/$USERNAME/ca.key /home/$USERNAME/kube-api-server.key /home/$USERNAME/kube-api-server.crt /home/$USERNAME/service-accounts.key /home/$USERNAME/service-accounts.crt /home/$USERNAME/encryption-config.yaml /var/lib/kubernetes/

            mv /home/$USERNAME/kube-apiserver-$CONTROLLER_HOSTNAME.service /etc/systemd/system/kube-apiserver.service
            mv /home/$USERNAME/kube-controller-manager-$CONTROLLER_HOSTNAME.service /etc/systemd/system/kube-controller-manager.service
            mv /home/$USERNAME/kube-scheduler.service /etc/systemd/system/

            mv /home/$USERNAME/kube-controller-manager.kubeconfig /var/lib/kubernetes/
            mv /home/$USERNAME/kube-scheduler.kubeconfig /var/lib/kubernetes/

            mv /home/$USERNAME/kube-scheduler.yaml /etc/kubernetes/config/

            systemctl daemon-reload
            systemctl enable kube-apiserver kube-controller-manager kube-scheduler
            systemctl start kube-apiserver kube-controller-manager kube-scheduler

            sleep 10

            kubectl apply -f /home/$USERNAME/kube-apiserver-to-kubelet.yaml --kubeconfig /home/$USERNAME/admin.kubeconfig
        '"

        echo -e "${GREEN}Kubernetes master setup completed on $CONTROLLER_HOSTNAME.${RESET}"

    done
}

function generate_configs_from_templates() {
    echo -e "${BLUE}Generating configs from templates...${RESET}"

    mkdir -p configs

    find preconfigs -type f | while read -r template; do
        relative_path="${template#preconfigs/}"
        target_path="configs/$relative_path"
        target_dir=$(dirname "$target_path")

        echo -e "${CYAN}Processing $relative_path...${RESET}"

        mkdir -p "$target_dir"
        envsubst < "$template" > "$target_path"
    done

    echo -e "${GREEN}All configs generated successfully into configs/.${RESET}"
}

function setup_routes() {
    echo -e "${BLUE}Setting up static routes between nodes...${RESET}"

    # Получаем IP и Hostname всех контроллеров
    CONTROLLER_IPS=()
    for i in $(seq 0 $(($CONTROLLER_COUNT - 1))); do
        CONTROLLER_IPS+=("$(yq -r ".nodes.controllers[$i].ip" configs/hosts.yaml)")
    done

    # Получаем IP и SUBNET всех воркеров
    NODE_IPS=()
    NODE_SUBNETS=()
    for i in $(seq 0 $(($WORKER_COUNT - 1))); do
        NODE_IPS+=("$(yq -r ".nodes.workers[$i].ip" configs/hosts.yaml)")
        NODE_SUBNETS+=("$(yq -r ".nodes.workers[$i].subnet" configs/hosts.yaml)")
    done

    # Добавляем маршруты на всех контроллерах
    for SERVER_IP in "${CONTROLLER_IPS[@]}"; do
        echo -e "${CYAN}Adding routes on controller ($SERVER_IP)...${RESET}"
        for i in "${!NODE_IPS[@]}"; do
            echo -e "${YELLOW}On controller: route to ${NODE_SUBNETS[$i]} via ${NODE_IPS[$i]}${RESET}"
            sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$SERVER_IP" "echo '$SUDO_PASSWORD' | sudo -S ip route add ${NODE_SUBNETS[$i]} via ${NODE_IPS[$i]} || true"
        done
    done

    # Добавляем маршруты между воркерами
    for i in "${!NODE_IPS[@]}"; do
        NODE_IP=${NODE_IPS[$i]}
        NODE_SUBNET=${NODE_SUBNETS[$i]}

        for j in "${!NODE_IPS[@]}"; do
            if [[ $i -ne $j ]]; then
                TARGET_IP=${NODE_IPS[$j]}
                TARGET_SUBNET=${NODE_SUBNETS[$j]}
                echo -e "${YELLOW}On worker $NODE_IP: route to ${TARGET_SUBNET} via ${TARGET_IP}${RESET}"
                sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$NODE_IP" "echo '$SUDO_PASSWORD' | sudo -S ip route add ${TARGET_SUBNET} via ${TARGET_IP} || true"
            fi
        done
    done

    echo -e "${GREEN}Static routes successfully configured on all controllers and workers.${RESET}"
}

function prepare_nodes() {
    echo -e "${BLUE}Preparing worker nodes...${RESET}"

    for i in $(seq 0 $(($WORKER_COUNT - 1))); do
        local WORKER_HOSTNAME=$(yq -r ".nodes.workers[$i].hostname" configs/hosts.yaml)
        local SUBNET=$(yq -r ".nodes.workers[$i].subnet" configs/hosts.yaml)

        echo -e "${CYAN}Preparing $WORKER_HOSTNAME with subnet $SUBNET...${RESET}"

        # Экспортируем переменные для envsubst
        export SUBNET

        # Патчим конфиги специально под воркера
        envsubst < preconfigs/10-bridge.conf > configs/10-bridge-$WORKER_HOSTNAME.conf
        envsubst < preconfigs/kubelet-config.yaml > configs/kubelet-config-$WORKER_HOSTNAME.yaml

        # Копируем конфиги и файлы на воркер
        sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no \
            configs/10-bridge-$WORKER_HOSTNAME.conf \
            configs/kubelet-config-$WORKER_HOSTNAME.yaml \
            "$USERNAME@$WORKER_HOSTNAME:/home/$USERNAME/"

        # Копируем бинарники и статичные конфиги
        sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no \
            downloads/runc \
            downloads/crictl.tar.gz \
            downloads/cni-plugins.tgz \
            downloads/containerd.tar.gz \
            downloads/kubectl \
            downloads/kubelet \
            downloads/kube-proxy \
            configs/99-loopback.conf \
            configs/containerd-config.toml \
            configs/kube-proxy-config.yaml \
            configs/kubelet-config.yaml \
            configs/kube-proxy-config.yaml \
            configs/kubelet-config.yaml \
            configs/kube-proxy-config.yaml \
            configs/kube-proxy-config.yaml \
            configs/kubelet-config.yaml \
            configs/kube-proxy-config.yaml \
            configs/kubelet-config.yaml \
            configs/units/containerd.service \
            configs/units/kubelet.service \
            configs/units/kube-proxy.service \
            "$USERNAME@$WORKER_HOSTNAME:/home/$USERNAME/"

        # Подготовка системы
        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
            apt-get update
            apt-get install -y socat conntrack ipset
            swapoff -a
            swapon --show
        '"

        echo -e "${GREEN}Preparation completed for $WORKER_HOSTNAME.${RESET}"
    done
}

function setup_nodes() {
    echo -e "${BLUE}Configuring worker nodes...${RESET}"

    for i in $(seq 0 $(($WORKER_COUNT - 1))); do
        local WORKER_HOSTNAME=$(yq -r ".nodes.workers[$i].hostname" configs/hosts.yaml)

        echo -e "${CYAN}Setting up $WORKER_HOSTNAME...${RESET}"

        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
            mkdir -p /etc/cni/net.d /opt/cni/bin /var/lib/kubelet /var/lib/kube-proxy /var/lib/kubernetes /var/run/kubernetes

            mkdir -p containerd
            tar -xvf crictl.tar.gz
            tar -xvf containerd.tar.gz -C containerd
            tar -xvf cni-plugins.tgz -C /opt/cni/bin/

            chmod +x crictl kubectl kube-proxy kubelet runc
            mv crictl kubectl kube-proxy kubelet runc /usr/local/bin/
            mv containerd/bin/* /bin/

            mv 10-bridge-$WORKER_HOSTNAME.conf /etc/cni/net.d/10-bridge.conf
            mv 99-loopback.conf /etc/cni/net.d/

            mkdir -p /etc/containerd/
            mv containerd-config.toml /etc/containerd/config.toml
            mv containerd.service /etc/systemd/system/

            mv kubelet-config-$WORKER_HOSTNAME.yaml /var/lib/kubelet/kubelet-config.yaml
            mv kubelet.service /etc/systemd/system/

            mv kube-proxy-config.yaml /var/lib/kube-proxy/kube-proxy-config.yaml
            mv kube-proxy.service /etc/systemd/system/

            systemctl daemon-reload
            systemctl enable containerd kubelet kube-proxy
            systemctl start containerd kubelet kube-proxy
        '"

        echo -e "${GREEN}Node setup completed for $WORKER_HOSTNAME.${RESET}"
    done
}

function configure_kubectl() {
  echo -e "${BLUE}Configuring local kubectl context...${RESET}"

  local SERVER_URL="https://$(yq -r '.nodes.controllers[0].fqdn' configs/hosts.yaml):6443"

  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=keys/ca.crt \
    --embed-certs=true \
    --server="$SERVER_URL"

  kubectl config set-credentials admin \
    --client-certificate=keys/admin.crt \
    --client-key=keys/admin.key

  kubectl config set-context kubernetes-the-hard-way \
    --cluster=kubernetes-the-hard-way \
    --user=admin

  kubectl config use-context kubernetes-the-hard-way

  echo -e "${GREEN}kubectl configured to access the cluster via $SERVER_URL${RESET}"
}

function install_metallb() {
    echo -e "${BLUE}Installing MetalLB...${RESET}"

    local METALLB_MANIFEST="downloads/metallb.yaml"

    if [ ! -f "$METALLB_MANIFEST" ]; then
        echo -e "${RED}MetalLB manifest not found at $METALLB_MANIFEST. Please check downloads.${RESET}"
        exit 1
    fi

    # Создаем namespace для metallb (если еще нет)
    kubectl create namespace metallb-system --dry-run=client -o yaml | kubectl apply -f -

    # Применяем MetalLB манифест
    kubectl apply -f "$METALLB_MANIFEST"

    echo -e "${GREEN}MetalLB installed successfully.${RESET}"
}


check_os
get_architecture
generate_configs_from_templates
check_required_packages
install_kubectl
display_welcome
get_credentials
download_files
generate_machines_list
check_availability
generate_etchosts
add_controllers_to_alt_names
add_workers_to_alt_names
distribute_etchosts
setup_routes
generate_ssh_keys
distribute_ssh_keys
create_ca_crt_and_key
generate_common_certs
generate_worker_certificates
distribute_all_certs
generate_k8s_worker_configs
generate_k8s_controller_configs
distribute_kube_configs_to_workers
distribute_kube_configs_to_controllers
generate_and_distribute_encryption_config
setup_etcd
setup_kubernetes_master
prepare_nodes
setup_nodes
configure_kubectl
install_metallb
