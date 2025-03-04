#!/bin/sh

# 脚本URL变量
SCRIPT_URL="https://raw.githubusercontent.com/Zhenyi-Wang/swapchicken-xray-caddy-script/main/setup_xray_caddy.sh"

# 配置文件存储设置
CONFIG_FILE="/etc/xray-script/config.ini"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
CADDY_CONFIG_FILE="/etc/caddy/Caddyfile"

# 用于美化界面的颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 打印彩色文本的函数
print_color() {
    case "$1" in
        "red") echo -e "${RED}$2${NC}" ;;
        "green") echo -e "${GREEN}$2${NC}" ;;
        "yellow") echo -e "${YELLOW}$2${NC}" ;;
        "blue") echo -e "${BLUE}$2${NC}" ;;
        *) echo "$2" ;;
    esac
}

# 检查是否以root身份运行
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_color "red" "此脚本必须以root身份运行"
        exit 1
    fi
}

# 安装常用软件包
install_common_packages() {
    print_color "blue" "安装常用软件包..."
    
    # 设置超时时间（秒）和重试次数
    local TIMEOUT=300
    local MAX_RETRIES=3
    local RETRY_WAIT=5
    
    # 更新包索引，添加超时和错误处理
    print_color "blue" "更新包索引..."
    local retry_count=0
    while [ $retry_count -lt $MAX_RETRIES ]; do
        timeout $TIMEOUT apk update
        if [ $? -eq 0 ]; then
            break
        fi
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $MAX_RETRIES ]; then
            print_color "yellow" "更新包索引失败，${RETRY_WAIT}秒后进行第${retry_count}次重试..."
            sleep $RETRY_WAIT
        else
            print_color "red" "更新包索引失败，请检查网络连接或手动运行 'apk update'。"
            exit 1
        fi
    done

    # 定义要安装的包
    local PACKAGES="curl jq openssl caddy coreutils socat libcap"
    
    # 一次性安装所有包
    print_color "blue" "安装所需软件包: $PACKAGES"
    retry_count=0
    while [ $retry_count -lt $MAX_RETRIES ]; do
        timeout $TIMEOUT apk add $PACKAGES
        if [ $? -eq 0 ]; then
            print_color "green" "所有软件包已安装完成。"
            return 0
        fi
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $MAX_RETRIES ]; then
            print_color "yellow" "安装失败，${RETRY_WAIT}秒后进行第${retry_count}次重试..."
            sleep $RETRY_WAIT
        else
            print_color "red" "安装失败。请尝试以下方法："
            print_color "red" "1. 重新运行脚本"
            print_color "red" "2. 手动安装: apk add $PACKAGES"
            print_color "red" "3. 检查网络连接和系统资源"
            print_color "red" "4. 尝试逐个安装包："
            for package in $PACKAGES; do
                print_color "red" "   apk add $package"
            done
            exit 1
        fi
    done
}

# 获取IP地址
get_ip_addresses() {
    print_color "blue" "获取IP地址..."
    
    # 获取外网IP
    EXTERNAL_IP=$(curl -s https://api.ipify.org)
    if [ -z "$EXTERNAL_IP" ]; then
        EXTERNAL_IP=$(curl -s https://ifconfig.me)
        if [ -z "$EXTERNAL_IP" ]; then
            print_color "red" "错误: 无法获取外网IP地址。请检查网络连接。"
            exit 1
        fi
    fi
    
    # 获取内网IP
    INTERNAL_IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    if [ -z "$INTERNAL_IP" ]; then
        print_color "red" "错误: 无法获取内网IP地址。"
        exit 1
    fi
    
    print_color "green" "外网IP: $EXTERNAL_IP"
    print_color "green" "内网IP: $INTERNAL_IP"
}

# 计算可用外网端口范围
calculate_port_range() {
    print_color "blue" "计算端口范围..."
    
    # 提取内网IP的最后一个八位字节
    LAST_OCTET=$(echo $INTERNAL_IP | cut -d. -f4)
    
    # 计算端口范围
    PORT_START="${LAST_OCTET}01"
    PORT_END="${LAST_OCTET}20"
    
    print_color "green" "端口范围: $PORT_START-$PORT_END"
}

# 从用户获取主机配置
get_host_config() {
    print_color "yellow" "请先在Cloudflare中添加DNS记录："
    print_color "yellow" "1. 登录Cloudflare控制面板"
    print_color "yellow" "2. 选择您的域名"
    print_color "yellow" "3. 点击'添加记录'"
    print_color "yellow" "4. 类型选择'A'"
    print_color "yellow" "5. 名称填写您要使用的子域名"
    print_color "yellow" "6. IPv4地址填写: $EXTERNAL_IP"
    print_color "yellow" "7. 代理状态选择'已代理'"
    echo ""
    
    print_color "blue" "请输入您刚才在Cloudflare设置的完整域名:"
    read HOST_NAME
    
    if [ -z "$HOST_NAME" ]; then
        print_color "red" "错误: 未提供域名。必须提供域名。"
        print_color "red" "退出安装..."
        exit 1
    fi
    
    print_color "green" "使用域名: $HOST_NAME"
}

# 生成新的UUID
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# 安装和配置Xray
install_xray() {
    print_color "blue" "安装Xray..."
    
    # 下载并运行安装脚本
    curl -s https://raw.githubusercontent.com/XTLS/alpinelinux-install-xray/main/install-release.sh | ash
    
    # 添加Xray到启动项
    rc-update add xray
    
    # 如果UUID未设置则生成
    if [ -z "$UUID" ]; then
        UUID=$(generate_uuid)
    fi
    
    # Xray内部端口（使用固定值以简化）
    if [ -z "$XRAY_PORT" ]; then
        XRAY_PORT=10000
    fi
    
    # 配置Xray入站
    mkdir -p $XRAY_CONFIG_DIR
    cat > $XRAY_CONFIG_DIR/05_inbounds.json << EOF
{
    "inbounds": [
        {
            "port": $XRAY_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "level": 0
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/$UUID"
                }
            }
        }
    ]
}
EOF

    # 配置Xray出站
    cat > $XRAY_CONFIG_DIR/06_outbounds.json << EOF
{
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF

    # 启动Xray服务
    rc-service xray start
    
    print_color "green" "Xray已安装并配置。"
    print_color "green" "UUID: $UUID"
    print_color "green" "Xray端口: $XRAY_PORT"
}

# 配置Caddy
configure_caddy() {
    print_color "blue" "配置Caddy..."
    
    # 创建Caddy配置目录
    mkdir -p /etc/caddy
    
    # 创建证书目录
    mkdir -p /etc/caddy/certificates
    
    # 确保证书权限正确
    set_certificate_permissions
    
    # 使用主机配置Caddy
    cat > $CADDY_CONFIG_FILE << EOF
$HOST_NAME:$PORT_START {
    tls /etc/caddy/certificates/$HOST_NAME.pem /etc/caddy/certificates/$HOST_NAME.key 
    
    # 反向代理VLESS WebSocket
    reverse_proxy /$UUID localhost:$XRAY_PORT

    reverse_proxy * https://cloud.seafile.com {
        header_up Host {upstream_hostport}
    }
}
EOF

    # 设置Caddy文件权限
    chown caddy:caddy $CADDY_CONFIG_FILE
    chmod 644 $CADDY_CONFIG_FILE
    
    # 授予Caddy绑定特权端口的权限
    print_color "blue" "授予Caddy绑定特权端口的权限..."
    setcap 'cap_net_bind_service=ep' /usr/sbin/caddy
    
    # 重启Caddy服务
    rc-service caddy restart
    
    print_color "green" "Caddy已配置，并被授予绑定特权端口的权限。"
}

# 下载Cloudflare Origin Server证书
download_cf_origin_cert() {
    print_color "blue" "=== 创建Cloudflare Origin Server证书 ==="
    
    # 获取Cloudflare账户信息
    print_color "blue" "请输入Cloudflare账户信息:"
    read -p "请输入Cloudflare邮箱: " CF_EMAIL
    read -p "请输入Cloudflare API密钥（Global API Key）: " CF_API_KEY
    
    # 获取域名信息
    CF_DOMAIN=$(echo "$HOST_NAME" | awk -F. '{print $(NF-1)"."$NF}')
    read -p "您的Cloudflare域名是 $CF_DOMAIN 吗？(y/N): " confirm
    if [ "$confirm" != "y" ]; then
        read -p "请输入正确的Cloudflare域名: " CF_DOMAIN
    fi
    
    # 创建证书目录
    mkdir -p /etc/caddy/certificates/
    
    # 生成CSR和私钥
    print_color "blue" "生成证书请求(CSR)和私钥..."
    
    # 创建临时目录
    TMP_DIR=$(mktemp -d)
    
    # 创建OpenSSL配置文件
    cat > "$TMP_DIR/openssl.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $HOST_NAME

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $HOST_NAME
EOF
    
    # 生成私钥和CSR
    openssl genrsa -out "$TMP_DIR/private.key" 2048
    openssl req -new -key "$TMP_DIR/private.key" -out "$TMP_DIR/request.csr" -config "$TMP_DIR/openssl.cnf"
    
    # 读取CSR内容并格式化为JSON字符串
    CSR=$(cat "$TMP_DIR/request.csr" | sed ':a;N;$!ba;s/\n/\\n/g')
    
    # 使用curl从Cloudflare API创建Origin证书
    print_color "blue" "通过Cloudflare API创建Origin Server证书..."
    
    create_response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json" \
        --data "{
            \"csr\": \"$CSR\",
            \"hostnames\": [\"$HOST_NAME\"],
            \"request_type\": \"origin-rsa\",
            \"requested_validity\": 5475
        }")
    
    if ! echo "$create_response" | jq -e '.success' &>/dev/null; then
        error_msg=$(echo "$create_response" | jq -r '.errors[0].message')
        print_color "red" "创建证书失败。错误信息: $error_msg"
        print_color "yellow" "API响应: $(echo "$create_response" | jq -c .)"
        print_color "yellow" "请手动在Cloudflare创建Origin Server证书并放置在 /etc/caddy/certificates/$HOST_NAME.pem 和 $HOST_NAME.key"
        CERT_TYPE="manual"
        
        # 清理临时文件
        rm -rf "$TMP_DIR"
        return 1
    fi
    
    # 提取证书
    certificate=$(echo "$create_response" | jq -r '.result.certificate')
    
    # 保存证书和私钥
    echo "$certificate" > "/etc/caddy/certificates/$HOST_NAME.pem"
    cat "$TMP_DIR/private.key" > "/etc/caddy/certificates/$HOST_NAME.key"
    
    # 设置证书权限
    set_certificate_permissions
    
    # 清理临时文件
    rm -rf "$TMP_DIR"
    
    print_color "green" "证书已创建并保存到 /etc/caddy/certificates/$HOST_NAME.pem 和 $HOST_NAME.key"
    
    return 0
}

# 设置证书权限，确保caddy用户可以访问
set_certificate_permissions() {
    # 创建证书目录（如果不存在）
    mkdir -p /etc/caddy/certificates/
    
    # 确保目录权限正确
    chown -R root:caddy /etc/caddy/certificates/
    chmod 750 /etc/caddy/certificates/
    
    # 设置证书文件权限
    if [ -f "/etc/caddy/certificates/$HOST_NAME.pem" ]; then
        chown root:caddy "/etc/caddy/certificates/$HOST_NAME.pem"
        chmod 640 "/etc/caddy/certificates/$HOST_NAME.pem"
    fi
    
    if [ -f "/etc/caddy/certificates/$HOST_NAME.key" ]; then
        chown root:caddy "/etc/caddy/certificates/$HOST_NAME.key"
        chmod 640 "/etc/caddy/certificates/$HOST_NAME.key"
    fi
    
    print_color "green" "证书权限已设置，caddy用户现在可以访问证书文件。"
}

# 更新证书
update_certificate() {
    if [ "$CERT_TYPE" = "self-signed" ]; then
        generate_self_signed_cert
    elif [ "$CERT_TYPE" = "cloudflare-origin" ]; then
        # 使用已保存的Cloudflare信息更新证书
        if [ -n "$CF_EMAIL" ] && [ -n "$CF_API_KEY" ] && [ -n "$CF_DOMAIN" ]; then
            print_color "blue" "使用已保存的Cloudflare账户信息更新证书..."
            download_cf_origin_cert
        else
            print_color "yellow" "未找到保存的Cloudflare账户信息，需要重新输入..."
            download_cf_origin_cert
        fi
    else
        print_color "yellow" "您正在使用手动放置的证书，请手动更新。"
    fi
}

# 生成自签名证书
generate_self_signed_cert() {
    # 检查是否安装了openssl
    if ! command -v openssl &> /dev/null; then
        print_color "blue" "安装openssl..."
        apk add --no-cache openssl
    fi
    
    # 创建证书目录
    mkdir -p /etc/caddy/certificates/
    
    # 生成自签名证书
    print_color "blue" "生成自签名证书..."
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout "/etc/caddy/certificates/$HOST_NAME.key" \
        -out "/etc/caddy/certificates/$HOST_NAME.pem" \
        -subj "/CN=$HOST_NAME" \
        -addext "subjectAltName=DNS:$HOST_NAME"
        
    # 设置证书权限
    set_certificate_permissions
    
    print_color "green" "自签名证书已生成"
}

# 证书设置
setup_certificate() {
    print_color "blue" "=== 证书设置 ==="
    echo "1) 使用本地生成的自签名证书（浏览器会显示不安全警告）"
    echo "2) 从Cloudflare下载Origin Server证书（需要Cloudflare账户）"
    echo "3) 使用已有证书（需手动放置）"
    
    read -p "请选择证书类型 [1-3]: " cert_choice
    
    case $cert_choice in
        1)
            CERT_TYPE="self-signed"
            generate_self_signed_cert
            ;;
        2)
            CERT_TYPE="cloudflare-origin"
            download_cf_origin_cert
            ;;
        3)
            CERT_TYPE="manual"
            print_color "yellow" "请手动将证书放置在以下位置:"
            print_color "yellow" "证书路径: /etc/caddy/certificates/$HOST_NAME.pem"
            print_color "yellow" "密钥路径: /etc/caddy/certificates/$HOST_NAME.key"
            ;;
        *)
            print_color "red" "无效选择，使用默认选项（手动放置证书）"
            CERT_TYPE="manual"
            ;;
    esac
    
    # 确保证书权限正确
    set_certificate_permissions
}

# 管理证书
manage_certificate() {
    clear
    print_color "blue" "=== 管理证书 ==="
    echo "1) 查看证书信息"
    echo "2) 更新证书"
    echo "3) 切换证书类型"
    echo "4) 返回主菜单"
    
    read -p "输入您的选择 [1-4]: " choice
    
    case $choice in
        1)
            print_color "blue" "证书信息:"
            echo "证书类型: $CERT_TYPE"
            echo "证书路径: /etc/caddy/certificates/$HOST_NAME.pem"
            echo "密钥路径: /etc/caddy/certificates/$HOST_NAME.key"
            
            # 显示证书详细信息
            if [ -f "/etc/caddy/certificates/$HOST_NAME.pem" ]; then
                echo ""
                print_color "blue" "证书详细信息:"
                openssl x509 -in "/etc/caddy/certificates/$HOST_NAME.pem" -text -noout | grep -E "Subject:|Issuer:|Not Before:|Not After:"
            else
                print_color "red" "证书文件不存在"
            fi
            ;;
        2)
            update_certificate
            ;;
        3)
            setup_certificate
            ;;
        4)
            return
            ;;
        *)
            print_color "red" "无效选择。"
            ;;
    esac
}

# 将配置保存到文件
save_config() {
    mkdir -p $(dirname $CONFIG_FILE)
    cat > $CONFIG_FILE << EOF
HOST_NAME=$HOST_NAME
EXTERNAL_IP=$EXTERNAL_IP
INTERNAL_IP=$INTERNAL_IP
PORT_START=$PORT_START
PORT_END=$PORT_END
UUID=$UUID
XRAY_PORT=$XRAY_PORT
INSTALL_DATE="$(date +"%Y-%m-%d %H:%M:%S")"
CERT_TYPE=$CERT_TYPE
INSTALL_TYPE=$INSTALL_TYPE
SCRIPT_URL="$SCRIPT_URL"
EOF
    if [ "$CERT_TYPE" = "cloudflare-origin" ]; then
        echo "CF_EMAIL=$CF_EMAIL" >> $CONFIG_FILE
        echo "CF_API_KEY=$CF_API_KEY" >> $CONFIG_FILE
        echo "CF_DOMAIN=$CF_DOMAIN" >> $CONFIG_FILE
    fi
    chmod 600 $CONFIG_FILE
    print_color "green" "配置已保存到 $CONFIG_FILE"
}

# 从文件加载配置
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        . $CONFIG_FILE
        return 0
    else
        return 1
    fi
}

# 初始安装
setup() {
    install_common_packages
    get_ip_addresses
    calculate_port_range
    get_host_config
    
    # 在安装Xray和配置Caddy之前设置证书
    setup_certificate
    
    install_xray
    configure_caddy
    save_config
    
    print_color "green" "安装完成！"
    create_management_command
    print_color "green" "您现在可以使用'v2ray'命令来管理您的安装。"
    
    view_config_and_status
    
    print_color "blue" "=== 重要提示 ==="
    if [ "$CERT_TYPE" = "manual" ]; then
        print_color "yellow" "您需要将TLS证书放置在以下位置:"
        print_color "yellow" "证书路径: /etc/caddy/certificates/$HOST_NAME.pem"
        print_color "yellow" "密钥路径: /etc/caddy/certificates/$HOST_NAME.key"
        print_color "yellow" "或者您可以修改Caddy配置文件 $CADDY_CONFIG_FILE 以使用正确的证书路径。"
    fi
    
    # 检查Caddy权限设置
    if ! getcap /usr/sbin/caddy | grep -q "cap_net_bind_service=ep"; then
        print_color "red" "警告: Caddy没有绑定特权端口的权限。"
        print_color "yellow" "如果Caddy服务无法启动，请在主菜单中选择'管理Caddy服务'，然后选择'重新授予Caddy绑定特权端口的权限'。"
    else
        print_color "green" "Caddy已被授予绑定特权端口的权限，可以使用80和443端口。"
    fi
    
    # Cloudflare配置提醒
    print_color "blue" "=== Cloudflare配置提醒 ==="
    print_color "yellow" "请确保在Cloudflare控制台中完成以下配置："
    print_color "yellow" "1. DNS解析设置"
    print_color "yellow" "   - 添加A记录: $HOST_NAME -> $EXTERNAL_IP"
    print_color "yellow" "   - 确保开启Proxy状态（云朵图标为橙色）"
    print_color "yellow" "2. 创建规则"
    print_color "yellow" "   - 登录Cloudflare控制台 (https://dash.cloudflare.com)"
    print_color "yellow" "   - 选择您的域名: $HOST_NAME"
    print_color "yellow" "   - 导航到 'Rules' > 'Overview' > 'Create rule' > 'Origin Rule'"
    print_color "yellow" "   - 创建新规则:"
    print_color "yellow" "     * Name: Change Port [443-$PORT_START]"
    print_color "yellow" "     * Match against: URI Full wildcard https://$HOST_NAME/*"
    print_color "yellow" "     * Action: Rewrite port to $PORT_START"
    print_color "yellow" "     * 确保规则处于Active状态"
}

# 主菜单
main_menu() {
    while true; do
        clear
        print_color "blue" "=== Xray和Caddy管理面板 ==="
        echo "1) 查看配置和服务状态"
        echo "2) 更改配置"
        echo "3) 管理Xray服务"
        echo "4) 管理Caddy服务"
        echo "5) 管理证书"
        echo "6) 更新脚本"
        echo "7) 卸载"
        echo "8) 退出"
        
        read -p "输入您的选择 [1-8]: " choice
        
        case $choice in
            1) view_config_and_status; read -p "按Enter继续..." ;;
            2) change_config; read -p "按Enter继续..." ;;
            3) manage_xray_service; read -p "按Enter继续..." ;;
            4) manage_caddy_service; read -p "按Enter继续..." ;;
            5) manage_certificate; read -p "按Enter继续..." ;;
            6) update_script; read -p "按Enter继续..." ;;
            7) uninstall; read -p "按Enter继续..." ;;
            8) exit 0 ;;
            *) print_color "red" "无效选择。"; read -p "按Enter继续..." ;;
        esac
    done
}

# 生成VLESS连接字符串
generate_vless_link() {
    echo "vless://$UUID@$HOST_NAME:$PORT_START?encryption=none&security=tls&type=ws&path=/$UUID#$HOST_NAME"
}

# 查看配置和服务状态
view_config_and_status() {
    clear
    if load_config; then
        print_color "blue" "=== 当前配置 ==="
        print_color "yellow" "主机/域名: $HOST_NAME"
        print_color "yellow" "外网IP: $EXTERNAL_IP"
        print_color "yellow" "内网IP: $INTERNAL_IP"
        print_color "yellow" "端口范围: $PORT_START-$PORT_END"
        print_color "yellow" "Xray UUID: $UUID"
        print_color "yellow" "Xray WebSocket路径: /$UUID"
        print_color "yellow" "Xray端口: $XRAY_PORT"
        print_color "yellow" "Caddy外部端口: $PORT_START"
        print_color "yellow" "安装日期: $INSTALL_DATE"
        if [ -n "$CERT_TYPE" ]; then
            print_color "yellow" "证书类型: $CERT_TYPE"
        fi
        echo ""
        print_color "green" "VLESS连接字符串:"
        print_color "green" "$(generate_vless_link)"
        echo ""
        print_color "yellow" "=== 证书信息 ==="
        print_color "yellow" "证书位置: /etc/caddy/certificates/"
        print_color "yellow" "证书文件: $HOST_NAME.pem"
        print_color "yellow" "密钥文件: $HOST_NAME.key"
        
        if [ "$CERT_TYPE" = "manual" ]; then
            print_color "yellow" "请确保将您的TLS证书放置在上述位置，或修改Caddy配置文件 $CADDY_CONFIG_FILE 以使用正确的证书路径。"
        elif [ "$CERT_TYPE" = "self-signed" ]; then
            print_color "yellow" "使用自签名证书，浏览器可能会显示不安全警告。"
        elif [ "$CERT_TYPE" = "cloudflare-origin" ]; then
            print_color "yellow" "使用Cloudflare Origin证书，域名: $CF_DOMAIN"
            print_color "yellow" "Cloudflare邮箱: $CF_EMAIL"
            print_color "yellow" "Cloudflare API密钥: $CF_API_KEY"
        fi
        
        echo ""
        print_color "blue" "=== 服务状态 ==="
        print_color "yellow" "Xray服务状态:"
        rc-service xray status | sed 's/^/  /'
        echo ""
        print_color "yellow" "Caddy服务状态:"
        rc-service caddy status | sed 's/^/  /'
        
        # Cloudflare配置提醒
        echo ""
        print_color "blue" "=== Cloudflare配置提醒 ==="
        print_color "yellow" "请确保在Cloudflare控制台中完成以下配置："
        print_color "yellow" "1. DNS解析设置"
        print_color "yellow" "   - 添加A记录: $HOST_NAME -> $EXTERNAL_IP"
        print_color "yellow" "   - 确保开启Proxy状态（云朵图标为橙色）"
        print_color "yellow" "2. 创建规则"
        print_color "yellow" "   - 登录Cloudflare控制台 (https://dash.cloudflare.com)"
        print_color "yellow" "   - 选择您的域名: $HOST_NAME"
        print_color "yellow" "   - 导航到 'Rules' > 'Overview' > 'Create rule' > 'Origin Rule'"
        print_color "yellow" "   - 创建新规则:"
        print_color "yellow" "     * Name: Change Port [443-$PORT_START]"
        print_color "yellow" "     * Match against: URI Full wildcard https://$HOST_NAME/*"
        print_color "yellow" "     * Action: Rewrite port to $PORT_START"
        print_color "yellow" "     * 确保规则处于Active状态"
    else
        print_color "red" "未找到配置。请先运行安装。"
    fi
}

# 更改配置
change_config() {
    clear
    if ! load_config; then
        print_color "red" "未找到配置。请先运行安装。"
        return
    fi
    
    print_color "blue" "=== 更改配置 ==="
    print_color "blue" "您想更改什么？"
    echo "1) 主机/域名"
    echo "2) Xray端口"
    echo "3) 外部端口"
    echo "4) 生成新UUID"
    echo "5) 返回主菜单"
    
    read -p "输入您的选择 [1-5]: " choice
    
    case $choice in
        1)
            print_color "blue" "当前主机/域名: $HOST_NAME"
            print_color "blue" "输入新主机/域名:"
            read new_host
            if [ -n "$new_host" ]; then
                HOST_NAME=$new_host
                configure_caddy
                save_config
                print_color "green" "主机/域名更新成功。"
            else
                print_color "red" "无效输入。主机/域名未更改。"
            fi
            ;;
        2)
            print_color "blue" "当前Xray端口: $XRAY_PORT"
            print_color "blue" "输入新Xray端口:"
            read new_port
            if [ -n "$new_port" ] && [ "$new_port" -eq "$new_port" ] 2>/dev/null; then
                XRAY_PORT=$new_port
                install_xray
                configure_caddy
                save_config
                print_color "green" "Xray端口更新成功。"
            else
                print_color "red" "无效输入。Xray端口未更改。"
            fi
            ;;
        3)
            print_color "blue" "当前外部端口: $PORT_START"
            print_color "blue" "输入新外部端口:"
            read new_ext_port
            if [ -n "$new_ext_port" ] && [ "$new_ext_port" -eq "$new_ext_port" ] 2>/dev/null; then
                PORT_START=$new_ext_port
                configure_caddy
                save_config
                print_color "green" "外部端口更新成功。"
            else
                print_color "red" "无效输入。外部端口未更改。"
            fi
            ;;
        4)
            print_color "blue" "当前UUID: $UUID"
            UUID=$(generate_uuid)
            print_color "blue" "新UUID: $UUID"
            install_xray
            configure_caddy
            save_config
            print_color "green" "UUID更新成功。"
            ;;
        5)
            return
            ;;
        *)
            print_color "red" "无效选择。"
            ;;
    esac
}

# 管理Xray服务
manage_xray_service() {
    clear
    print_color "blue" "=== 管理Xray服务 ==="
    echo "1) 查看状态"
    echo "2) 启动服务"
    echo "3) 停止服务"
    echo "4) 重启服务"
    echo "5) 查看最近日志"
    echo "6) 返回主菜单"
    
    read -p "输入您的选择 [1-6]: " choice
    
    case $choice in
        1)
            print_color "blue" "Xray服务状态:"
            rc-service xray status
            ;;
        2)
            print_color "blue" "启动Xray服务..."
            rc-service xray start
            ;;
        3)
            print_color "blue" "停止Xray服务..."
            rc-service xray stop
            ;;
        4)
            print_color "blue" "重启Xray服务..."
            rc-service xray restart
            ;;
        5)
            print_color "blue" "Xray最近日志:"
            echo ""
            if [ -f "/var/log/xray/access.log" ]; then
                tail -n 50 /var/log/xray/access.log
            elif [ -f "/var/log/messages" ]; then
                grep -i xray /var/log/messages | tail -n 50
            else
                journalctl -u xray --no-pager | tail -n 50
            fi
            ;;
        6)
            return
            ;;
        *)
            print_color "red" "无效选择。"
            ;;
    esac
}

# 管理Caddy服务
manage_caddy_service() {
    clear
    print_color "blue" "=== 管理Caddy服务 ==="
    echo "1) 查看状态"
    echo "2) 启动服务"
    echo "3) 停止服务"
    echo "4) 重启服务"
    echo "5) 查看最近日志"
    echo "6) 重新授予Caddy绑定特权端口的权限"
    echo "7) 返回主菜单"
    
    read -p "输入您的选择 [1-7]: " choice
    
    case $choice in
        1) 
            print_color "blue" "Caddy服务状态:"
            rc-service caddy status
            ;;
        2)
            print_color "blue" "启动Caddy服务..."
            rc-service caddy start
            ;;
        3)
            print_color "blue" "停止Caddy服务..."
            rc-service caddy stop
            ;;
        4) 
            print_color "blue" "重启Caddy服务..."
            rc-service caddy restart
            ;;
        5)
            print_color "blue" "Caddy最近日志:"
            echo ""
            if [ -f "/var/log/caddy/access.log" ]; then
                tail -n 50 /var/log/caddy/access.log
            elif [ -f "/var/log/messages" ]; then
                grep -i caddy /var/log/messages | tail -n 50
            else
                journalctl -u caddy --no-pager | tail -n 50
            fi
            ;;
        6)
            print_color "blue" "重新授予Caddy绑定特权端口的权限..."
            setcap 'cap_net_bind_service=ep' /usr/sbin/caddy
            print_color "green" "权限已设置，Caddy现在应该可以绑定到80和443端口。"
            rc-service caddy restart
            print_color "green" "Caddy已重启以应用新权限。"
            ;;
        7)
            return
            ;;
        *)
            print_color "red" "无效选择。"
            ;;
    esac
}

# 卸载所有内容
uninstall() {
    clear
    print_color "red" "=== 卸载 ==="
    print_color "red" "警告: 这将完全删除Xray、Caddy和所有配置。"
    print_color "red" "您确定要继续吗? (y/N)"
    read confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        # 停止服务
        rc-service xray stop 2>/dev/null
        rc-service caddy stop 2>/dev/null
        
        # 从启动项中移除
        rc-update del xray default 2>/dev/null
        rc-update del caddy default 2>/dev/null
        
        # 删除Xray
        rm -rf $XRAY_CONFIG_DIR
        rm -f /usr/local/bin/xray
        
        # 删除Caddy
        apk del caddy
        rm -f $CADDY_CONFIG_FILE
        
        # 删除证书
        rm -rf /etc/caddy/certificates/
        
        # 删除配置
        rm -f $CONFIG_FILE
        
        # 删除v2ray命令和管理脚本
        rm -f /usr/local/bin/v2ray
        rm -f /usr/local/bin/xray-manager
        
        print_color "green" "卸载完成。"
        print_color "blue" "感谢使用！"
        exit 0
    else
        print_color "yellow" "取消卸载。"
    fi
}

# 更新脚本
update_script() {
    print_color "blue" "正在从 $SCRIPT_URL 更新脚本..."
    if wget -q -O /usr/local/bin/xray-manager "$SCRIPT_URL"; then
        chmod +x /usr/local/bin/xray-manager
        print_color "green" "脚本更新成功！"
        print_color "yellow" "请重新运行脚本以使用新版本。"
        exit 0
    else
        print_color "red" "脚本更新失败。"
        return 1
    fi
}

# 将当前脚本内容保存到xray-manager
create_management_command() {
    # 首先将当前脚本内容保存到xray-manager
    if [ -f "$0" ] && [ "$0" != "/dev/fd/*" ]; then
        # 如果是本地文件
        cp "$0" /usr/local/bin/xray-manager
    else
        # 如果是通过wget执行的
        wget -qO /usr/local/bin/xray-manager "$SCRIPT_URL"
    fi
    chmod +x /usr/local/bin/xray-manager

    # 创建v2ray命令
    cat > /usr/local/bin/v2ray << 'EOF'
#!/bin/sh
/bin/sh /usr/local/bin/xray-manager
EOF
    chmod +x /usr/local/bin/v2ray
    
    print_color "green" "管理命令'v2ray'已创建。"
    print_color "yellow" "由于您是通过远程下载方式运行脚本，需要重新连接终端或执行以下命令后才能使用v2ray命令："
    print_color "blue" "    source ~/.bashrc"
    print_color "blue" "或者直接运行："
    print_color "blue" "    /usr/local/bin/v2ray"
}

# 检查是首次运行还是作为管理脚本被调用
check_root
if [ "$(basename $0)" = "xray-manager" ]; then
    # 作为管理脚本被调用
    if load_config; then
        main_menu
    else
        print_color "red" "未找到配置。运行初始安装..."
        # 通过 readlink 获取 xray-manager 的真实路径
        REAL_PATH=$(readlink -f "$(command -v xray-manager)")
        if [ -L "$REAL_PATH" ] && echo "$(readlink -f "$REAL_PATH")" | grep -q "^/dev/fd/"; then
            INSTALL_TYPE="remote"
        else
            INSTALL_TYPE="local"
        fi
        setup
    fi
else
    # 首次运行
    clear
    print_color "blue" "=== Alpine Linux Xray和Caddy安装脚本 ==="
    print_color "blue" "此脚本将安装和配置Xray和Caddy。"
    
    # 检查是否已安装
    if load_config; then
        print_color "yellow" "Xray和Caddy已经安装。"
        print_color "blue" "请选择操作："
        echo "1) 退出"
        echo "2) 重新配置"
        echo "3) 更新脚本"
        read -p "您的选择 [1-3]: " choice
        
        case $choice in
            2) 
                OLD_INSTALL_TYPE=$INSTALL_TYPE
                setup
                INSTALL_TYPE=$OLD_INSTALL_TYPE
                save_config
                ;;
            3) update_script ;;
            *) exit 0 ;;
        esac
    else
        # 记录安装方式
        if echo "$0" | grep -q "^/dev/fd/"; then
            # 通过 sh <(wget -qO- url) 方式运行
            INSTALL_TYPE="remote"
        else
            # 下载脚本后执行
            INSTALL_TYPE="local"
        fi
        setup
    fi
fi
