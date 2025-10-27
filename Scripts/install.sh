#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用root用户运行此脚本！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "alpine"; then
    release="alpine"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat|rocky|alma|oracle linux"; then
    release="centos"
elif cat /proc/version | grep -Eqi "arch"; then
    release="arch"
else
    echo -e "${red}未检测到系统版本，请联系脚本作者！${plain}\n" && exit 1
fi

########################
# 参数解析
########################
VERSION_ARG=""
API_HOST_ARG=""
SERVER_ID_ARG=""
SECRET_KEY_ARG=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --api-host)
                API_HOST_ARG="$2"; shift 2 ;;
            --server-id)
                SERVER_ID_ARG="$2"; shift 2 ;;
            --secret-key)
                SECRET_KEY_ARG="$2"; shift 2 ;;
            -h|--help)
                echo "用法: $0 [版本号] [--api-host URL] [--server-id ID] [--secret-key KEY]"
                exit 0 ;;
            --*)
                echo "未知参数: $1"; exit 1 ;;
            *)
                # 兼容第一个位置参数作为版本号
                if [[ -z "$VERSION_ARG" ]]; then
                    VERSION_ARG="$1"; shift
                else
                    shift
                fi ;;
        esac
    done
}

arch=$(uname -m)

if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="arm64-v8a"
elif [[ $arch == "s390x" ]]; then
    arch="s390x"
else
    arch="64"
    echo -e "${red}检测架构失败，使用默认架构: ${arch}${plain}"
fi

if [ "$(getconf WORD_BIT)" != '32' ] && [ "$(getconf LONG_BIT)" != '64' ] ; then
    echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)，如果检测有误，请联系作者"
    exit 2
fi

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}请使用 CentOS 7 或更高版本的系统！${plain}\n" && exit 1
    fi
    if [[ ${os_version} -eq 7 ]]; then
        echo -e "${red}注意： CentOS 7 无法使用hysteria1/2协议！${plain}\n"
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}请使用 Ubuntu 16 或更高版本的系统！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}请使用 Debian 8 或更高版本的系统！${plain}\n" && exit 1
    fi
fi

install_base() {
    need_install_apt() {
        local packages=("$@")
        local missing=()
        
        # 批量检查已安装的包
        local installed_list=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | sort)
        
        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done
        
        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "安装缺失的包: ${missing[*]}"
            apt-get update -y >/dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}" >/dev/null 2>&1
        fi
    }

    need_install_yum() {
        local packages=("$@")
        local missing=()
        
        # 批量检查已安装的包
        local installed_list=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sort)
        
        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done
        
        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "安装缺失的包: ${missing[*]}"
            yum install -y "${missing[@]}" >/dev/null 2>&1
        fi
    }

    need_install_apk() {
        local packages=("$@")
        local missing=()
        
        # 批量检查已安装的包
        local installed_list=$(apk info 2>/dev/null | sort)
        
        for p in "${packages[@]}"; do
            if ! echo "$installed_list" | grep -q "^${p}$"; then
                missing+=("$p")
            fi
        done
        
        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "安装缺失的包: ${missing[*]}"
            apk add --no-cache "${missing[@]}" >/dev/null 2>&1
        fi
    }

    # 一次性安装所有必需的包
    if [[ x"${release}" == x"centos" ]]; then
        # 检查并安装 epel-release
        if ! rpm -q epel-release >/dev/null 2>&1; then
            echo "安装 EPEL 源..."
            yum install -y epel-release >/dev/null 2>&1
        fi
        need_install_yum wget curl unzip tar cronie socat ca-certificates pv
        update-ca-trust force-enable >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"alpine" ]]; then
        need_install_apk wget curl unzip tar socat ca-certificates pv
        update-ca-certificates >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"debian" ]]; then
        need_install_apt wget curl unzip tar cron socat ca-certificates pv
        update-ca-certificates >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"ubuntu" ]]; then
        need_install_apt wget curl unzip tar cron socat ca-certificates pv
        update-ca-certificates >/dev/null 2>&1 || true
    elif [[ x"${release}" == x"arch" ]]; then
        echo "更新包数据库..."
        pacman -Sy --noconfirm >/dev/null 2>&1
        # --needed 会跳过已安装的包，非常高效
        echo "安装必需的包..."
        pacman -S --noconfirm --needed wget curl unzip tar cronie socat ca-certificates pv >/dev/null 2>&1
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /usr/local/PPanel-node/ppnode ]]; then
        return 2
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        temp=$(service PPanel-node status | awk '{print $3}')
        if [[ x"${temp}" == x"started" ]]; then
            return 0
        else
            return 1
        fi
    else
        temp=$(systemctl status PPanel-node | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
        if [[ x"${temp}" == x"running" ]]; then
            return 0
        else
            return 1
        fi
    fi
}

generate_ppnode_config() {
        local api_host="$1"
        local server_id="$2"
        local secret_key="$3"

        mkdir -p /etc/PPanel-node >/dev/null 2>&1
        cat > /etc/PPanel-node/config.yml <<EOF
Log:
  # 日志等级，可选: debug, info, warn(warning), error
  Level: warn
  # 日志输出位置，可以是文件路径，留空时使用 "stdout"（标准输出）
  Output: 
  # 访问日志路径，例如logs/access.log，写none时关闭访问日志
  Access: none

Api:
  # 后端 API 地址，例如 "https://api.example.com"
  ApiHost: ${api_host}
  # 服务器唯一标识
  ServerID: ${server_id}
  # 通讯密钥，用于验证请求合法性
  SecretKey: ${secret_key}
  # 请求超时时间（单位：秒）
  Timeout: 30
EOF
        echo -e "${green}PPanel-node 配置文件生成完成,正在重新启动服务${plain}"
        if [[ x"${release}" == x"alpine" ]]; then
            service PPanel-node restart
        else
            systemctl restart PPanel-node
        fi
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}PPanel-node 重启成功${plain}"
        else
            echo -e "${red}PPanel-node 可能启动失败，请使用 ppnode log 查看日志信息${plain}"
        fi
}

install_ppnode() {
    local version_param="$1"
    if [[ -e /usr/local/PPanel-node/ ]]; then
        rm -rf /usr/local/PPanel-node/
    fi

    mkdir /usr/local/PPanel-node/ -p
    cd /usr/local/PPanel-node/

    if  [[ -z "$version_param" ]] ; then
        last_version=$(curl -Ls "https://api.github.com/repos/perfect-panel/PPanel-node/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}检测 PPanel-node 版本失败，可能是超出 Github API 限制，请稍后再试，或手动指定 PPanel-node 版本安装${plain}"
            exit 1
        fi
        echo -e "${green}检测到最新版本：${last_version}，开始安装...${plain}"
        url="https://github.com/perfect-panel/PPanel-node/releases/download/${last_version}/ppanel-node-linux-${arch}.zip"
        curl -sL "$url" | pv -s 30M -W -N "下载进度" > /usr/local/PPanel-node/ppanel-node-linux.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 PPanel-node 失败，请确保你的服务器能够下载 Github 的文件${plain}"
            exit 1
        fi
    else
    last_version=$version_param
        url="https://github.com/perfect-panel/PPanel-node/releases/download/${last_version}/ppanel-node-linux-${arch}.zip"
        curl -sL "$url" | pv -s 30M -W -N "下载进度" > /usr/local/PPanel-node/ppanel-node-linux.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 PPanel-node $1 失败，请确保此版本存在${plain}"
            exit 1
        fi
    fi

    unzip ppanel-node-linux.zip
    rm ppanel-node-linux.zip -f
    chmod +x ppnode
    mkdir /etc/PPanel-node/ -p
    cp geoip.dat /etc/PPanel-node/
    cp geosite.dat /etc/PPanel-node/
    if [[ x"${release}" == x"alpine" ]]; then
        rm /etc/init.d/PPanel-node -f
        cat <<EOF > /etc/init.d/PPanel-node
#!/sbin/openrc-run

name="PPanel-node"
description="PPanel-node"

command="/usr/local/PPanel-node/ppnode"
command_args="server"
command_user="root"

pidfile="/run/ppnode.pid"
command_background="yes"

depend() {
        need net
}
EOF
        chmod +x /etc/init.d/PPanel-node
        rc-update add PPanel-node default
        echo -e "${green}PPanel-node ${last_version}${plain} 安装完成，已设置开机自启"
    else
        rm /etc/systemd/system/PPanel-node.service -f
        cat <<EOF > /etc/systemd/system/PPanel-node.service
[Unit]
Description=PPanel-node Service
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
Group=root
Type=simple
LimitAS=infinity
LimitRSS=infinity
LimitCORE=infinity
LimitNOFILE=999999
WorkingDirectory=/usr/local/PPanel-node/
ExecStart=/usr/local/PPanel-node/ppnode server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl stop PPanel-node
        systemctl enable PPanel-node
        echo -e "${green}PPanel-node ${last_version}${plain} 安装完成，已设置开机自启"
    fi

    if [[ ! -f /etc/PPanel-node/config.yml ]]; then
        # 如果通过 CLI 传入了完整参数，则直接生成配置并跳过交互
        if [[ -n "$API_HOST_ARG" && -n "$SERVER_ID_ARG" && -n "$SECRET_KEY_ARG" ]]; then
            generate_ppnode_config "$API_HOST_ARG" "$SERVER_ID_ARG" "$SECRET_KEY_ARG"
            echo -e "${green}已根据参数生成 /etc/PPanel-node/config.yml${plain}"
            first_install=false
        else
            cp config.yml /etc/PPanel-node/
            first_install=true
        fi
    else
        if [[ x"${release}" == x"alpine" ]]; then
            service PPanel-node start
        else
            systemctl start PPanel-node
        fi
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}PPanel-node 重启成功${plain}"
        else
            echo -e "${red}PPanel-node 可能启动失败，请使用 ppnode log 查看日志信息${plain}"
        fi
        first_install=false
    fi


    curl -o /usr/bin/ppnode -Ls https://raw.githubusercontent.com/perfect-panel/PPanel-node/main/script/ppnode.sh
    chmod +x /usr/bin/ppnode

    cd $cur_dir
    rm -f install.sh
    echo "------------------------------------------"
    echo "PPanel-node 管理脚本使用方法: "
    echo "------------------------------------------"
    echo "ppnode              - 显示管理菜单 (功能更多)"
    echo "ppnode start        - 启动 PPanel-node"
    echo "ppnode stop         - 停止 PPanel-node"
    echo "ppnode restart      - 重启 PPanel-node"
    echo "ppnode status       - 查看 PPanel-node 状态"
    echo "ppnode enable       - 设置 PPanel-node 开机自启"
    echo "ppnode disable      - 取消 PPanel-node 开机自启"
    echo "ppnode log          - 查看 PPanel-node 日志"
    echo "ppnode generate     - 生成 PPanel-node 配置文件"
    echo "ppnode update       - 更新 PPanel-node"
    echo "ppnode update x.x.x - 安装 PPanel-node 指定版本"
    echo "ppnode install      - 安装 PPanel-node"
    echo "ppnode uninstall    - 卸载 PPanel-node"
    echo "ppnode version      - 查看 PPanel-node 版本"
    echo "------------------------------------------"

    if [[ $first_install == true ]]; then
        read -rp "检测到你为第一次安装 PPanel-node，是否自动生成 /etc/PPanel-node/config.yml？(y/n): " if_generate
        if [[ "$if_generate" =~ ^[Yy]$ ]]; then
            # 交互式收集参数，提供示例默认值
            read -rp "面板API地址[格式: https://example.com/]: " api_host
            api_host=${api_host:-https://example.com/}
            read -rp "服务器ID: " server_id
            server_id=${server_id:-1}
            read -rp "通讯密钥: " secret_key

            # 生成配置文件（覆盖可能从包中复制的模板）
            generate_ppnode_config "$api_host" "$server_id" "$secret_key"
        else
            echo "${green}已跳过自动生成配置。如需后续生成，可执行: ppnode generate${plain}"
        fi
    fi
}

parse_args "$@"
echo -e "${green}开始安装${plain}"
install_base
install_ppnode "$VERSION_ARG"