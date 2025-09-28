import dns.resolver
import sys
import os
import requests
import ipaddress

def load_cloudflare_cidr_list():
    """加载Cloudflare CIDR列表"""
    cidr_url = "https://raw.githubusercontent.com/GuangYu-yu/ACL4SSR/refs/heads/main/Clash/Cloudflare.txt"
    cidr_list = []
    
    try:
        response = requests.get(cidr_url)
        response.raise_for_status()
        
        for line in response.text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and '/' in line:
                cidr_list.append(line)
        
        print(f"成功加载 {len(cidr_list)} 个Cloudflare CIDR范围")
        return cidr_list
    except Exception as e:
        print(f"加载Cloudflare CIDR列表失败: {e}")
        return []

def is_cloudflare_ip(ip, cidr_list):
    """检查IP是否在Cloudflare CIDR列表中"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidr_list:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in network:
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    
    return False

def get_authoritative_nameservers(domain):
    """查询域名的权威DNS服务器"""
    nameservers = []
    
    try:
        # 查询NS记录获取权威服务器
        ns_records = dns.resolver.resolve(domain, 'NS')
        for record in ns_records:
            nameservers.append(str(record))
    except dns.resolver.NoAnswer:
        # 没有NS记录，尝试查询SOA记录
        try:
            soa_records = dns.resolver.resolve(domain, 'SOA')
            for record in soa_records:
                # SOA记录中的MNAME字段通常是主权威服务器
                nameservers.append(str(record.mname))
        except dns.resolver.NoAnswer:
            pass
    except dns.resolver.NXDOMAIN:
        print(f"域名 {domain} 不存在")
    except dns.resolver.Timeout:
        print(f"查询域名 {domain} 的权威服务器超时")
    except Exception as e:
        print(f"查询域名 {domain} 的权威服务器时出错: {e}")
    
    return nameservers

def query_authoritative_nameserver(domain, nameserver, cidr_list):
    """向指定的权威DNS服务器查询域名的记录"""
    cloudflare_ips = []
    
    try:
        # 创建自定义解析器，指定权威DNS服务器
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        
        # 查询A记录（IPv4）
        try:
            a_records = resolver.resolve(domain, 'A')
            for record in a_records:
                ip = str(record)
                if is_cloudflare_ip(ip, cidr_list):
                    cloudflare_ips.append(ip)
        except dns.resolver.NoAnswer:
            pass
        
        # 查询AAAA记录（IPv6）
        try:
            aaaa_records = resolver.resolve(domain, 'AAAA')
            for record in aaaa_records:
                ip = str(record)
                if is_cloudflare_ip(ip, cidr_list):
                    cloudflare_ips.append(ip)
        except dns.resolver.NoAnswer:
            pass
            
    except dns.resolver.NXDOMAIN:
        print(f"域名 {domain} 在权威服务器 {nameserver} 上不存在")
    except dns.resolver.Timeout:
        print(f"向权威服务器 {nameserver} 查询域名 {domain} 超时")
    except Exception as e:
        print(f"向权威服务器 {nameserver} 查询域名 {domain} 时出错: {e}")
    
    return cloudflare_ips

def get_nameserver_ips(nameservers, cidr_list):
    """查询权威DNS服务器的IP地址"""
    nameserver_ips = []
    
    for nameserver in nameservers:
        try:
            # 查询权威服务器的A记录（IPv4）
            a_records = dns.resolver.resolve(nameserver, 'A')
            for record in a_records:
                ip = str(record)
                nameserver_ips.append(ip)
            
            # 查询权威服务器的AAAA记录（IPv6）
            aaaa_records = dns.resolver.resolve(nameserver, 'AAAA')
            for record in aaaa_records:
                ip = str(record)
                nameserver_ips.append(ip)
                    
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f"权威服务器 {nameserver} 不存在")
        except dns.resolver.Timeout:
            print(f"查询权威服务器 {nameserver} 超时")
        except Exception as e:
            print(f"查询权威服务器 {nameserver} 时出错: {e}")
    
    return nameserver_ips

def get_cloudflare_ips(domain, cidr_list):
    """查询域名的Cloudflare IP地址（通过权威服务器）"""
    cloudflare_ips = []
    
    # 1. 先查询域名的权威DNS服务器
    print(f"  查询权威服务器...")
    nameservers = get_authoritative_nameservers(domain)
    
    if nameservers:
        print(f"  找到权威服务器: {', '.join(nameservers)}")
        
        # 2. 查询权威服务器的IP地址
        nameserver_ips = get_nameserver_ips(nameservers, cidr_list)
        
        # 3. 向每个权威DNS服务器查询域名的记录
        for nameserver_ip in nameserver_ips:
            print(f"  向权威服务器 {nameserver_ip} 查询...")
            ips = query_authoritative_nameserver(domain, nameserver_ip, cidr_list)
            cloudflare_ips.extend(ips)
            
        # 去重
        cloudflare_ips = list(set(cloudflare_ips))
    else:
        print(f"  未找到权威服务器，使用默认DNS查询")
        # 如果没有找到权威服务器，回退到直接查询域名
        try:
            # 查询A记录（IPv4）
            a_records = dns.resolver.resolve(domain, 'A')
            for record in a_records:
                ip = str(record)
                if is_cloudflare_ip(ip, cidr_list):
                    cloudflare_ips.append(ip)
            
            # 查询AAAA记录（IPv6）
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            for record in aaaa_records:
                ip = str(record)
                if is_cloudflare_ip(ip, cidr_list):
                    cloudflare_ips.append(ip)
                    
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f"域名 {domain} 不存在")
        except dns.resolver.Timeout:
            print(f"查询域名 {domain} 超时")
        except Exception as e:
            print(f"查询域名 {domain} 时出错: {e}")
    
    return cloudflare_ips

def main():
    input_file = 'domain.txt'
    output_file = 'api.txt'
    
    # 加载Cloudflare CIDR列表
    print("正在加载Cloudflare CIDR列表...")
    cidr_list = load_cloudflare_cidr_list()
    
    if not cidr_list:
        print("无法加载Cloudflare CIDR列表，程序终止")
        return
    
    # 读取域名列表
    domains = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):  # 跳过空行和注释
                domains.append(line)
    
    if not domains:
        print("未找到有效的域名")
        return
    
    print(f"找到 {len(domains)} 个域名需要查询")
    
    # 查询每个域名的Cloudflare IP
    results = {}
    for domain in domains:
        print(f"正在查询: {domain}")
        ips = get_cloudflare_ips(domain, cidr_list)
        results[domain] = ips
        if ips:
            print(f"  Cloudflare IP: {', '.join(ips)}")
        else:
            print(f"  未找到Cloudflare IP")
    
    # 写入结果文件（只包含纯IP列表）
    with open(output_file, 'w', encoding='utf-8') as f:
        for domain, ips in results.items():
            if ips:
                for ip in ips:
                    f.write(f"{ip}\n")
    
    print(f"\n结果已保存到: {output_file}")
    
    # 统计信息
    domains_with_ips = sum(1 for ips in results.values() if ips)
    total_ips = sum(len(ips) for ips in results.values())
    
    print(f"统计信息:")
    print(f"- 总域名数: {len(domains)}")
    print(f"- 有Cloudflare IP的域名: {domains_with_ips}")
    print(f"- 总Cloudflare IP数: {total_ips}")

if __name__ == "__main__":
    main()