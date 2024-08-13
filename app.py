from flask import Flask, render_template, request
import base64
import json
import re

app = Flask(__name__)

def parse_node_input(node_input):
    node_input = node_input.replace('\n', ' ').replace('\r', ' ')
    node_input = re.sub(r'\s+', ' ', node_input)
    nodes = re.findall(r'\{[^}]*\}', node_input)
    parsed_nodes = []

    for node in nodes:
        node = node.strip().strip('{}')
        if not node:
            continue

        node_dict = {}
        items = re.split(r',\s*(?![^{}]*\})', node)
        
        for item in items:
            if ':' not in item:
                continue
            key, value = item.split(':', 1)
            key = key.strip()
            value = value.strip().strip('"')

            
            if key == 'ws-opts':
                
                ws_opts_items = re.findall(r'(\w+:\s*[^,{}]+)', value)
                for ws_item in ws_opts_items:
                    ws_key, ws_value = ws_item.split(':', 1)
                    ws_key = ws_key.strip()
                    ws_value = ws_value.strip().strip('"')
                    
                    if ws_key == 'path':
                        node_dict['ws-opts.path'] = ws_value
                        print(f"Extracted path: {node_dict['ws-opts.path']}") 
                    elif ws_key == 'headers':
                        headers_items = re.findall(r'(\w+:\s*[^,{}]+)', ws_value)
                        for header in headers_items:
                            h_key, h_value = header.split(':', 1)
                            node_dict[f'ws-opts.headers.{h_key.strip()}'] = h_value.strip().strip('"')
                continue

            node_dict[key] = value
        
        if 'port' in node_dict:
            node_dict['port'] = int(node_dict['port'])
        if 'alterId' in node_dict:
            node_dict['alterId'] = int(node_dict['alterId'])

        if 'name' not in node_dict or 'server' not in node_dict or 'type' not in node_dict:
            continue

        parsed_nodes.append(node_dict)

    return parsed_nodes

def convert_to_vmess(node):
    try:
        
        path = node.get('ws-opts.path', '')  

        vmess_node = {
            "v": "2",
            "ps": node['name'],
            "add": node['server'],
            "port": str(node['port']),
            "id": str(node['uuid']),
            "aid": str(node.get('alterId', 0)),
            "scy": node.get('cipher', 'auto'),
            "net": node.get('network', 'tcp'),
            "type": "none",
            "host": node.get('ws-opts.headers.Host', node.get('servername', "")),
            "path": path,  
            "tls": "tls" if node.get('tls', False) else ""
        }
        print(f"Converting node with path: {path}")  
        
        
        json_str = json.dumps(vmess_node, separators=(',', ':'))
        
        
        vmess_base64 = base64.b64encode(json_str.encode()).decode()
        
        
        return f"vmess://{vmess_base64}"
    except KeyError as e:
        return f"Error in VMess conversion: Missing {e} key"



def convert_to_vless(node):
    try:
        params = []
        if node.get('tls', False):
            params.append("security=tls")
        if node.get('flow', ''):
            params.append(f"flow={node['flow']}")
        if node.get('servername', ''):
            params.append(f"sni={node['servername']}")
        if node.get('ws-opts.path', ''):
            params.append(f"path={node['ws-opts.path']}")
        if node.get('ws-opts.headers.Host', ''):
            params.append(f"host={node['ws-opts.headers.Host']}")
        if node.get('client-fingerprint', ''):
            params.append(f"fp={node['client-fingerprint']}")
        
        param_str = "&".join(params)
        vless_link = f"vless://{node['uuid']}@{node['server']}:{node['port']}?{param_str}#{node['name']}"
        
        return vless_link
    except KeyError as e:
        return f"Error in VLess conversion: Missing {e} key"

def convert_to_trojan(node):
    try:
        trojan_link = f"trojan://{node['password']}@{node['server']}:{node['port']}?sni={node.get('sni', '')}#{node['name']}"
        return trojan_link
    except KeyError as e:
        return f"Error in Trojan conversion: Missing {e} key"

def convert_to_ss(node):
    try:
        ss_link = f"ss://{node['cipher']}:{node['password']}@{node['server']}:{node['port']}#{node['name']}"
        return ss_link
    except KeyError as e:
        return f"Error in Shadowsocks conversion: Missing {e} key"

def convert_to_hysteria2(node):
    try:
        hysteria2_link = (
            f"hysteria2://{node['password']}@{node['server']}:{node['port']}"
            f"?auth={node.get('auth', '')}&skip-cert-verify={str(node.get('skip-cert-verify', False)).lower()}"
            f"&udp={str(node.get('udp', False)).lower()}#{node['name']}"
        )
        return hysteria2_link
    except KeyError as e:
        return f"Error in Hysteria2 conversion: Missing {e} key"


@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        node_input = request.form['node_input']
        nodes = parse_node_input(node_input)
        
        converted_nodes = []
        
        for node in nodes:
            if node['type'] == 'ss':
                converted_nodes.append(convert_to_ss(node))
            elif node['type'] == 'vmess':
                converted_nodes.append(convert_to_vmess(node))
            elif node['type'] == 'vless':
                converted_nodes.append(convert_to_vless(node))
            elif node['type'] == 'trojan':
                converted_nodes.append(convert_to_trojan(node))
            elif node['type'] == 'hysteria2':
                converted_nodes.append(convert_to_hysteria2(node))
            else:
                converted_nodes.append(f"Unknown node type: {node['type']}")

        result = "\n".join(converted_nodes)
    
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=2786)
