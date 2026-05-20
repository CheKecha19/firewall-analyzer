import re

files = [
    r'C:\Users\chech\.openclaw\workspace\output\firewall_map.html',
    r'C:\Users\chech\.openclaw\workspace\output\output.html',
    r'C:\Users\chech\.openclaw\workspace\_PROJECTS\firewall-analyzer\full_report.html',
]

for fpath in files:
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            h = f.read()
        n = re.search(r'nodesData = (\[.*?\]);', h, re.DOTALL)
        print(f'{fpath}:')
        print(f'  Size: {len(h):,} bytes')
        print(f'  vis-network: {"vis-network" in h}')
        print(f'  initNetwork: {"initNetwork" in h}')
        print(f'  nodesData: {"YES" if n else "NO"}')
        if n:
            import json
            try:
                nd = json.loads(n.group(1))
                print(f'    {len(nd)} nodes')
            except:
                print('    (parse error)')
        print()
    except FileNotFoundError:
        print(f'{fpath}: NOT FOUND')
        print()
