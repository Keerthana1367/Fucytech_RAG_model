import json

# Check golden edges
with open('datasets/reports_db/bms_1.json', encoding='utf-8') as f:
    d = json.load(f)
nodes = {n['id']: n.get('data', {}).get('label', n.get('id')) for n in d['Assets'][0]['template']['nodes']}
print('=== bms_1.json Edges ===')
for e in d['Assets'][0]['template']['edges']:
    src = nodes.get(e.get('source'), e.get('source'))
    tgt = nodes.get(e.get('target'), e.get('target'))
    print(f"{src} --[{e.get('data', {}).get('label', '')}]--> {tgt}")

print('\n=== tara_output_BMS.json Edges ===')
with open('outputs/results/tara_output_BMS.json', encoding='utf-8') as f2:
    d2 = json.load(f2)
nodes2 = {n['id']: n.get('data', {}).get('label', n.get('id')) for n in d2['Assets'][0]['template']['nodes']}
for e in d2['Assets'][0]['template']['edges']:
    src = nodes2.get(e.get('source'), e.get('source'))
    tgt = nodes2.get(e.get('target'), e.get('target'))
    print(f"{src} --[{e.get('data', {}).get('label', '')}]--> {tgt}")
