import json
import os

logs = [
    'd4da0012-e4a6-4dab-bb7e-72f24a4069bf',
    'f2685574-f11b-4655-9dff-6a128fd2ab11',
    'cbf96c6d-283d-47ec-a7ec-27ff77fdbc66',
    '82fc5977-8792-4760-b22c-475e5ea44bd4'
]
base_path = r'C:\Users\r3h4n\.gemini\antigravity\brain'
recovered = 0

for log_id in logs:
    log_file = os.path.join(base_path, log_id, '.system_generated', 'logs', 'transcript_full.jsonl')
    if not os.path.exists(log_file):
        continue
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            if data.get('tool_calls'):
                for call in data['tool_calls']:
                    if call['name'] == 'write_to_file':
                        try:
                            args = call['args']
                            if isinstance(args, str):
                                args = json.loads(args)
                            target = args.get('TargetFile')
                            if target and target.endswith('.py'):
                                code = args.get('CodeContent')
                                if code:
                                    code = code.replace('from ..utils', 'from utils')
                                    with open(target, 'w', encoding='utf-8') as out_f:
                                        out_f.write(code)
                                    print(f'Recovered {target}')
                                    recovered += 1
                        except Exception as e:
                            print(f"Error parsing call: {e}")

print(f'Total recovered: {recovered}')
