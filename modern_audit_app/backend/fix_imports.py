import re

with open('app/audit/services.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace all safe_call("function_name" with safe_call(legacy_functions.function_name
pattern = r'safe_call\("(\w+)"'
replacement = r'safe_call(legacy_functions.\1'

content = re.sub(pattern, replacement, content)

with open('app/audit/services.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed all function imports in services.py")






