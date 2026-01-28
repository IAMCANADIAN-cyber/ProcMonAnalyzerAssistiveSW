import re

file_path = 'ProcMon-Enterprise-Unified.ps1'

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "Id='1011'" in line:
        # Correctly fix the unescaped quotes in both 'Res' and 'Lookup' fields.
        # Current bad state: ... Res="... logs\ "Application\ Error"\ event ..." ... Lookup="... logs "Application Error" event ..." ...
        # Desired state:     ... Res="... logs\ `"Application\ Error`"\ event ..." ... Lookup="... logs `"Application Error`" event ..." ...

        # Replace unescaped quotes with backtick-escaped quotes
        line = line.replace('"Application\\ Error"', '`"Application\\ Error`"')
        line = line.replace('"Application Error"', '`"Application Error`"')

    new_lines.append(line)

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
