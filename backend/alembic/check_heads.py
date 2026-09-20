import re, os
revs = {}
for f in os.listdir('.'):
    if not f.endswith('.py'):
        continue
    src = open(f).read()
    rev = re.search(r'^revision\s*=\s*"(.+?)"', src, re.M)
    down = re.search(r'^down_revision\s*=\s*(None|\(.+?\)|"(.+?)")', src, re.M)
    if not rev:
        continue
    r = rev.group(1)
    downs = []
    if down:
        raw = down.group(1)
        if raw == 'None':
            downs = []
        elif raw.startswith('('):
            downs = re.findall(r'"(.+?)"', raw)
        else:
            downs = [down.group(2)]
    revs[r] = (downs, f)
down_set = set()
for v in revs.values():
    down_set.update(v[0])
heads = [r for r in revs if r not in down_set]
print('heads:', heads)
for h in heads:
    print(' ', h, revs[h][1])