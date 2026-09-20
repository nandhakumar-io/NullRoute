import os
import re

versions_dir = "alembic/versions"

to_delete = [
    "F6a7b8c9d0e1_add_evidence_object_key.py",
    "V7w8x9y0z1a2_add_custom_controls.py",
    " w8x9y0z1a2b3_add_finding_provenance.py"
]

for f in to_delete:
    path = os.path.join(versions_dir, f)
    if os.path.exists(path):
        os.remove(path)
        print(f"Deleted {f}")

# read all remaining files
files = os.listdir(versions_dir)
rev_to_file = {}
down_revisions = set()
all_revisions = set()

# Special handling for pipeline controls duplicate
pipeline_path = os.path.join(versions_dir, "X9y0z1a2b3c4_add_pipeline_control_columns.py")
if os.path.exists(pipeline_path):
    with open(pipeline_path, 'r') as f:
        content = f.read()
    content = content.replace('revision = "x9y0z1a2b3c4"', 'revision = "x9y0z1a2b3c5"')
    with open(pipeline_path, 'w') as f:
        f.write(content)
    print("Fixed duplicate ID in X9...pipeline_control_columns")

def get_revisions(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    rev = None
    down = []
    # match single or tuple down_revision
    for line in content.split('\n'):
        if line.startswith("revision"):
            m = re.search(r"['\"]([^'\"]+)['\"]", line)
            if m: rev = m.group(1)
        elif line.startswith("down_revision"):
            matches = re.findall(r"['\"]([^'\"]+)['\"]", line)
            down.extend(matches)
    return rev, down

for file in os.listdir(versions_dir):
    if not file.endswith('.py'): continue
    path = os.path.join(versions_dir, file)
    rev, downs = get_revisions(path)
    if rev:
        rev_to_file[rev] = path
        all_revisions.add(rev)
        for d in downs:
            down_revisions.add(d)

heads = list(all_revisions - down_revisions)
heads.sort()
print(f"Current heads: {heads}")

if len(heads) > 1:
    print("Linearizing heads...")
    # Keep the last one as the final head, modify the down_revisions of others
    # Actually, to linearize A, B, C:
    # make C down_rev to B
    # make B down_rev to A
    
    for i in range(1, len(heads)):
        prev_head = heads[i-1]
        curr_head = heads[i]
        curr_file = rev_to_file[curr_head]
        
        with open(curr_file, 'r') as f:
            content = f.read()
        
        content = re.sub(r'down_revision\s*=\s*(None|[\'\"].+?[\'\"]|\(.*?\))', f'down_revision = "{prev_head}"', content)
        
        with open(curr_file, 'w') as f:
            f.write(content)
        print(f"Updated {curr_file} to depend on {prev_head}")

