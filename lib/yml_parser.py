import re
reg_clean = re.compile(r'[:]')

def db_info(db_yml):
  new_list = []
  with open(db_yml, 'r') as f:
    new_list += [re.sub(r':\s', ':', line.strip()) for line in f if reg_clean.search(line)]
    new_dict = dict(map(str, x.split(':')) for x in new_list)
    return new_dict

