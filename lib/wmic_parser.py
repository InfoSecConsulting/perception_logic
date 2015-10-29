from locale import getdefaultlocale
from subprocess import PIPE, Popen


def wmic_query(domain, username, password, host, query):

  try:
    wmi_dict_lists = []
    encoding = getdefaultlocale()[1]
    wmi_query = Popen(['wmic',
                       '-U',
                       '%s/%s%%%s' % (domain, username, password),
                       '//%s' % host,
                       '%s' % query],
                      stdout=PIPE)
    wmi_reply = wmi_query.communicate()[0]
    wmi_reply_list = wmi_reply.rstrip().decode(encoding).split('\n')
    num_elements = len(wmi_reply_list) - 1
    i = 2
    while i <= num_elements:
      keys = wmi_reply_list[1].split('|')
      values = wmi_reply_list[i].split('|')
      wmi_op_dict = dict(zip(keys, values))
      wmi_dict_lists.append(wmi_op_dict)
      i += 1
    return wmi_dict_lists

  except IndexError:
    print('Something went horribly wrong, try a different query.')
    return 1
