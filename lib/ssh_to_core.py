from lib.cisco_cmds import SHOWVER, IOSTERMLEN0, QOUTMORE, ASATERMPAGER0
from lib.pormpts import PRIV_EXEC_MODE
from pexpect import expect, spawnu, TIMEOUT


def cisco_enable_mode(user, host, passwd, en_passwd):
  ssh_newkey = 'Are you sure you want to continue connecting (yes/no)?'
  constr = 'ssh %s@%s' % (user, host)
  child = spawnu(constr)

  ret = child.expect([TIMEOUT, ssh_newkey, '[P|p]assword:'])
  if ret == 0:
    print('[-] Error Connecting to %s' % host)
    return
  if ret == 1:
    child.sendline('yes')
    new_ret = child.expect([TIMEOUT, '[P|p]assword:'])
    if new_ret == 0:
      print('[-] Could not accept new key from %s' % host)
      return
    if new_ret == 1:
      child.sendline(passwd)

      auth = child.expect([TIMEOUT, '[P|p]assword:', '.>', '.#'])
      if auth == 0:
        print('Timed out sending user auth password to host %s' % host)
        return
      if auth == 1:
        print('User password is incorrect')
        return
      if auth == 2:
        child.sendline(SHOWVER)
        # find out what Cisco OS we are working with
        what_os = child.expect([TIMEOUT, '.IOS.', '.Adaptive.'])
        if what_os == 0:
          print('show version timed out for %s' % host)
          return

        if what_os == 1:  # if it's an IOS device
          child.sendcontrol('c')
          child.expect(PRIV_EXEC_MODE)
          child.sendline('enable')
          child.sendline(en_passwd)
          enable = child.expect([TIMEOUT, '[P|p]assword:', '.#'])
          if enable == 0:
            print('Timed out sending enable password to host %s' % host)
          if enable == 1:
            print('enable password for %s is incorrect' % host)
            return
          if enable == 2:
            child.sendline(IOSTERMLEN0)
            return child

        if what_os == 2:  # if it's an ASAOS device
          child.sendline(QOUTMORE)
          child.expect(PRIV_EXEC_MODE)
          enable = child.expect([TIMEOUT, 'Invalid password', '.#'])
          if enable == 0:
            print('Timed out sending enable password to host %s' % host)
            return
          if enable == 1:
            print('enable password for %s is incorrect' % host)
            return
          if enable == 3:
            child.sendline(ASATERMPAGER0)
            return child
      if auth == 3:
        child.sendline(SHOWVER)
        # find out what Cisco OS we are working with
        what_os = child.expect([TIMEOUT, '.IOS.', '.Adaptive.'])
        if what_os == 0:
          print('show version timed out for %s' % host)
          return

        if what_os == 1:  # if it's an IOS device
          child.sendcontrol('c')
          child.sendline(IOSTERMLEN0)
          return child

        if what_os == 2:  # if it's an ASAOS device
          child.sendline(QOUTMORE)
          child.sendline(ASATERMPAGER0)
          return child

  child.sendline(passwd)
  auth = child.expect([TIMEOUT, '[P|p]assword:', '.>', '.#'])

  if auth == 0:
    print('Timed out sending user auth password to host %s' % host)
    return
  if auth == 1:
    print('User password is incorrect')
    return
  if auth == 2:
    child.sendline('enable')
    child.sendline(en_passwd)
    enable = child.expect([TIMEOUT, '.#'])
    if enable == 0:
      print('enable password for %s is incorrect' % host)
    if enable == 1:
      child.sendline(SHOWVER)
      # find out what Cisco OS we are working with
      what_os = child.expect([TIMEOUT, '.IOS.', '.Adaptive.'])
      if what_os == 0:
        print('show version timed out for %s' % host)
        return

      if what_os == 1:  # if it's an IOS device
        child.sendcontrol('c')
        child.sendline(IOSTERMLEN0)
        return child

      if what_os == 2:  # if it's an ASAOS device
        child.sendline(QOUTMORE)
        child.sendline(ASATERMPAGER0)
        return child

  if auth == 3:
    child.sendline(SHOWVER)
    # find out what Cisco OS we are working with
    what_os = child.expect([TIMEOUT, '.IOS.', '.Adaptive.'])
    if what_os == 0:
      print('show version timed out for %s' % host)
      return

    if what_os == 1:  # if it's an IOS device
      child.sendcontrol('c')
      #child.sendline(IOSTERMLEN0)
      ready = child.expect([TIMEOUT, '.#'])
      if ready == 0:
        print('timed out for host: %s' % host)
      if ready == 1:
        return child

    if what_os == 2:  # if it's an ASAOS device
      child.sendline(QOUTMORE)
      child.sendline(ASATERMPAGER0)
      ready = child.expect([TIMEOUT, '.#'])
      if ready == 0:
        print('timed out for host: %s' % host)
      if ready == 1:
        return child

  else:
    print('Failed to login to %s' % host)
