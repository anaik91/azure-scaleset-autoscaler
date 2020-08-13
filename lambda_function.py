import paramiko
from paramiko.ssh_exception import SSHException,NoValidConnectionsError
import io

def run_remote_command(ssh_host,ssh_port,ssh_user,ssh_private_key,command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ssh_host,port=ssh_port, username=ssh_user, pkey=ssh_private_key)
    except (SSHException,NoValidConnectionsError,TimeoutError):
        print('\nERROR : Issue accessing Host => {}\nFix the access issue to Continue with the Upgrade...'.format(ssh_host))
        print('\nHINT : Incorrect SSH Private Key OR SSH Username\n'.format(ssh_host))
        return False
    except FileNotFoundError:
        print('\nERROR : Private Key is not present in ==> {}\n'.format(ssh_private_key))
        return False
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('UTF-8')
    return output

def lambda_handler(event, context):
    key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxLC9tFecDt6s3gPs/xg0U/c3MpVfxmQ+QfYNQd/YtkEJz/RW
hsS0ZV0W9z/xHaDE/4QfSQzLBCvoR9kgYwRrMAVlbiKbD8YJ0o/J1IXIecutvEay
y3MwfoXaSuU+DbFmwl3lA7yulFWnIrQexxEKsAEyBPqA4TVKz90mB/54rbDuiMG/
eHn5EBPNXlOgsQYn1kfQVhorZThJ+kA17bqKgwulxRK5Z2g7eVskZARaXh4PoYCY
Wd1+17Fdy+HXLH0bLdKKC1g4yTddIIo2KOVEgpm1TnsNtiB0/vpvlpJ6ynDMBK1W
avCQqXku7GA8RgKms8uJ1X8qqUROEAB+1/8gKQIDAQABAoIBAQCKpBYj73kmFhl9
qQC90t7XrLMwqY/H9NLZhclUfKdx2ChFd/IhrreFl3dfsqePfco+XW/7+tODTju9
oTOt9+hiAfu8BRKNrMcxr37Rmbd0+nes9ZyDwd8V39292xbBaiGHsc2Cs9XO4w0b
biEfqkiBRWZvke+UTw87s6NiESIZMxYve3ag4nOsvRbzSqeTwBq322lgcIqmhXv+
l0a7lxk3g8IjZGO9CJ8EbIBhM0szm7gAzaIjfvGXheD61aWDYUr8or/gzNWPDNWS
BV0vyZtLhQvIgEbwUkFWuDvUfkG3cmEqAO8vUFzhEtwH0KNV35CBRDdo71qUOWJ0
ddPPUJsNAoGBAMYIS5KwgjcXE5v2kiqRj8r5sHcq1D33i3RHX0OlAxEqwLqFGAei
dKVuweF20DtDI1yXTQxzyvb1hPeJ72fftVzAXXhqwdrtqTemdTXj9xyPwVWeJSVT
XMl1uJPnyomInnITvfB5QGizRybUl0O8SOkS8j5bQYacINPKYQtsdR3TAoGBAP5D
4aUeJZAAelQsBg1VCTXXtU47Aa48W8uVrYdL1m5f2gkyUlBcLuYefCyLkkBDFzr2
4omxQPV5XDSC2SVcsQ3TAsjYQtnQyoJLyW1ppqJTadY7/3ASVhFVDnu5Rs1roL/f
n0wNQVIN4dkKOIIhcoy094Erofn4+l2HJB+x5QCTAoGAVJhekD9OoPH+snVWY1Dj
ODYJqB5npEEHFZkXnPH0qXS19/e7GCfR5Im30PTMZ0R66qbHhzY/0dd4AbauypTK
COE0DKiuPzOfQeKd13OWsGDImiaAf71oubbMLoKqBq6R4PGGBiAF37QWBQRzyb+4
9bfeO70H9NTlQRQG+LZQIXkCgYEAr3PZ9d16oAakYwbJ2lNOerfxpRz0iO2fjjkn
uA+t1RYRV31A7bDer+5jUz2wWuWw1wBbzBXjNEBdTuLnwm9WwapU5pDMeI8p3oU7
ZmOcF7ElfC6Ekiok9+rQhrGP2Nom36AIxSr0YxGvQdxap/k6mTua+qhIKj0TToyd
cb2Ivz8CgYEAkwb94XuXpbQ2I6JnRbmSQaqEcifQFMb+0EKM4ufXLfgWiQ0QFp/C
7728DVr3O5EYdYX2isrYvlfGsuq8s2XCtHP3zxfT7XCPVKChe+beWt9i+ArnvRMI
WK/34iabmo30m9UqZem9rFcbB3sBJsWKT2GweMiP1l9WauMuOwhJUz0=
-----END RSA PRIVATE KEY-----"""
    priv = io.StringIO(key)
    k = paramiko.RSAKey.from_private_key(priv)
    out = run_remote_command('aws-mp-pool-002-ansible-nlb-6cff2aa8ccb8a73d.elb.us-east-1.amazonaws.com',2222,'concurseci',k,'ifconfig')
    print(out)