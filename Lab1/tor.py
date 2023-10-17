import cryptography
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# RSA-OAEP Encrypting and decrypting
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from base64 import b64decode,b64encode
pubkey_dictionary = {
	"alpe": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkh11pHrMUzT0D9E1WVLwMJ2Uu9KP/wQMelB2P0kw4CMR0+6kNDKUSbxF23Ksimd0f9TqgWCkAZ375RRynR1y1GSa+GHItnM9n5rWshBbUbqN7O/4PjHrGde97mSRgsryurKuOIiKy53BF/oTqa4NaNKFx3noLlSpp++Lla9Qtf9Hv6Nl5PDeSr/7V+Uate26vyZAliPzpvcq7FMEz4RwnBcYvq7qoGaKcQTMZaHENJKaX/jrMfQEBMDy2QDIU5EYE4POIbHsFmas/iT0kDvBF9ZVo1llQZuhkhxAOpHeec8LsxqdQr7xMqzxJ+Pz4rEQvfkqoFHB3Sq0u+ZXypNDbwIDAQAB",
	"jal": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDYPsHbba2p0bRdakkF5hq3thtLlXOthSlcRIb11nigqL97nZ+/ZBaCDkvwT+jRlnA+VXIH3u0Cu+QCVXC9dxOhw3i6JUdOeG+GhtizdqqeId7pnh1/KP4EuOVXFQJy/hKdW/t21qMWsG/7NoqR1FNoFdHyu2yRIgvjR3v4Yh/blnt1mL783PtnmoWtfu4txi7qEOuMQS91u6SJEcRpYzBkabi0eMz2IxgKIDzjsQ+2BeN7pulMPoEaedZKWoMQo13vM8zeqgbUXpavf8D6YN7RtzEYx4PeP2xlkcxFUNMqx7UIiWlygAd8MX5fhmABYv0xKn/PuxMEJOk+7ndSQJ1Sx6EqbIUxtvI+S8eM67zlPP/byr8zNzYCkqgB+RF3DXOVrOpguWcFjV67x7dRoEpj2U60kvhrZID7Mya10CxkLAgl+NpvpaxaRkYN2wthycmioXGCfN7+EwEZBjMwZc1t5i1pMigkFANvbQK5vJE0innjJZIUpr2H8ZV8rkBhcV8=",
	"ANSB": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC3b7S3QFbSpDb/PUA5BXQ8L6WZKFanf/lZFL2+8F5k6TM3R1CUM7/UiBkc8BqHa9nqbMyIkUonfM7q5aZRDXl8b7qXHDYxZppYw5VJotYtkQxG3lOfOwadPB2yhVX/IXD2Io7mQHvdpG6ntwfD0UEc9dl4oCHOVVvuGMzVGV6GmKkZfXuE2ucAeO7Yvo+Of+liw/XsqvSMlcHYmGLTXxTqVskBx53oWIJaURRgdGLIoSwWj8M/KmhwskBhQ1EN08PAssRpwMUyJyPAaj3f+ZRL5ISk/lJ5rkxYLYtNoyzxy7JKAbHYkx67b65Z4r/7+WG9Q+aS02pFgOYJavun32J3MsZhoawlqe1zfjq/fmOMOFv6+l2z0ktxkd9kBMZtAke8HkYmfX1oBG9d04w9/njQNtrxEc+7S+z9igeYb1TbTOJqgDCwbI9l1T7Jp03i0k4SPVzuLt4RtV9wZ2lnvIf1ZK/v0oL8u4hRB/TVyBHnbckV0TAYAskAiJ0BJz/v36c=",
	"dpm": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCwp6J5uoGXeNEdvhPQsXlNL5W3HDGGp5OjS0k+RnbkC4bWmfhCbX2pw39+hNoaNychiwdSpRt/Y7nQ9/aIMKIb12q1EckucOdVN992uvo/F+OBMR3JBiqKa/qg9aFZ8oAUoGZtabApjo4e7gyvpTNQDCCYfY05SWJ9rwxmjlFhO5WiM+8xuwJLmbm1csBi3EGqMcPdpM+R8F4oHvtRuxJB+N0Dc+PXpL7BJPd2ON/W3Fz/iHwp4o9UNujMTf39JGhtLP45L93+fNJZb085yGwZp1IlPLjUB4HQ5Ch89sZp2VZlN6cAvsDW1bNjWsX5p/+Iz3otZXGsIAGH9N8Rp2UpYfcl1uax8lw7xnXz5WHQTI/Drtf30BXSpKmrfcg6e4CsGC3urXHDczsCtgilOI97Al8q8TM7tl+DvYMToYj8XabF0lQwD54sdJwmnAPHpUnZQCgfVasIr3aSN9oEKlqcspzT57W9A+uCm/n1d5OfcLgzvNBOvXCPdbWV+gj400M=",
	"egf": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDhtZd49XQT0yCiPA6rQ5gJ+rKDdDKkRO3H7QW+EwNChM2Evdob9AqbCt47E4PHhCs/SE/X8qq6chkT58uXM2cv4txPzceHLKRB//kvLNhpLL2y+3Tk7AY81krX3PY6xwKnska+sqhvnGujmxWsq2vdQXbxQQGrfg0zK07910+nQ52n+xmJg3eHR2n2G5y14alarbaIYYmAywjFlvU0HMA6eNxWKZ8xLvEGHa556Q/tTwN2uZeijiBBCyZp8v1ULcEU5ENFs6j5IaMHh8YAT7ftDJIdXidnpQN8DnYRTiNBIIvp1eSdZYpTSb+QQAa7N1CkPe8aXzfCEpmJbmk9Htn5rcgSNcofDIrpLcrzF8immj2vzDRPdfSBsstvzQyxBHJKmcVoTSQ2fyVDVb+yrW1NoYe9YdxuRCjrVFzWuvI4ky4oosYo2ns9Qc7Sl5+O/IrYEy1QuiUhFTlPxLMejimm+ZT7HmIgIAZrIXogWq3yf71L/fNXj5ubvrZDvNbsBc8a=",
	"RSD": "AAAAB3NzaC1yc2EAAAADAQABAAABAQC0FknfZI1mJhsD/ijmVrnuhpB/DlIrKGr1bZ1ibe/XAQUaCZeJNQGJaRWt6zRGwKHBIAykBx5o5JoNSidswGeqp7qFeG4YIvwSR0Jqxz3Miq6kp73JCp+o03i0JcHNc2zt/FbJsvyzm4w9Roxk75MBR8T3v/UfxCy0SqrlOgssxLAkdnkzycbziNPtyqc7DNnPU3cmodf+N5bgOA6/+cxgIesPsDJDPolfsTa53rbmdioiqlxVazvm3Ti1hsJJoCfsNiZqk2dq7pt0oVQDOhvKw4SnCbEW8PB41wyZcdD0RODISSxlTtBoBPdrHVZ5v0VT6ePM9CrOb/P/IM+YpHBJ",
	"lol": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC3oBYYL47vtNFh5O7xthpktHaJ/pbe691exYkaZlXkDKuyhPpTpa3j5g8j7QSK4n+5YL4gf0QBHJRptNcUhn+gMCWWzsLPByWcdntkxHt+ZYFT4xZM9Bttj9/fy40x9CTX3dixMnOJeaw15YT6HrfBe7I6Yef+7hosz9JQR92Oq0S8EMYpDuhuITSeSyYEWZOGmfUDt5/BH/Z1fiAglFXnOOIyt+yU8G6bHwVyv+WHMPTkx89ebty3hnAH92rpL90+QYMICTH6oiqpvtErlI99bTzARm+yXBgXMCzyaVdXqPGg2AQZ0EBUi1VpW6q9P+pNE+gB4ulEC/3yopgEKjfj9jm8lu87R4PTTr8Yua+MtNdrXyia2C7vHDcfFK4fCypfz8ZcGp4I8wsZ5aCqLEfkbaqR6TqRRDswSER8BY5WFcyCUF/tCJ/jE9bVtgo0l/GSfFNhklyPjowCByi4dTO0JO/TL8lb1cJAoBBd1qsjd4VSBjhWGVqTDcHSXc7N+d8=",
	"poke": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCzG1wqpoVFRHXru6ZgAtdqV+YDniXBDk4LvFEd/IP/dMNiFfSaXBvnmvCWmUsPOWFoanq4Fiz7jZD5R7zUnGxHsW7I27xN2746v+G+EnHAEwue9ykEP5sbN63vtYYsG0+11wmGQcLE/8FVRKc1iWHHLv7AHAyYklYCmYggDzUhi5PdJcSajm6FnbNMGIIM5qkza1emNseTN/lg2PhjbMovP3wfwZj/stA8uUS15V1UeRfE4dz5Wb32z180hK6c3tvKiGkjOXnZk+I4cxDkaWtxqG+Bi3yIkhpAKInxKYynM5KHR5yfTO8CPgj5MmMjAqIYZX9boCspkIfzDjleUkYrTiUopcumPp6JgeSYSRAkCtpbJKKaF8pZxNbro6rkpvH087SrWhbvbSxTDCBgnVAh8eXIp8jqiD/q2rmMEA+GZ73SgopNOya8MDkt07h8ipK25QMsRjls7u3fd8PB+b6Xp0R49EJygWWf3lYtkMsV35Vyq+TejZJGn/dQAwkKCiU=",
    "hnf": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC3g8Kx94hXjblklCYPyAt8HCgrM6aN2bYfYn8xM0CauKMFZA3d9cgt/FS9kzkjW5lvGp/w+x3LEmB2n+ZV4X/PPid+cKKqXD9kcymD6cI6Ze5mRXJQfLctiqxvtV4JPbWaDbeaJG0ru/tIUGrBaq8SxAsU6ba2Rpa/LOxPQWZRR/jFkXtgcGi5Y6g506ibnyBgXzF5YZQOrxo8gIqkD1pp7Y948Hp1fjV4g3FeDgOGdvB6lpdCY2uAxJ0PBjKANiE2cXOmx6RDzLR0a1Ijj6xsMikY5e9lPmIFySvGzVZ86cAW45Dt6pL/XMVdAdcIruWHEx9jf5cUSOdyQd3V1p99SLMxjEbjj/SO7bi/26ng3Qdaa/es7EiK8d6DGizAoJnf1lNc3su2D8xZ4L64W286a+7A9Di/+Qi4Ow8CxOi0tLfbrOLMfdclC1Yv63K9y2slzaro0ZH15btuAeZUbSNZsQQjcSKT34axfdHBRiOsN5+VLswxZxaVMcRbYH6eLGE=",
    "MV37": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDUpIAQQ5HuqXNvvTUps8Dxgho20cOlDVQbRZQRzzm07PhobNI49e/7dgJd/NnkF30YJzwSv4mgEwQ/1mAnYMJX6Ow/R6nCH9OXJoUSw/xkccuuSRtU7+1Zr9IrquuTthqMCci/sAEb4s/ARl/WOWL32cwmjXaXP/aPpegAP/fZucoYHJIQds51OpGeHmCKewdfcnkoxTTN6EOk8ejd1Fgk1ESWXLQtuNfrSEnluD3WUFvkUAEewRSYGrMk6sq/Ql7u0y+UMb7DjZgZitGplAFTpZ3e/TONqiyZZTX6PD5qbfxVfcr0ev5FEXiRuvQ539MPBXD3i5M1JeD7x8MQMoa1KSn9r8Fdi99h83nG5dSlR9ptEW3l62ZWD7+y5D8KHmSuYIVgLRP8wR0CDgJfas+vznAiu8JkrOTts+5z5y0ldnxYTXPqjCLOnXYyxw+CvHq+N+LhrFnQGJtB5F46sS4zBnNZUjYAs8ZE0LEl2WRef/9He+DjjiC5DLY1C/3IOHs=",
    "alsb": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCsIsAnPuL2k2fRp0EExnz3O66f8BGVb5g2jYET09XfS/wVmxdApDHr1BY6HqU+9rX4/vR/yRm4wygUc2FlGW5RpcRK/NXaT/ZWDwJOWiKiykbOXVz1Ew6OxYp2iu7DsCJe7sdG5RDET7SWxlV291+4u3eh0BJmJIVzDiszSpiLsI6jg2LLQ2A+FylMiXADigUpTYj7psyGdn94G+BUA6F6qmYSF3rYNtKIHDnYEQqxo4LTpHFL//7rfMNpvzc4IDNAC6O2vOBABJY2/EoOJ9W/mBveCMARcXMgo6S1j4aZjyq0UqvyOatyKiqgFm36qQ+Kv9DnYuEAvxc+2fJXtmES5gzeQWgekbSkR/8f2I51arRQK4fb4aqwRMNmLKlnspWhqKjCWHbb3Af60qgw+gThvrvXAxBUjjy39vVvIgy+wuefNflj6P1I7LQyLIRd3uYYhv/PZBfjdjhQXG3H8qrs6LDSaCGzhrIZw+2Bn5SewPjV0O7Y+EV2x1MTbR4BaoU=",
    "adri": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCtVzu2/HFhGhT+6QOyKF0gSrGvk/qQTl+UnCcj18EUpZQi/J72z5qkeH9i8lFsvHr9nqLny9vEmiU5VCSyjpSL8g4x429aQ6oXH7R9rNFS2RZTtnZo1zo28FCOks2cKzJxgWUwIcW0mGdlj3OvD79bhlzv5TV1BIcEQp3hLq6fq68cp4AknqdqbczvN6ZETPqY5KqgKj3fJFHfF+zHwbK4d0DnwvXuSnD6j7Km8h7RetAYm2UG8u5vm/Gclt7GDHWeY/JdAQb4lQxzfDWJXxkufMGo0tXFpscmZKZNG1tHEy6s76qA/yRjuOugxRX5uBJEEapPPj+E4/ov5uXgKCniiaT9/mPKWrxrpcx/b5GYx3xtbSVBcy1/+r9dhzrlXMO6HeXOUAf+Ft1jStHn/QWQdCekIvQBMhMwUIHGPuerQwa1t0MV6eJ3DcArsBa1/+/IA4yWzDfYy3eZsF4V15UarllN1ydFiudeqBcVvCWnYKQ6kYfKDay8zbJNLV1TOZU=",
    "kd01": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCwhBoKx0aV5EwOE6+6idVSRZlUD4VhPwZ5x0xLrKd8mNNy4Xzu2ch/6BCkx02Ca86k/T4btu5PgOZlqUpTbKwqG8iDbJIMtZSw9GLENdbaU45jRHDKykyrSZVZETELQtNMzhWWMgOIk4RJRXNhT0Xsdy8Vwz+0+u8F/Lkn53ohbeRpWr00dabdgt4cEGagupDQ7IIwActAgh98XCtJigohRL2thwOV00yDjQILipuBngYqe1sqHJwVwDf20pDIfmWuTiVmXyHZ4Cywuv6mTDdAKFJlZVAuKkDEvloz/28bb3I1jN7rwJ5xNoN5lczhDA6q8CxO3JeekmkVuoNyPO7bTA8G8UiIwW4+8xKWgwJ5ZbkqfgSmKMWQMdkTtY9jSyQWLiI8Rq/C7sJWeYaoVWqvQ9YGaA82nGfKIVATG93hQm7BcW3bFCt8jC8fD+9azYyRrUL9EHFAAZHd/1jSxuizNp2PU2SYsE9DaffOx0PKWGA600GrSHIz8uswf/mGPbM=",
    "MAUB": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDX0KBb4fhY2w4kyPyOpoBthmFsMVAfG6szp/RGSwIRvQgDEtQ6ZkjPTdJPvFoXvlj0iaTleiKzHVRmvXnVQY2K7XLNUZ52pfjpT504o1VGcIMGFtREu43er1za0MN5iaRHP4ixMhs1XbIByJRCH9tTE0p1d7Bbl4iEW5Klg4klBe7PkPevOg9FE99FsF7Ni0FwYAJZh+7l+015IuzuX39WfrYuTQULETmVgqrZqC2XsZAzIlhSzFv2jTm/asiRhnrwO1BMG42mHIufrhKJsLZut4mmQle5tDURsoXRjUF74Hk0eIfenmzwnJKwiekJP4PlciWaMYDLLqeDMsnvnNyjFT6t+zQfV8Fr8HCeuWIkm169zeqNoSO2Q4k3/4EWpxH/2FMsMdsXs8c6m/4opkT81oEJXHWCyseYLxfCTNDZf3JLNA2tGqrtJki7c0OsZ47sjLuR+XOZ2vmQf7I4DGm40TxlNiQss+6fXfXGSAypcJsIUSmQRTXvICM3zrq7S38=",
    "eau": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDOoViPC8KY6fEqOy0hxPdlbhYdI2d8zWvFUNg/IkV8K6IUWuJlQD+cmJpekH45/c90ZkApCk4qhymwKKFRbu4KxCmrICNGF83vNTjQF1yrBUvsduh93A1UdKidAq/NiQHv525OANzYzrDdDpKRVP8doGCff996wZthfVrGoPW9fQlKj2edAbqHWuQvlHl17uq+Y+vAjuZiWppObUmM0gq3axK9QCa7wlMhx1N8fpZJLBqSKwLC7yc+wlcpv0nhZ6oSK/rMQ6s0kaHwId0zM++WB58DzGpmmH+YV4gxv3VYROV7h+PG5aPQSfjYv3QS/jvJvpn9zjd6TIh6+zU7R2Jcg9jwW+e06lpLChep2+O1SrKBMYaiU9xjw9h81WDbBDFd4lgM+qjTck3YkGPVSFyJDAIuzFKFVcVY3UJfzB88m6Gpb9d9XavRIyCDCbZFF4F5K+Zde16tdAreH/UPtwyXs/BMvzYh5Oyv+wPGgD6HOQM61ecOiQcC3hBkBfbZy/E=",
    "JLGS": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDhVNqzQtcCowF9HU2EXmBOVrlbqruGI4lG/92Rr4gvGGpYVuVmrtCDKPUd1RGWXVDp8YUrQ2DvnG9brOidx77oHz7a8P8LeuAFn4wPFe5A66FzNnYoOrrlhictRSQjS44ufIblwduCGmBjJVx5gh0HuAw7k3xaEjgZcXTFeoOrQ7E9RSyiKrj2HJr6WDER1I+XtNtfgZP4wVJ1ojMFyTvtBbgmqm6p192kjZ/JxWRiw9dSq7ENIwtHtNvYURtaqk7jfdkuh60EKC2n3PB6ybljpgsTxCq+WTKO4FLiRMjA/d+Ls4gvGLEC6p6PtLRd96wIJ+uR80gjhmVsHgfypwdYsdpqi3jFQMoSJXtT5lZgA9hgLa5TIZAxWr90pM7YIjkkGm0GZjKkWfOqCynyh4mvm56DmjMsiNF4KFCPE1giJvaoJDMQXC/NdP6mBGW6aGVOM8wxRk3qgQwrwy6bH/lHW8HEFasWg2IvNnLvjZofmzHxW5nCatRDspZ2vRKfXUc=",
    "ivan": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDR14hvDZS7q1cZ7PTXy7jEVfLWCuUspJxc+Ei9YZKv+XQ+QlTJoyKlyxUJQ+egge+f7S7g2Z/mszpwte43auxkaePo47TfbYI5jvPebFX4jQk+mJ3/YKvbx66wfC+pT5dgeulhTA05TeUBxXMgZffDqQWPWjd6q3gQ275aic4Abk+oqKVgJZwtiZH8L9Cpz4TjYJFSSl2IMLAGE4v01MzTGEB2+Xh5wR45o/GjgFio0WwP8lN6YC1dPtIDPpNULHtfdC4n/st6RtmM9avThJTgSJfX6G01D79VEXYFnfPsABVV+ER3JoJ5AfSkK46HwSDoEk7bWTo4d2ZnuRx19/bg1BrqEPvpaGAxRnJIec5EOHSB0TBqpiY3q4nkrrWBj3ITe5L+spkyrWdDuLnTR+6F7AM6XQNZIGaAS3ZaqXCZvWoieqc8OAYVuDp0/0/YMAEZEdja7zoNkFPWX0AKu3Mz8BwyIY1dPtu/JwUysdRN5km/o7nV0MVby9tZz70joXM=",
    "cab": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDEL/O0w1oWCBBkMyM+AjsGdlpobfjf+wZ4uGp2UEiIu183gsYGUJRK0E5V6avHXcJbh8mLJ9nsDAXRMexy3B12RUU34SjlL37ByGJwKKe/zlcw7MaXAqsfYmkkwyJGS/8v0uOvF/oihz6GyblbWzFIsqekkKLOVcTOT+fFU7MiHpXW/Azna9zaGdWyUNS8GWDvI3rENIUP30rKCwvlSQGh1yDdEa4c8SrDgfEUuqdhjqzbw0D3NQkXOj4lxh5e0c/X9OtRuOsnjBZhAVBDE5syNg8gvtOsYYR195NgB0a3LaHa9SiqeyCdJOrM++4dxwxT8wgvvdxqUaPU1fsQ+GaTSHuYX3jy/jL/H+FuktVPNXtWHL72vr92x2HnyFB32LyGxgqx2GY2hGjImfqawn8NC6xKKAeSAo0xNJbmRcDwlcMpaUdVsNntJSynYoq1M86H083UsITh7j44IlbXmRnlvlFrUAYC3XQWii3ZZOGaUXiStnkESgcLRyDiykGQVOE=",
    "idi": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC6QBeWNGPvaGb/t4MHL0WQ+NhJsghL9pwV+aJDoEowKeEl3bcK5cXQijWweG2d9N/wFgrnWtD7Flk4ZInM82HhemNexXLfv9s+2yDvfeFfmJfaXwo28fMuH9ExfqUMptLIxzlBphsR68NHDa5abFlq+yEI7VXwfUGPGg3+ntjYS+Z9vRQy/N6qtcHlhAHwHjPfT16D9wlMsfvw49Ca9ttWRnsRSxWbK+pNqGO3QhJ+IOAWTIxqXCU7S6BW6cHlLyCjK/GyV6wEq4sbAoljWH1dcn4ZyP7/d8mdOHorclkW3O4SA5gheeS9dPlNiMVRGuCbJ6vUd9DV1FV23KgrgV3wd7eBChL/5bxr1X4hliOyGwSRHusXcXHXN7S6P+Z/sDb3kIIKzn2oDl92XXesNFoXdZTFcv8Pjq8trzvQulYdaksmVY0Quelk7LaI6uEqr599fcbQrBnHrylcQXJvR3Zzxvgj/ZK2M+y6r7L7hMc9ds8Ih9Qe65Bpoeg/QZnxld108=",
    "DALN": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDjT/g48aaFE3518ncYRvScAKhpOI2MDX/8OxACoYzKRvzAiavDgaLE4rM2tYVc2WHuy05QGiFe1IHiX7ypcqwRZQDsxZ7y2o2wRsykdgLEQdJttaW+mpx5OLHDmzH5k6Qpvtbj9B0bxwbIsgO58gX/s3n2D/Ub1A0aPhXg4WkpD7mq6LK19ccM6bz0S79M2xihl2vKf0XG0ZzOTDJm18h8yyquPITWaQvsxfk/YbCnbGzjFwgLLn3co11lxDwzS+RleW5qmVaSQPHSwIO+mZZgboWR9bz2P3qpP2NgIgiUuTwU6rMCHrpDoAzSZaU19ahmKiazyKzIO9agFuaeo8wZVD5TMPislirGdq8maiKumXjmd0/ZcrxUiHwzwgFdfMSNkk3x5uU/xffHUTUf8oL9ciIsJf1XfKptHQs6299TNtS+4L9e2q5zmsnVNq5XqrZQwX49rViyQO+PA0QnAlnwhKcF2IILgx8XFrjvIjyTZTbL6gndnE+apFSlfl7RBqM=",
    "SNR8": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCgklgDdqIPFX3+FEcUAz4khtwrfRHFOWPL48XZkxcMJkWhV0y0v4pZ2eBrwJIxQw058pk+JnnDu8CJGnaXPReHPA50OQzbpkbt/ncIOJ35qQC8ek69cQGpccnK2yjI1K7eXS/dXD1qAH9O/ez2vR23jWbZhHBSsrYgQzH1zOLql5nMQtc4YaPR6g3WUcm+QvR8zJq+W3EIYR8qQmq9PbC2zPNDpXSe5vnbqQV+yacC6qRZdcPVnBXJXhiVCn4KFRd4PwTIyP5IAvzi4rmYko6g8mGfLdXTtuVoVz0tfW/W9ajSft/q+jXuQB8rcehzbqO/+fBmtwAS904BVjRnrmRWQdriHWTXOIRnTj8tRS6FbH7v/JsbFONkn+LxZAfd12B/SQVMOBGyZ63aLkqE2gmjDBq64OkvW1zeMxEurtxcEpgDkFj7tZqKEjlzrogHTtLM+BPt0d3bjtzJJ/L7gFnVxrM5tK4v+CM7O6AVdoxbdjjE2QZEcj0756MzuwpsjmM=",
    "dhbo": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDupUvldN0vwz5qSJXbKi2oZbfUr5ViMThyb91lq0hqY7sKdvfXP3ArZGgbT1f6sjB3ptCdXfmrFhpPdI4KxQNiDTQ+ZkmV3y64SwpgEIwcrWSoyfI6mrQtFrdlripAL02IJk237WYf94CfWcxxg3W3et8mxCHF7RNjGFIjZu8J5x151QfhwLeFv9b5AlfhmGRe7GB4VP0P2rpOGTXOOB3sgV/u6wBUSimynR8aSoTsN1rwTQP2hmYtkFuIY4Xo3bhSB52LK76hcn7WO53ZkQKXiyJGgsMel+O+CNezFN0WFd5nkSFgPo9lwzofD/2/hqxQkw2yqJSyzF07pD924Nd7Qc/8Nk3N6DEKeEU33/PbJ2aVsSfV5bhWaT5TrOmMvCXIYctEyYcnN+VD2Kc3mJZuCtFBDjSFnuFbFDeZndwJV1cOhOK+yDCUkOYABpD9fC85bkzs23ch/usPAbP7uQw5De4WuvRgw4p2hFIts0jXYhnFpdBW8eRbSo2LKcGJWfs=",
    "dfp": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC2jDdDOSZFNhUzVnVPaHLpGfcQaAotoSplZfvaogKmamkn1KkbOELL+vkdNeQa/KP5n+cnd727UHom+r989rtsNT+0YvXJb02LiJefECElX7Voqgd/OvP2+lIOdp+w4j4xz0vaAIr1YyPV3Ftp+noh47Y/Xf8Q3YhwinQoFbCy2DsWFU3ssnHOOeHrBLOxMy0bI7I7uBnzu38DVbpcrITlZFe+jyUzcDirwNztL+7Kon5zvFL5zJDSW1aL5nI2J/NQbeV7NsWI6O1aup9RXBht7dwxAJYdClramesbMlhaITzrSBVcvQRJSYjgNSCVYS7pDmzrvl+XokgJ2Bppo7Z0YszoZUHiUjxKWi35j6qwJdvV+OIRYzIlMAA1aQO22K6KJiWSUAged4ikps8N+QZtZpQVUfOnT+1qwEqYXI6Pzs2XsXRByhlnGZOdGx1w6QuaYeu7UekIdL4TH8/AvviAkX4X2zDgFkJN1xJPy2T3zb387bCu7T0+5iky6w1UHS0=",
    "pepe": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDKh5VLb0lvQ4LJZQ3Hw4xaZY6Q3h6uVroeqgOpzAng6r1EWsat6cIM9ScbcuFbSkRZS4hVhdyLy07W14zW1i9rFDUEY1SYneSa5F2slnLGtrtgCCu7jm3YBI3ISm1qVoRNdZTekAoFxOOou7wSfzWcjprFDM/spgPjbm9LIqEgEqOtB9m5vPjtT3YaympGiY1Z7bfrGI8sfo97q0F+KyYXjROuRJWGOqOVndx1AL84eXoEv3Afirh09VRd+JjymQFkEOg5QiKRh+KGh5mexMU9kt39aJDwc242BQGrdGP/7E1olqYeSUHLnYHtvYRqIG+hc7/b7N9UcavJZjNOegPAql7M3/aIbuLSnscTPLhl9z74aa4uJ4vFG10xb92NQrlbB42JpbHSOFeAcZYG0ZrWtR4gTI+H4b4UMECm7TuU6x9+NXXlR4uA5oaRxIGoCpFV1K8RD5G5aJG00OU7HmrZB8kP1V/cO9cIfyjH5HEqyNewg6JuBL1UCSBi60M9Z3U=",
    "luis": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDbbWnImsKURmjVnrJb1avzlv3kXwDK+OrRdYYJ1PUeyIQyghbWfvlnMKsDunXkhlFykVMNdyyp4jknbzzZbkxCoEzajrDBfPREtFryp1djRoxt43XeiTa6E68sLlZGvcLiZXFISAzwJ6PzzJkDzqf7tsIET54rBk/oPnUnECbxkEVB+hxVkBmH6nyE8RSU+B7dhGGmqcsuHh6xVW2MBLd4NZH1iKYnHf7MiJdLMrrm4OIHmLoKKq0Qh64w6Mlge6EpneQN8nXTZChzMXyIk+wfk54Egnbx8RzeSG8C3OxerNqtNCCQu3N67t1nQ2XUXb7AEZpO3qX/xKMU81h7pHdZi0qz+L5fbxgj58Rc57p5wFFrBaRNfvNB7ltxePMrdmJTK6LhUlO0uFYIZ3atVvSxRJQBrUCaZ3wjPJ/2WFlCjfezq4EMhy9NmRqqtLtkrKrwHmbZFHzRo1yxfGrYMu9udbRWII7yvVPEU+DFnT/XQwiI1uQPsvErwhGmjQkBDvE=",
    "juan": "AAAAB3NzaC1yc2EAAAADAQABAAABgQCbLBDkbZgR7HyK6mJyctpe7h0Mk7y47Dre1TLXvWR7HKS6tnHcmkr1mpaSGs1RC/ZNO9jt/AZW0o8NEfvxu8nZ1czBhboE2kOpXxrUPKYZ5DKD6zre9RzGlGk3LpqW69eR+jvAhDGpKikG1vTya/lJVI00r/L3+257xVbqVTOhyO7MUaWMI0KNEeIsxYT1X+d0OA4c8TvvzE6/sFkpUDQjXwk0t9HFHXioD3VnjS1o9xstKHCmBUsMBMALpDrnNtmV+ZwBb7DOUi4kAOZAi16W6kzz/NcwwI+0LfO3T1EAuyb6/JCJKfXn4n6kHtPW9kLiBNvQpKAj2AwfYihH3IzCmw5lTXOsMwC2N8BwKbOAxhfxOBzCuSj0ydWW538ehtnPUcSzZ/DczsQLh8tn04uWXPubrWoWM+3dkU2xyfQSQhIJ9TYhSEnjEQauRa5fjIh//HwlmZ39ZIaGXbYyoq6KKpd5ft1csgp67j/WdSU/x3olNMIAP+BzXkmwa/J/uwM="

}

# Open my private key
with open("id_rsa", "rb") as key_file:
    private_key = serialization.load_ssh_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Open my public key    
with open("id_rsa.pub", "rb") as key_file:
    public_key = serialization.load_ssh_public_key(
        key_file.read(),
        backend=default_backend()
    )


# Example path and relay public keys
# path = ["hnf","hnf", "hnf", "hnf"]
# Add padding to user_id to made him have 5 characters
def format_userid(user_id):
    return (b'\x00' * (5-len(user_id)) + user_id)

# Find public key by Id
def findPublicKeyById(id):
        pkey = pubkey_dictionary.get(id)
        if pkey is not None:
            return serialization.load_ssh_public_key(
                ('ssh-rsa ' + pkey).encode('ascii'),
                backend=default_backend()
            )
        else:
            return pkey
# Encrypt a plaintext with a key using AESGCM cipher
def encrypt_aesgcm(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = key
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext
    
# Decrypt a plaintext with a key using AESGCM cipher
def decrypt_aesgcm(key, ciphertext):
    aesgcm = AESGCM(key)
    nonce = key
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
    
# Encrypt a plaintext with a key using RSA cipher
def encrypt_rsa(pub_key, plaintext):
    ciphertext = pub_key.encrypt(    
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
    
# Decrypt a plaintext with a key using RSA cipher
def decrypt_rsa(ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
# Encrypt a text using hybrid encryption, first AESGCM to cipher the text and then RSA to cipher the key used in AESGCM.
def encrypt_hybrid(pub_key, plaintext):
    key = AESGCM.generate_key(bit_length=128)
    c_aesgcm = encrypt_aesgcm(key, plaintext)
    c_rsa = encrypt_rsa(pub_key,key)
    return c_rsa + c_aesgcm
# Decrypt a ciphertext using hybrid encryption, first RSA to recover the AESGCM key and then AESGCM to recover the plaintext.
def decrypt_hybrid(ciphertext):
    key_length = private_key.key_size // 8

    cipher_k = ciphertext[:key_length]
    cipher_plaintext = ciphertext[key_length:]
    key = decrypt_rsa(cipher_k)
    plaintext = decrypt_aesgcm(key, cipher_plaintext)
    return plaintext

# Encrypt nested throught the path using hybrid cipher
def encrypt_nested_hybrid(path, plaintext):
    # Revealed sender and end tags
    m_end = format_userid(b"end") + format_userid(b"hnf") + format_userid(plaintext)
    pkey_last = findPublicKeyById(path[-1])
    c = encrypt_hybrid(pkey_last,m_end)
    # Iterate through relays in reverse order and encrypt with their public keys
    for i in range(len(path) - 2, 0, -1):
        pkey_i = findPublicKeyById(path[i])
        c = format_userid(bytes(path[i+1],'ascii')) + c
        c = encrypt_hybrid(pkey_i, c)
    return c

# If the message starts with end, it's for me, else I send it to the next relay
def receive_message(ciphertext):
    decrypted = decrypt_hybrid(ciphertext)
    if decrypted[:4].lower().strip() == "end" or "END":
        print(
            "Message with: ", decrypted[:4],
            "Sent by: ", decrypted[4:8],
            "Content: ", decrypted[8:]
        )

    else:
        print(decrypted[:12])
        next_hop = decrypted[:4]
        print("Sending to the next node with topic: ", next_hop)

# Example usage
#key = findPublicKeyById("hnf")
#plaintext_message = "hola"
#encrypted_message = encrypt_nested_hybrid(path, plaintext_message)
#decrypted_message = receive_comunication(encrypted_message)
#print("Encrypted Message:", encrypted_message)
#print("Decrypted Message:", decrypted_message)
