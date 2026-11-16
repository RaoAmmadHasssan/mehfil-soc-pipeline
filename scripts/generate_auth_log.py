import random
from datetime import datetime, timedelta

random.seed(42)
START = datetime(2026, 11, 15, 0, 0, 0)
HOST = "mehfil-booking"
USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "booking", "mehfil"]
VALID_USERS = {"admin", "booking", "mehfil"}
STAFF_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.20"]

events = []

def ts(dt):
    return f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S}"

def add(dt, msg):
    events.append((dt, f"{ts(dt)} {HOST} sshd[{random.randint(1000, 32000)}]: {msg}"))

def failed(dt, user, ip):
    inv = "invalid user " if user not in VALID_USERS else ""
    add(dt, f"Failed password for {inv}{user} from {ip} port {random.randint(1024, 65535)} ssh2")

def accepted(dt, user, ip):
    add(dt, f"Accepted password for {user} from {ip} port {random.randint(1024, 65535)} ssh2")

# 1) Brute-force attackers (bursts => dashboard par spike)
attackers = {
    "185.220.101.45": (3, 120),
    "45.155.205.233": (14, 75),
    "103.151.122.18": (21, 40),
}
for ip, (hour, n) in attackers.items():
    t = START + timedelta(hours=hour, minutes=random.randint(0, 30))
    for _ in range(n):
        t += timedelta(seconds=random.randint(1, 5))
        failed(t, random.choice(USERS), ip)

# 2) Attacker ko ek successful login (compromise)
accepted(START + timedelta(hours=3, minutes=40), "admin", "185.220.101.45")

# 3) Legit staff logins (working hours)
for _ in range(7):
    t = START + timedelta(hours=random.randint(9, 18), minutes=random.randint(0, 59),
                          seconds=random.randint(0, 59))
    accepted(t, random.choice(sorted(VALID_USERS)), random.choice(STAFF_IPS))

# 4) Normal noise: staff ke typos
for _ in range(10):
    t = START + timedelta(hours=random.randint(8, 19), minutes=random.randint(0, 59),
                          seconds=random.randint(0, 59))
    failed(t, random.choice(sorted(VALID_USERS)), random.choice(STAFF_IPS))

events.sort(key=lambda e: e[0])
with open("logs/auth.log", "w") as f:
    for _, line in events:
        f.write(line + "\n")

print(f"Generated {len(events)} log lines")
