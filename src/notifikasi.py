with open("hasil.txt", "r") as file:
    lines = file.readlines()

failed = 0
success = 0

for line in lines:
    if "failed_login" in line:
        failed = int(line.split(":")[1])
    elif "successful_login" in line:
        success = int(line.split(":")[1])

if failed >= 3:
    print(f"🚨 ALERT: {failed} failed login attempts detected!")
elif failed >= 1:
    print(f"⚠️  WARNING: {failed} failed login attempt(s) detected")

if success >= 1:
    print(f"✅ INFO: {success} successful login(s) detected")
