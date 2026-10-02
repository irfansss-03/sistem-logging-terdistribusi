with open("hasil.txt", "r") as file:
    lines = file.readlines()

failed = 0
success = 0

for line in lines:
    if "failed_login" in line:
        failed = int(line.split(":")[1])
    elif "successful_login" in line:
        success = int(line.split(":")[1])

if failed == 1:
    print("⚠️ PERINGATAN: 1 login gagal terdeteksi")
elif failed >= 3:
    print("🚨 WARNING: 3+ login gagal terdeteksi!")

if success >= 1:
    print(f"✅ INFO: {success} login berhasil terdeteksi")
