with open("example.txt", "rb") as f1, open("received_example.txt", "rb") as f2:
    if f1.read() == f2.read():
        print("✅ Dosyalar tamamen aynı!")
    else:
        print("❌ Dosyalar farklı!")
