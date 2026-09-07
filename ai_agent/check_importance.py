import joblib

judge = joblib.load('../data/surrogate_ids_ctu13.pkl')
features = ['dur', 'tot_pkts', 'tot_bytes', 'src_bytes', 'proto', 'state']
importances = judge.feature_importances_

print("[*] Mức độ quan trọng của các đặc trưng:")
for name, imp in zip(features, importances):
    print(f" - {name}: {imp * 100:.2f}%")
