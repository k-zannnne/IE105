import math
from collections import Counter

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy

# 3 kịch bản mẫu
clean_code = "print('Hello student! This is a benign script.')"
repeated_str = "Ym9uZyBKSB2aWVOIG5hbSB2byBkaWNo" * 20
malicious_payload = "aHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlLmNvbS9wYXlsb2FkPWFhYmJiY2NjMTIzNCEjJCVeJiooKQ=="

print("----------------------------------------")
print(f"1. Benign Code Entropy:   {shannon_entropy(clean_code):.4f}")
print(f"2. Repeated Str Entropy: {shannon_entropy(repeated_str):.4f}")
print(f"3. MALICIOUS PAYLOAD:    {shannon_entropy(malicious_payload):.4f}")
print("----------------------------------------")

