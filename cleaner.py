import ast
import hashlib
import os
import pandas as pd

EXTRACT_DIR = "data/extracted_sources"
MAPPING_FILE = "metadata/dataset_mapping.csv"

def clean_data():
    df = pd.read_csv(MAPPING_FILE)
    initial_count = len(df)
    valid_rows = []
    seen_content_hashes = set()

    print(f"[*] Bắt đầu làm sạch {initial_count} mẫu vật...")

    for index, row in df.iterrows():
        file_hash = row['sha256']
        package_path = os.path.join(EXTRACT_DIR, file_hash)
        
        if not os.path.exists(package_path):
            continue

        is_valid = True
        content_fingerprint = ""

        # Duyệt qua các file .py đã giải nén
        for root, dirs, files in os.walk(package_path):
            for file in files:
                if file.endswith('.py'):
                    file_p = os.path.join(root, file)
                    with open(file_p, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                        
                        # 1. Kiểm tra lỗi cú pháp (AST Parsing)
                        try:
                            ast.parse(code)
                        except SyntaxError:
                            print(f"[!] Lỗi cú pháp: {row['package_name']} - {file}")
                            is_valid = False
                            break
                        
                        # 2. Tạo dấu vân tay nội dung (Deduplication)
                        content_fingerprint += code

        if is_valid:
            # Hash nội dung để kiểm tra trùng lặp (loại bỏ package giống hệt nhau)
            content_hash = hashlib.md5(content_fingerprint.encode()).hexdigest()
            if content_hash not in seen_content_hashes:
                seen_content_hashes.add(content_hash)
                valid_rows.append(row)
            else:
                print(f"[-] Loại bỏ trùng lặp nội dung: {row['package_name']}")

    # Cập nhật lại file mapping sạch
    clean_df = pd.DataFrame(valid_rows)
    clean_df.to_csv("metadata/dataset_mapping_clean.csv", index=False)
    print(f"\n[DONE] Hoàn thành! Giữ lại {len(clean_df)}/{initial_count} mẫu sạch.")

if __name__ == "__main__":
    clean_data()
