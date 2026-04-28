import tarfile
import zipfile
import os
import pandas as pd

# Cấu hình đường dẫn (Đảm bảo các thư mục này đã tồn tại)
STORAGE_DIR = "data/package_storage"
EXTRACT_DIR = "data/extracted_sources"
MAPPING_FILE = "metadata/dataset_mapping.csv"

def unpack_packages():
    # Kiểm tra file mapping
    if not os.path.exists(MAPPING_FILE):
        print(f"[-] Không tìm thấy file mapping tại: {MAPPING_FILE}")
        return

    df = pd.read_csv(MAPPING_FILE)
    
    if not os.path.exists(EXTRACT_DIR):
        os.makedirs(EXTRACT_DIR)

    print(f"[*] Bắt đầu giải nén {len(df)} mẫu vật...")

    for index, row in df.iterrows():
        file_hash = row['sha256']
        # Tìm file trong storage (có thể là .tar.gz hoặc .zip)
        tar_path = os.path.join(STORAGE_DIR, f"{file_hash}.tar.gz")
        zip_path = os.path.join(STORAGE_DIR, f"{file_hash}.zip")
        
        output_path = os.path.join(EXTRACT_DIR, file_hash)
        
        # Xử lý nếu là file .tar.gz
        if os.path.exists(tar_path):
            try:
                with tarfile.open(tar_path, "r:gz") as tar:
                    # Chỉ lấy file .py
                    members = [m for m in tar.getmembers() if m.name.endswith('.py')]
                    tar.extractall(path=output_path, members=members)
                    print(f"[+] Giải nén thành công (TAR): {row['package_name']}")
            except Exception as e:
                print(f"[-] Lỗi TAR {row['package_name']}: {e}")

        # Xử lý nếu là file .zip/.whl
        elif os.path.exists(zip_path):
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # Lọc file .py
                    py_files = [f for f in zip_ref.namelist() if f.endswith('.py')]
                    zip_ref.extractall(path=output_path, members=py_files)
                    print(f"[+] Giải nén thành công (ZIP): {row['package_name']}")
            except Exception as e:
                print(f"[-] Lỗi ZIP {row['package_name']}: {e}")
        else:
            print(f"[!] Không tìm thấy file vật lý cho mã Hash: {file_hash[:8]}")

if __name__ == "__main__":
    unpack_packages()
    print("\n[DONE] Quy trình giải nén hoàn tất.")
