import pandas as pd
import requests
import hashlib
import os
import time

# --- CẤU HÌNH HỆ THỐNG ---
INPUT_FILE = "targets.csv"           # File danh sách mục tiêu
STORAGE_DIR = "data/package_storage" # Nơi lưu file thực tế
LOG_FILE = "metadata/dataset_mapping.csv"

# Tạo các thư mục cần thiết
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs("metadata", exist_ok=True)

def get_sha256(content):
    """Tính toán dấu vân tay SHA-256 của file"""
    return hashlib.sha256(content).hexdigest()

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[-] Lỗi: Không tìm thấy file {INPUT_FILE}!")
        return

    # Đọc danh sách mục tiêu
    df_targets = pd.read_csv(INPUT_FILE)
    results = []

    print(f"[*] Bắt đầu quy trình thu thập {len(df_targets)} gói tin...")

    for _, row in df_targets.iterrows():
        name = str(row['package_name']).strip()
        ver = str(row['version']).strip()
        label = row['label']
        
        print(f"\n[>] Đang xử lý: {name} v{ver} (Nhãn: {label})")
        
        try:
            # 1. Truy vấn Metadata qua PyPI JSON API
            # Endpoint này cung cấp thông tin tổng quan và các phiên bản
            api_url = f"https://pypi.org/pypi/{name}/json"
            response = requests.get(api_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                # Kiểm tra phiên bản cụ thể có tồn tại không
                releases = data.get('releases', {})
                if ver in releases and releases[ver]:
                    files = releases[ver]
                else:
                    # Nếu không thấy bản cụ thể, lấy thông tin từ 'urls' (thường là bản mới nhất)
                    print(f"    [!] Phiên bản {ver} không khớp, đang kiểm tra dữ liệu thay thế...")
                    files = data.get('urls', [])

                if not files:
                    print(f"    [!] Không tìm thấy liên kết tải xuống hợp lệ.")
                    continue

                # 2. Tìm tệp tin phân phối nguồn (Source Distribution - sdist)
                # Thường có định dạng .tar.gz, đây là mục tiêu chính để phân tích mã nguồn
                sdist = next((f for f in files if f.get('packagetype') == 'sdist'), files[0])
                file_url = sdist['url']
                
                # 3. Tải tệp tin trực tiếp vào bộ nhớ máy ảo
                file_res = requests.get(file_url, timeout=20)
                file_content = file_res.content
                
                # 4. Kiểm tra tính toàn vẹn và định danh bằng SHA-256
                sha256 = get_sha256(file_content)
                file_name = f"{sha256}.tar.gz"
                
                # 5. Lưu trữ mẫu vật vào "lồng sắt" (Thư mục lưu trữ cô lập)
                save_path = os.path.join(STORAGE_DIR, file_name)
                with open(save_path, "wb") as f:
                    f.write(file_content)
                
                # Lưu thông tin dán nhãn vào danh sách
                results.append({
                    "sha256": sha256,
                    "package_name": name,
                    "version": ver,
                    "label": label,
                    "file_name": file_name
                })
                print(f"    [+] Thành công! Hash: {sha256[:15]}...")
            
            elif response.status_code == 404:
                print(f"    [!] Cảnh báo: Gói {name} không còn tồn tại trên PyPI (Có thể đã bị gỡ bỏ).")
            else:
                print(f"    [!] Lỗi HTTP: {response.status_code}")
                
        except Exception as e:
            print(f"    [!] Lỗi phát sinh: {str(e)}")
        
        # Nghỉ để tránh bị Rate Limit
        time.sleep(1)

    # 6. Xuất bảng ánh xạ (Mapping Table) cho Dataset
    if results:
        output_df = pd.DataFrame(results)
        # Ghi đè hoặc nối thêm vào file mapping
        output_df.to_csv(LOG_FILE, index=False)
        print(f"\n[HOÀN THÀNH] Đã cập nhật Dataset Mapping tại: {LOG_FILE}")
    else:
        print("\n[!] Kết thúc: Không có dữ liệu nào được thu thập.")

if __name__ == "__main__":
    main()
