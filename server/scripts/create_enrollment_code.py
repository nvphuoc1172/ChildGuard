"""Tạo mã ghép đôi từ dòng lệnh — tạm thời thay cho nút "Tạo mã" trên
dashboard (dashboard chưa có đăng nhập thật ở giai đoạn này).

Chạy trên VM, trong venv:
    cd /opt/childguard/app/server
    python -m scripts.create_enrollment_code --parent-email demo@ogk.local --child-name "Minh An"

Nếu phụ huynh/trẻ với thông tin đó chưa tồn tại, script tự tạo luôn
(tài khoản demo — ghi rõ trong README khi nộp bài).
"""
import argparse
import sys
from pathlib import Path

# Cho phép chạy trực tiếp "python scripts/create_enrollment_code.py" từ
# thư mục server/ mà không cần cài package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import models, security  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402


def get_or_create_parent(db, email: str) -> models.Parent:
    parent = db.query(models.Parent).filter(models.Parent.email == email).first()
    if parent is None:
        parent = models.Parent(email=email, password_hash="demo-not-for-production")
        db.add(parent)
        db.flush()
        print(f"[tạo mới] Phụ huynh: {email}")
    return parent


def get_or_create_child(db, parent: models.Parent, name: str) -> models.Child:
    child = (
        db.query(models.Child)
        .filter(models.Child.parent_id == parent.id, models.Child.display_name == name)
        .first()
    )
    if child is None:
        child = models.Child(parent_id=parent.id, display_name=name)
        db.add(child)
        db.flush()
        print(f"[tạo mới] Trẻ: {name}")
    return child


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-email", required=True)
    parser.add_argument("--child-name", required=True)
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        parent = get_or_create_parent(db, args.parent_email)
        child = get_or_create_child(db, parent, args.child_name)

        code = security.generate_enrollment_code()
        expires_at = security.enrollment_code_expiry()
        enrollment = models.EnrollmentCode(
            code=code,
            parent_id=parent.id,
            child_id=child.id,
            expires_at=expires_at,
        )
        db.add(enrollment)
        db.commit()

        print()
        print("=" * 40)
        print(f"  MÃ GHÉP ĐÔI:  {code}")
        print(f"  Hết hạn lúc:  {expires_at.isoformat()} UTC")
        print(f"  Trẻ:          {child.display_name} (child_id={child.id})")
        print("=" * 40)
        print()
        print("Nhập mã này trên agent trong 10 phút (agent/enroll.py).")
    finally:
        db.close()


if __name__ == "__main__":
    main()
