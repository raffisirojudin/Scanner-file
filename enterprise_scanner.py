import argparse
import concurrent.futures
from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import string
import sys
from typing import Dict, List, Optional, Set, Tuple

# ==============================================================================
# ENTERPRISE DUPLICATE AUDITOR & SAFETY SCANNER (ALL-DRIVES EDITION)
# ==============================================================================

# Folder & Berkas Sistem yang WAJIB Dikecualikan Saat Memindai Seluruh Disk
SYSTEM_EXCLUSIONS = {
    "$RECYCLE.BIN",
    "System Volume Information",
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "AppData",
    ".git",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
}

IGNORE_PREFIXES = ("~$", ".~", "tmp_")
IGNORE_EXTENSIONS = {
    ".tmp",
    ".bak",
    ".lnk",
    ".sys",
    ".dll",
    ".exe",
    ".iso",
    ".img",
}


@dataclass
class FileMetadata:
  path: Path
  size: int
  created_time: float
  modified_time: float
  file_id: Tuple[int, int]
  filename: str
  extension: str


@dataclass
class DuplicateGroup:
  group_id: str
  hash_sha256: str
  size_bytes: int
  original: FileMetadata
  duplicates: List[FileMetadata] = field(default_factory=list)
  risk_level: str = "LOW"
  risk_reasons: List[str] = field(default_factory=list)


class EnterpriseScanner:

  def __init__(
      self,
      target_dirs: List[Path],
      quarantine_dir: Optional[Path] = None,
  ):
    self.target_dirs = [p.resolve() for p in target_dirs]
    default_quarantine_base = (
        Path.home() / "Documents"
    )  # Simpan Karantina di folder Documents agar aman
    self.quarantine_dir = (
        quarantine_dir
        or default_quarantine_base
        / f"_QUARANTINE_ALL_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )

  @staticmethod
  def get_available_drives() -> List[Path]:
    """Mendeteksi semua Drive aktif di Windows (misal C:\, D:\, E:\)."""
    drives = []
    for letter in string.ascii_uppercase:
      drive_path = Path(f"{letter}:\\")
      if drive_path.exists():
        drives.append(drive_path)
    return drives

  @staticmethod
  def verify_bit_by_bit(file1_path: Path, file2_path: Path) -> bool:
    chunk_size = 65536
    try:
      with open(file1_path, "rb") as f1, open(file2_path, "rb") as f2:
        while True:
          b1 = f1.read(chunk_size)
          b2 = f2.read(chunk_size)
          if b1 != b2:
            return False
          if not b1:
            return True
    except (OSError, PermissionError):
      return False

  @staticmethod
  def compute_partial_hash(
      filepath: Path, block_size: int = 16384
  ) -> Optional[str]:
    try:
      size = filepath.stat().st_size
      hasher = hashlib.blake2b()
      with open(filepath, "rb") as f:
        hasher.update(f.read(block_size))
        if size > block_size * 2:
          f.seek(-block_size, os.SEEK_END)
          hasher.update(f.read(block_size))
      return hasher.hexdigest()
    except (OSError, PermissionError):
      return None

  @staticmethod
  def compute_full_sha256(filepath: Path) -> Optional[str]:
    hasher = hashlib.sha256()
    try:
      with open(filepath, "rb") as f:
        while chunk := f.read(65536):
          hasher.update(chunk)
      return hasher.hexdigest()
    except (OSError, PermissionError):
      return None

  def scan_files(self) -> List[FileMetadata]:
    file_list = []
    scanned_count = 0

    for target_dir in self.target_dirs:
      print(f"[*] Memulai pemindaian direktori: {target_dir}")
      for root, dirs, files in os.walk(target_dir):
        # Filter direktori sistem secara ketat
        dirs[:] = [
            d
            for d in dirs
            if d not in SYSTEM_EXCLUSIONS
            and not d.startswith("_QUARANTINE_")
        ]

        for file in files:
          scanned_count += 1
          if scanned_count % 1000 == 0:
            print(f"  -> Telah memeriksa {scanned_count} berkas...", end="\r")

          if file.startswith(IGNORE_PREFIXES) or any(
              file.endswith(ext) for ext in IGNORE_EXTENSIONS
          ):
            continue

          full_path = Path(root) / file
          try:
            stat = full_path.stat()
            if stat.st_size == 0 or full_path.is_symlink():
              continue

            meta = FileMetadata(
                path=full_path,
                size=stat.st_size,
                created_time=stat.st_ctime,
                modified_time=stat.st_mtime,
                file_id=(stat.st_dev, stat.st_ino),
                filename=file,
                extension=full_path.suffix.lower(),
            )
            file_list.append(meta)
          except (OSError, PermissionError):
            continue

    print(
        f"\n[+] Pemindaian selesai: Total {len(file_list)} berkas terverifikasi"
        " aman diproses.\n"
    )
    return file_list

  def evaluate_risk(
      self, original: FileMetadata, duplicate: FileMetadata
  ) -> Tuple[str, List[str]]:
    reasons = []
    risk = "LOW"

    if original.filename.lower() != duplicate.filename.lower():
      risk = "HIGH"
      reasons.append("Nama berkas beda (Kemungkinan dipanggil dependensi lain)")

    orig_parts = set(original.path.parent.parts)
    dup_parts = set(duplicate.path.parent.parts)
    if not orig_parts.intersection(dup_parts):
      if risk != "HIGH":
        risk = "MEDIUM"
      reasons.append("Berada di drive/struktur folder terpisah")

    critical_exts = {
        ".json",
        ".xml",
        ".ini",
        ".conf",
        ".db",
        ".sqlite",
        ".py",
        ".bat",
        ".ps1",
    }
    if duplicate.extension in critical_exts:
      risk = "HIGH"
      reasons.append(
          f"Ekstensi sensitif '{duplicate.extension}' (Dapat merusak"
          " sistem/konfigurasi)"
      )

    if risk == "LOW":
      reasons.append("Nama berkas identik (Aman dikarantina)")

    return risk, reasons

  def execute_audit(self) -> List[DuplicateGroup]:
    all_files = self.scan_files()

    size_map: Dict[int, List[FileMetadata]] = {}
    for f in all_files:
      size_map.setdefault(f.size, []).append(f)

    size_candidates = [
        files for size, files in size_map.items() if len(files) > 1
    ]

    unique_inode_candidates = []
    for group in size_candidates:
      seen_inodes: Set[Tuple[int, int]] = set()
      dedup_group = []
      for f in group:
        if f.file_id not in seen_inodes:
          seen_inodes.add(f.file_id)
          dedup_group.append(f)
      if len(dedup_group) > 1:
        unique_inode_candidates.append(dedup_group)

    print("[*] Memindai Partial Hash (Header/Tail)...")
    partial_map: Dict[Tuple[int, str], List[FileMetadata]] = {}
    for group in unique_inode_candidates:
      for f in group:
        p_hash = self.compute_partial_hash(f.path)
        if p_hash:
          partial_map.setdefault((f.size, p_hash), []).append(f)

    partial_candidates = [
        files for key, files in partial_map.items() if len(files) > 1
    ]

    print("[*] Menghitung Full SHA-256 Cryptographic Hash...")
    sha_map: Dict[str, List[FileMetadata]] = {}
    for group in partial_candidates:
      for f in group:
        full_hash = self.compute_full_sha256(f.path)
        if full_hash:
          sha_map.setdefault(full_hash, []).append(f)

    sha_candidates = {
        h: files for h, files in sha_map.items() if len(files) > 1
    }

    print("[*] Memverifikasi Fisik Bit-by-Bit...")
    results: List[DuplicateGroup] = []

    group_counter = 1
    for sha256_hash, candidate_files in sha_candidates.items():
      candidate_files.sort(key=lambda x: x.created_time)
      master_file = candidate_files[0]

      confirmed_duplicates = []
      group_risk = "LOW"
      group_reasons = set()

      for dupe_candidate in candidate_files[1:]:
        if self.verify_bit_by_bit(master_file.path, dupe_candidate.path):
          confirmed_duplicates.append(dupe_candidate)
          risk, reasons = self.evaluate_risk(master_file, dupe_candidate)
          group_reasons.update(reasons)
          if risk == "HIGH":
            group_risk = "HIGH"
          elif risk == "MEDIUM" and group_risk != "HIGH":
            group_risk = "MEDIUM"

      if confirmed_duplicates:
        dg = DuplicateGroup(
            group_id=f"GRP-{group_counter:04d}",
            hash_sha256=sha256_hash,
            size_bytes=master_file.size,
            original=master_file,
            duplicates=confirmed_duplicates,
            risk_level=group_risk,
            risk_reasons=list(group_reasons),
        )
        results.append(dg)
        group_counter += 1

    return results


class AuditReporter:

  @staticmethod
  def export_json(groups: List[DuplicateGroup], output_path: Path):
    data = []
    for g in groups:
      item = {
          "group_id": g.group_id,
          "sha256": g.hash_sha256,
          "size_bytes": g.size_bytes,
          "risk_level": g.risk_level,
          "risk_reasons": g.risk_reasons,
          "original": str(g.original.path),
          "duplicates": [str(d.path) for d in g.duplicates],
      }
      data.append(item)

    with open(output_path, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=4)
    print(f"[+] Laporan Audit JSON disimpan: {output_path}")

  @staticmethod
  def print_terminal_summary(groups: List[DuplicateGroup]):
    total_saved_bytes = sum(
        g.size_bytes * len(g.duplicates) for g in groups
    )
    print("\n" + "=" * 75)
    print(" RINGKASAN HASIL AUDIT LINTAS DRIVE")
    print("=" * 75)
    print(f"Total Kelompok Duplikat Valid : {len(groups)}")
    print(
        f"Total Potensi Ruang Tersisa  : {total_saved_bytes / (1024*1024):.2f}"
        " MB"
    )
    print("-" * 75)

    for g in groups:
      print(
          f"\n{g.group_id} | Size: {g.size_bytes/1024:.1f} KB | Risk:"
          f" [{g.risk_level}]"
      )
      print(f"  [ASLI]     : {g.original.path}")
      for d in g.duplicates:
        print(f"  [DUPLIKAT] : {d.path}")

  @staticmethod
  def quarantine_duplicates(
      groups: List[DuplicateGroup],
      quarantine_dir: Path,
      allow_high_risk: bool = False,
  ):
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = quarantine_dir / "restore_manifest.json"
    manifest_data = []

    moved_count = 0
    skipped_count = 0

    for g in groups:
      if g.risk_level == "HIGH" and not allow_high_risk:
        skipped_count += len(g.duplicates)
        continue

      for dup in g.duplicates:
        dest_path = quarantine_dir / dup.path.name
        counter = 1
        while dest_path.exists():
          dest_path = (
              quarantine_dir / f"{dup.path.stem}_{counter}{dup.path.suffix}"
          )
          counter += 1

        try:
          shutil.move(str(dup.path), str(dest_path))
          manifest_data.append({
              "original_location": str(dup.path),
              "quarantine_location": str(dest_path),
              "timestamp": datetime.now().isoformat(),
          })
          moved_count += 1
          print(f"[KARANTINA] : {dup.path} -> {dest_path.name}")
        except Exception as e:
          print(f"[GAGAL]     : {dup.path} ({e})")

    with open(manifest_path, "w", encoding="utf-8") as f:
      json.dump(manifest_data, f, indent=4)

    print("\n" + "=" * 75)
    print(f"[SELESAI] {moved_count} berkas dipindahkan ke karantina.")
    print(f"[DILINDUNGI] {skipped_count} berkas HIGH-RISK dilewati.")
    print(f"[MANIFEST] Restore Manifest tersimpan di: {manifest_path}")

  @staticmethod
  def restore_from_manifest(manifest_path: Path):
    if not manifest_path.exists():
      print(f"[ERROR] Manifest tidak ditemukan: {manifest_path}")
      return

    with open(manifest_path, "r", encoding="utf-8") as f:
      items = json.load(f)

    restored = 0
    for item in items:
      src = Path(item["quarantine_location"])
      dst = Path(item["original_location"])
      if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        restored += 1
        print(f"[RESTORED] : {src.name} -> {dst}")

    print(f"\n[SELESAI] {restored} berkas dikembalikan ke lokasi asli!")


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Enterprise Duplicate Scanner (Multi-Drive & System Wide)"
  )
  parser.add_argument(
      "--all-drives",
      action="store_true",
      help="Pindai SELURUH Drive yang ada di komputer (C:, D:, E:)",
  )
  parser.add_argument(
      "--dir",
      type=str,
      default=None,
      help="Tentukan spesifik folder (misal C:\\Users)",
  )
  parser.add_argument(
      "--quarantine",
      action="store_true",
      help="Pindahkan berkas duplikat ke Karantina",
  )
  parser.add_argument(
      "--allow-high-risk",
      action="store_true",
      help="Izinkan pemindahan file HIGH RISK",
  )
  parser.add_argument(
      "--restore",
      type=str,
      help="Jalankan pemulihan berdasarkan manifest JSON",
  )

  args = parser.parse_args()

  if args.restore:
    AuditReporter.restore_from_manifest(Path(args.restore))
    sys.exit(0)

  if args.all_drives:
    targets = EnterpriseScanner.get_available_drives()
  elif args.dir:
    targets = [Path(args.dir)]
  else:
    targets = [Path.cwd()]

  scanner = EnterpriseScanner(target_dirs=targets)
  groups = scanner.execute_audit()

  if not groups:
    print("[+] Tidak ada berkas duplikat yang terdeteksi.")
    sys.exit(0)

  AuditReporter.print_terminal_summary(groups)
  report_file = Path.home() / "Documents" / "audit_report_all_drives.json"
  AuditReporter.export_json(groups, report_file)

  if args.quarantine:
    print("\n[*] Menjalankan tindakan Karantina Aman...")
    AuditReporter.quarantine_duplicates(
        groups, scanner.quarantine_dir, allow_high_risk=args.allow_high_risk
    )
  else:
    print("\n[*] Mode Audit Selesai (Tidak ada berkas yang dipindah/dihapus).")