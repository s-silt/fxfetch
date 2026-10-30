"""Bounded defaults; web callers cannot disable these limits."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_url_bytes: int = 8192
    max_package_bytes: int = 512 * 1024 * 1024
    max_body_bytes: int = 8 * 1024 * 1024
    max_web_bytes: int = 128 * 1024 * 1024
    max_redirects: int = 10
    max_requests: int = 300
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    chain_timeout: float = 600.0
    max_candidates: int = 200
    max_archive_entries: int = 100_000
    max_archive_directory_bytes: int = 32 * 1024 * 1024
    max_archive_metadata_bytes: int = 8 * 1024 * 1024
    max_image_bytes: int = 10 * 1024 * 1024
    max_upload_bytes: int = 11 * 1024 * 1024
    max_image_pixels: int = 25_000_000
    image_timeout: float = 5.0
    image_memory_bytes: int = 512 * 1024 * 1024
    max_qr_candidates: int = 16
    image_ttl_seconds: int = 86400
    max_pending_images: int = 10
    max_queued_jobs: int = 20
    max_queued_builds: int = 10
    build_timeout: float = 900.0
    build_memory_bytes: int = 2 * 1024 * 1024 * 1024
    max_build_scratch_bytes: int = 8 * 1024 * 1024 * 1024
    max_task_bytes: int = 2 * 1024 * 1024 * 1024
    analysis_timeout: int = 360
    analysis_queue_timeout: int = 600
    max_queued_analyses: int = 10
    max_analyses_per_job: int = 10
