"""Database CRUD helper exports."""

from security_scanner.crud.scraped_job import create_scraped_job, get_scraped_jobs

__all__ = [
    "create_scraped_job",
    "get_scraped_jobs",
]
