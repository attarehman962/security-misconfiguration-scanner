from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import ScrapedItem, ScrapeResult

CSV_FIELDNAMES = ["title", "price", "url", "source_url"]


def item_to_csv_row(item: ScrapedItem) -> dict[str, str]:
    """Convert one scraped item into a CSV-safe row."""
    return {
        "title": item.title,
        "price": item.price or "",
        "url": item.url or "",
        "source_url": item.source_url,
    }


def result_to_dict(result: ScrapeResult) -> dict[str, Any]:
    """Convert a scrape result dataclass into a JSON-serializable dict."""
    return asdict(result)


def save_result_json(result: ScrapeResult, output_path: Path) -> Path:
    """Save a full scrape result to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as json_file:
        json.dump(result_to_dict(result), json_file, indent=2, ensure_ascii=False)

    return output_path


def save_items_csv(items: list[ScrapedItem], output_path: Path) -> Path:
    """Save scraped items to a CSV file with stable headers."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()

        for item in items:
            writer.writerow(item_to_csv_row(item))

    return output_path
