from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from security_scanner.scraper import ScrapeResult


class ScrapeRequest(BaseModel):
    """Request body for the public URL scraping endpoint."""

    model_config = ConfigDict(extra="forbid")

    url: HttpUrl = Field(..., description="Page URL to scrape.")
    css_selector: str | None = Field(
        default=None,
        min_length=1,
        description="Optional CSS selector for readable page elements.",
    )
    use_javascript: bool = Field(
        default=False,
        description="Whether to render the page with JavaScript before scraping.",
    )


class StructuredScrapeRequest(BaseModel):
    """Detailed scraping request for item/card extraction."""

    model_config = ConfigDict(extra="forbid")

    source_url: HttpUrl = Field(..., description="Page URL to scrape.")
    item_selector: str = Field(
        ...,
        min_length=1,
        description="CSS selector for each item/card.",
    )
    title_selector: str = Field(
        ...,
        min_length=1,
        description="CSS selector for item title.",
    )
    price_selector: str | None = Field(
        default=None,
        description="Optional selector for price.",
    )
    link_selector: str | None = Field(
        default=None,
        description="Optional selector for item link.",
    )
    max_items: int = Field(
        default=200,
        ge=1,
        le=200,
        description="Maximum number of items to scrape.",
    )

    @field_validator("max_items")
    @classmethod
    def validate_max_items(cls, value: int) -> int:
        if value > 200:
            raise ValueError("max_items cannot exceed 200")
        return value


class ScrapedItemResponse(BaseModel):
    """Single item extracted from a scraped page."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., description="Extracted item title.")
    price: str | None = Field(
        default=None,
        description="Extracted item price when available.",
    )
    url: str | None = Field(
        default=None,
        description="Absolute item URL when available.",
    )


class ScrapeResponse(BaseModel):
    """Response body returned for a scrape."""

    model_config = ConfigDict(extra="forbid")

    source_url: str = Field(..., description="Normalized source URL that was scraped.")
    success: bool = Field(..., description="Whether the scrape completed successfully.")
    items: list[ScrapedItemResponse] = Field(
        default_factory=list,
        description="Structured items extracted from the page.",
    )
    scraped_at: datetime = Field(..., description="UTC timestamp when scraping ran.")
    error_message: str | None = Field(
        default=None,
        description="Failure or warning message returned by the scraper.",
    )


def scrape_result_to_response(scrape_result: ScrapeResult) -> ScrapeResponse:
    """Convert a scraper domain result into an API response model."""
    return ScrapeResponse(
        source_url=scrape_result.source_url,
        success=scrape_result.success,
        items=[
            ScrapedItemResponse(
                title=item.title,
                price=item.price,
                url=item.url,
            )
            for item in scrape_result.items
        ],
        scraped_at=datetime.fromisoformat(scrape_result.timestamp_utc),
        error_message=scrape_result.error_message,
    )
