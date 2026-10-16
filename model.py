from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class RedFlag(BaseModel):
    indicator: str = Field(
        ...,
        description="The detected scam signal (e.g., 'Artificial Urgency', 'Suspicious Unofficial Domain', 'Reverse UPI Collect').",
    )
    explanation: str = Field(
        ...,
        description="Why this specific element constitutes a security risk or fraudulent vector.",
    )


class ExtractedEntities(BaseModel):
    urls: List[str] = Field(default_factory=list, description="Extracted URLs or domains.")
    phone_numbers: List[str] = Field(default_factory=list, description="Extracted phone/mobile numbers.")
    upi_ids: List[str] = Field(default_factory=list, description="Extracted UPI VPA handles (e.g., name@okaxis).")
    claimed_organization: Optional[str] = Field(
        None, description="The bank or institution being impersonated (e.g., SBI, HDFC, PhonePe)."
    )


class ScamAnalysisResult(BaseModel):
    is_scam: bool = Field(
        ...,
        description="Whether the communication is identified as a fraudulent attempt or phishing scam.",
    )
    scam_category: Literal[
        "KYC_Suspension",
        "Fraudulent_UPI_Request",
        "Phishing_Link",
        "Lottery_Prize_Fraud",
        "Impersonation_Bank_Official",
        "Remote_Access_Trojan",
        "Legitimate_Notification",
        "Other",
    ] = Field(..., description="Primary classification of the message.")
    risk_level: Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        ..., description="Overall severity assessment."
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Confidence/probability score from 0 (completely benign) to 100 (confirmed scam).",
    )
    extracted_entities: ExtractedEntities = Field(
        default_factory=ExtractedEntities,
        description="Key communication artifacts parsed from text.",
    )
    red_flags: List[RedFlag] = Field(
        default_factory=list,
        description="Itemized flags explaining the fraudulent indicators.",
    )
    recommended_actions: List[str] = Field(
        ...,
        description="Immediate actionable instructions for the user (non-technical, clear).",
    )
    helpline_guidance: str = Field(
        ...,
        description="Official national or institutional reporting contacts (e.g., 1930 / cybercrime.gov.in).",
    )